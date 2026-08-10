#!/usr/bin/env python3
"""Reproducible cold/warm performance benchmark for qazmorph.

This utility performs no downloads and depends only on the Python standard
library.  "Cold" means a fresh Python worker process (it does not claim to drop
the operating-system page cache).  "Warm" means repeated calls through one
already-constructed ``Analyzer`` in an isolated worker process.
"""

from __future__ import annotations

import argparse
import hashlib
from importlib import metadata as importlib_metadata
import json
import math
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import sys
import time
from typing import Any, Iterator, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
if SOURCE_ROOT.is_dir() and str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))


SCHEMA_VERSION = "qazmorph.benchmark.v3"
BUILTIN_TEXT = (
    "Қазақстан Республикасы — Еуразия құрлығының орталығында орналасқан мемлекет.\n"
    "Қазақ тілінің морфологиясы жалғамалы құрылымымен ерекшеленеді.\n"
    "Бүгін Алматыда күн ашық, бірақ кешке жаңбыр жаууы мүмкін.\n"
    "Зерттеушілер жаңа жүйенің нәтижелерін мұқият тексеріп жатыр."
)


class BenchmarkError(RuntimeError):
    """Raised for an invalid benchmark workload or failed worker."""


def _analyzer_mode_flags(mode: str) -> dict[str, bool]:
    """Return the mutually exclusive Analyzer flags for a benchmark engine."""

    if mode not in {"lattice", "cg", "neural"}:
        raise ValueError(f"unknown analyzer mode: {mode}")
    return {
        "disambiguate": mode == "cg",
        "neural": mode == "neural",
    }


def _percentile(sorted_values: Sequence[float], percentile: float) -> float:
    if not sorted_values:
        raise ValueError("cannot compute a percentile of an empty sequence")
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = (len(sorted_values) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    fraction = position - lower
    return sorted_values[lower] * (1.0 - fraction) + sorted_values[upper] * fraction


def _summary(values: Sequence[float], *, digits: int = 3) -> dict[str, float | int | None]:
    if not values:
        return {
            "count": 0,
            "min": None,
            "p50": None,
            "p95": None,
            "p99": None,
            "max": None,
            "mean": None,
            "stdev": None,
        }
    ordered = sorted(values)

    def rounded(value: float) -> float:
        return round(value, digits)

    return {
        "count": len(values),
        "min": rounded(ordered[0]),
        "p50": rounded(_percentile(ordered, 0.50)),
        "p95": rounded(_percentile(ordered, 0.95)),
        "p99": rounded(_percentile(ordered, 0.99)),
        "max": rounded(ordered[-1]),
        "mean": rounded(statistics.fmean(values)),
        "stdev": rounded(statistics.stdev(values)) if len(values) > 1 else 0.0,
    }


def _rss_bytes(who: int) -> int | None:
    try:
        raw = resource.getrusage(who).ru_maxrss
    except (AttributeError, OSError, ValueError):
        return None
    # Linux and other common Unix platforms report KiB; macOS reports bytes.
    return int(raw if sys.platform == "darwin" else raw * 1024)


def _current_rss_bytes() -> int | None:
    status = Path("/proc/self/status")
    if not status.is_file():
        return None
    try:
        for line in status.read_text(encoding="ascii").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (OSError, UnicodeError, ValueError, IndexError):
        return None
    return None


def _linux_process_memory(pid: int) -> dict[str, int | None]:
    """Read live RSS/HWM for one process without pretending it is a waited peak."""

    result: dict[str, int | None] = {
        "current_rss_bytes": None,
        "high_water_rss_bytes": None,
    }
    status = Path(f"/proc/{pid}/status")
    if not status.is_file():
        return result
    names = {"VmRSS:": "current_rss_bytes", "VmHWM:": "high_water_rss_bytes"}
    try:
        for line in status.read_text(encoding="ascii").splitlines():
            fields = line.split()
            if fields and fields[0] in names and len(fields) >= 2:
                result[names[fields[0]]] = int(fields[1]) * 1024
    except (OSError, UnicodeError, ValueError, IndexError):
        return {
            "current_rss_bytes": None,
            "high_water_rss_bytes": None,
        }
    return result


def _analyzer_token_count(document: Any) -> int:
    return sum(
        1
        for token in document.tokens
        if token.text and not token.text.isspace() and token.kind != "space"
    )


def _load_analyzer() -> tuple[Any, str]:
    try:
        from qazmorph import Analyzer, __version__
    except ImportError as exc:
        raise BenchmarkError(
            "qazmorph is not importable; install the project or run this script from its checkout"
        ) from exc
    return Analyzer, __version__


def _persistent_process_snapshot(process: Any | None) -> dict[str, Any]:
    if process is None:
        return {
            "started": False,
            "pid": None,
            "alive": False,
            "returncode": None,
            "live_memory": {
                "current_rss_bytes": None,
                "high_water_rss_bytes": None,
            },
        }
    pid = int(process.pid)
    memory = _linux_process_memory(pid)
    returncode = process.poll()
    return {
        "started": True,
        "pid": pid,
        "alive": returncode is None,
        "returncode": returncode,
        "live_memory": memory,
    }


def _close_analyzer_with_report(analyzer: Any) -> dict[str, Any]:
    """Close and wait for the persistent guesser child, retaining honest state."""

    guesser = analyzer.guesser
    worker = guesser._worker
    process = worker._process
    before = _persistent_process_snapshot(process)
    diagnostics_before = dict(guesser.diagnostics)
    started = time.perf_counter_ns()
    analyzer.close()
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    diagnostics_after = dict(guesser.diagnostics)
    original_returncode = process.poll() if process is not None else None
    waited = process is None or original_returncode is not None
    return {
        "scope": (
            "persistent hfst-lookup OOV child owned by this Analyzer; live RSS/HWM "
            "is sampled immediately before close, while waited-child ru_maxrss is "
            "sampled only after close"
        ),
        "before_close": before,
        "after_close": {
            "worker_reference_detached": worker._process is None,
            "original_process_waited": waited,
            "original_process_returncode": original_returncode,
        },
        "close_latency_ms": round(elapsed_ms, 3),
        "guesser_diagnostics_before_close": diagnostics_before,
        "guesser_diagnostics_after_close": diagnostics_after,
    }


def _candidate_lattice_completeness(diagnostics: dict[str, int]) -> dict[str, Any]:
    events = {
        name: int(diagnostics.get(name, 0))
        for name in (
            "cap_aborts",
            "timeouts",
            "failures",
            "cycle_truncations",
            "unsafe_resource_skips",
        )
    }
    events["unsafe_resource_configuration"] = int(
        not diagnostics.get("productive_resource_safe", 1)
    )
    return {
        "complete": not any(events.values()),
        "incomplete_event_counts": events,
        "informational_event_counts": {
            "protocol_restarts": int(diagnostics.get("protocol_restarts", 0)),
        },
        "definition": (
            "false if any enabled productive OOV lookup was truncated by a response "
            "cap, timed out, failed, or emitted HFST's cyclic truncation marker in "
            "this worker, or was disabled for an unsafe legacy resource; true does "
            "not claim that an ineligible OOV has dictionary analyses"
        ),
    }


def _visible_distribution_versions() -> dict[str, str | list[str]]:
    observed: dict[str, set[str]] = {}
    for distribution in importlib_metadata.distributions():
        raw_name = distribution.metadata.get("Name")
        if not raw_name:
            continue
        name = raw_name.lower().replace("_", "-").replace(".", "-")
        observed.setdefault(name, set()).add(distribution.version)
    return {
        name: next(iter(versions)) if len(versions) == 1 else sorted(versions)
        for name, versions in sorted(observed.items())
    }


def _pipeline_device_inventory(ranker: Any) -> dict[str, dict[str, Any]]:
    """Inspect only processor trainer/direct models, never auxiliary loss modules."""

    result: dict[str, dict[str, Any]] = {}
    processors = getattr(getattr(ranker, "pipeline", None), "processors", {})
    for name, processor in sorted(processors.items()):
        models: list[Any] = []
        direct_model = getattr(processor, "model", None)
        if direct_model is not None:
            models.append(direct_model)
        for attribute in ("trainer", "_trainer"):
            trainer = getattr(processor, attribute, None)
            model = getattr(trainer, "model", None) if trainer is not None else None
            if model is not None and all(model is not item for item in models):
                models.append(model)
        devices: set[str] = set()
        parameter_count = 0
        errors: list[str] = []
        for model in models:
            parameters = getattr(model, "parameters", None)
            if not callable(parameters):
                errors.append("model exposes no parameters() iterator")
                continue
            try:
                for parameter in parameters():
                    parameter_count += 1
                    devices.add(str(parameter.device))
            except (AttributeError, RuntimeError, TypeError) as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
        if errors:
            status = "unresolved_model_device"
        elif devices:
            status = "model_parameters_observed"
        elif models and not errors and parameter_count == 0:
            status = "verified_parameterless_model"
        else:
            status = "unresolved_model_device"
        result[str(name)] = {
            "devices": sorted(devices) or None,
            "parameter_count": parameter_count,
            "status": status,
            "errors": errors,
        }
    return result


def _pipeline_devices(ranker: Any) -> dict[str, list[str] | None]:
    return {
        name: item["devices"]
        for name, item in _pipeline_device_inventory(ranker).items()
    }


def _device_family(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.casefold()
    if normalized.startswith("cuda"):
        return "gpu"
    if normalized.startswith("cpu"):
        return "cpu"
    return None


def _neural_device_verification(
    *,
    requested_device: str,
    pipeline_device: str | None,
    processor_model_devices: dict[str, list[str] | None],
    cuda_available: bool,
    processor_device_status: dict[str, str] | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    pipeline_family = _device_family(pipeline_device)
    if pipeline_family is None:
        reasons.append(f"pipeline device is unavailable or unsupported: {pipeline_device!r}")
    expected_family = (
        pipeline_family if requested_device == "auto" else requested_device
    )
    if expected_family not in {"cpu", "gpu"}:
        reasons.append(f"requested neural device cannot be resolved: {requested_device!r}")
    elif pipeline_family != expected_family:
        reasons.append(
            f"requested device {requested_device!r} resolved to {expected_family!r}, "
            f"but pipeline uses {pipeline_device!r}"
        )
    if expected_family == "gpu" and not cuda_available:
        reasons.append("GPU execution was requested/resolved but CUDA is unavailable")

    processor_families: dict[str, list[str] | None] = {}
    if not processor_model_devices:
        reasons.append("pipeline exposes no processor model devices")
    for name, devices in sorted(processor_model_devices.items()):
        status = (processor_device_status or {}).get(name)
        if not devices:
            processor_families[name] = None
            if status != "verified_parameterless_model":
                reasons.append(
                    f"processor {name!r} exposes no verifiable model parameter device"
                )
            continue
        if status is not None and status != "model_parameters_observed":
            reasons.append(
                f"processor {name!r} model-device inspection is incomplete: {status!r}"
            )
        unknown_devices = sorted(
            device for device in devices if _device_family(device) is None
        )
        if unknown_devices:
            reasons.append(
                f"processor {name!r} exposes unsupported devices {unknown_devices!r}"
            )
        families = sorted(
            {family for device in devices if (family := _device_family(device)) is not None}
        )
        processor_families[name] = families or None
        if len(families) != 1 or families[0] != expected_family:
            reasons.append(
                f"processor {name!r} devices {devices!r} do not agree with "
                f"resolved device {expected_family!r}"
            )
    return {
        "verified": not reasons,
        "requested_device": requested_device,
        "resolved_device_family": expected_family,
        "pipeline_device": pipeline_device,
        "pipeline_device_family": pipeline_family,
        "processor_model_devices": processor_model_devices,
        "processor_device_status": processor_device_status,
        "processor_device_families": processor_families,
        "reasons": reasons,
    }


def _manifest_object(path: Path, label: str) -> tuple[dict[str, Any] | None, str | None]:
    if not path.is_file():
        return None, f"{label} is missing: {path}"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, f"cannot read {label} {path}: {type(exc).__name__}: {exc}"
    if not isinstance(value, dict):
        return None, f"{label} root is not an object: {path}"
    return value, None


def _neural_manifest_verification(
    model_dir: Path, environment_manifest: Path
) -> dict[str, Any]:
    verifier = (PROJECT_ROOT / "scripts" / "write_neural_manifest.py").resolve()
    lock_path = (PROJECT_ROOT / "scripts" / "neural_assets.lock.json").resolve()
    model_manifest, model_error = _manifest_object(
        model_dir / "manifest.json", "neural model manifest"
    )
    environment, environment_error = _manifest_object(
        environment_manifest, "neural environment manifest"
    )
    reasons = [error for error in (model_error, environment_error) if error]
    selected_model_bundle_id = (
        model_manifest.get("bundle_id") if model_manifest is not None else None
    )
    environment_model_bundle_id = (
        environment.get("model_bundle_id") if environment is not None else None
    )
    environment_bundle_id = (
        environment.get("bundle_id") if environment is not None else None
    )
    for label, value in (
        ("selected model bundle", selected_model_bundle_id),
        ("environment model bundle", environment_model_bundle_id),
        ("environment bundle", environment_bundle_id),
    ):
        if not isinstance(value, str) or len(value) != 64:
            reasons.append(f"{label} identity is missing or malformed")
    if (
        isinstance(selected_model_bundle_id, str)
        and isinstance(environment_model_bundle_id, str)
        and selected_model_bundle_id != environment_model_bundle_id
    ):
        reasons.append(
            "selected model bundle does not match the live environment manifest"
        )

    verifier_record = _optional_file_record(verifier)
    lock_record = _optional_file_record(lock_path)
    if verifier_record is None:
        reasons.append(f"checked-in neural verifier is missing: {verifier}")
    if lock_record is None:
        reasons.append(f"checked-in neural lock is missing: {lock_path}")
    command = [
        sys.executable,
        str(verifier),
        "--lock",
        str(lock_path),
        "--model-dir",
        str(model_dir),
        "--project-root",
        str(PROJECT_ROOT),
        "--verify-environment-manifest",
    ]
    returncode: int | None = None
    stdout = ""
    diagnostic: str | None = None
    if verifier_record is not None and lock_record is not None and model_dir.is_dir():
        try:
            completed = subprocess.run(
                command,
                text=True,
                encoding="utf-8",
                capture_output=True,
                check=False,
                timeout=300,
            )
            returncode = int(completed.returncode)
            stdout = completed.stdout.strip()
            if returncode:
                diagnostic = (completed.stderr.strip() or stdout or "no diagnostic")[-2000:]
                reasons.append(
                    f"checked-in neural verifier exited with {returncode}: {diagnostic}"
                )
        except (OSError, subprocess.TimeoutExpired) as exc:
            diagnostic = f"{type(exc).__name__}: {exc}"
            reasons.append(f"checked-in neural verifier could not complete: {diagnostic}")
    else:
        reasons.append("checked-in neural verifier was not runnable")
    if (
        returncode == 0
        and isinstance(environment_bundle_id, str)
        and stdout.splitlines()[-1:] != [environment_bundle_id]
    ):
        reasons.append("neural verifier output does not name the live environment bundle")
    return {
        "verified": not reasons,
        "reasons": reasons,
        "selected_model_bundle_id": selected_model_bundle_id,
        "environment_model_bundle_id": environment_model_bundle_id,
        "environment_bundle_id": environment_bundle_id,
        "verifier": verifier_record,
        "lock": lock_record,
        "command": command,
        "returncode": returncode,
        "stdout": stdout[-1000:],
        "diagnostic": diagnostic,
    }


def _runtime_validity(
    backend_runtime: dict[str, Any], neural_resources: dict[str, Any] | None
) -> dict[str, Any]:
    backend_official = backend_runtime.get("official") is True
    reasons = list(backend_runtime.get("non_official_reasons", ()))
    neural_verified = True
    neural_status = None
    if neural_resources is not None:
        verification = neural_resources["verification"]
        neural_verified = verification.get("verified") is True
        reasons.extend(f"neural: {reason}" for reason in verification.get("reasons", ()))
        neural_status = {
            "verified": neural_verified,
            "selected_model_bundle_id": verification.get("selected_model_bundle_id"),
            "manifest_verified": verification["manifest"].get("verified") is True,
            "device_verified": verification["device"].get("verified") is True,
        }
    official = backend_official and neural_verified
    return {
        "official_runtime": official,
        "valid_for_official_performance_claims": official,
        "non_official_reasons": reasons,
        "backend_official": backend_official,
        "neural_status": neural_status,
    }


def _neural_worker_provenance(
    analyzer: Any, *, model_dir_value: str | None, requested_device: str
) -> dict[str, Any]:
    model_dir = (
        Path(model_dir_value).expanduser().resolve()
        if model_dir_value
        else (analyzer.backend.runtime_dir / "neural" / "stanza").resolve()
    )
    resources_json = model_dir / "resources.json"
    model_manifest = model_dir / "manifest.json"
    environment_manifest = Path(sys.prefix).resolve() / "qazmorph-neural-environment.json"
    declared_environment, environment_error = _manifest_object(
        environment_manifest, "neural environment manifest"
    )

    try:
        import torch
    except ImportError as exc:
        torch = None  # type: ignore[assignment]
        torch_error = f"{type(exc).__name__}: {exc}"
    else:
        torch_error = None

    cuda_available = bool(torch is not None and torch.cuda.is_available())
    devices: list[dict[str, Any]] = []
    if cuda_available:
        for index in range(torch.cuda.device_count()):
            properties = torch.cuda.get_device_properties(index)
            devices.append(
                {
                    "index": index,
                    "name": torch.cuda.get_device_name(index),
                    "capability": list(torch.cuda.get_device_capability(index)),
                    "total_memory_bytes": int(properties.total_memory),
                }
            )
    cudnn_version = None
    try:
        cudnn_version = torch.backends.cudnn.version() if torch is not None else None
    except (AttributeError, RuntimeError):
        pass
    packages = _visible_distribution_versions()
    pipeline = getattr(analyzer.neural_ranker, "pipeline", None)
    pipeline_device = (
        str(getattr(pipeline, "device"))
        if pipeline is not None and getattr(pipeline, "device", None) is not None
        else None
    )
    processor_inventory = _pipeline_device_inventory(analyzer.neural_ranker)
    processor_devices = {
        name: item["devices"] for name, item in processor_inventory.items()
    }
    processor_device_status = {
        name: str(item["status"]) for name, item in processor_inventory.items()
    }
    manifest_verification = _neural_manifest_verification(
        model_dir, environment_manifest
    )
    device_verification = _neural_device_verification(
        requested_device=requested_device,
        pipeline_device=pipeline_device,
        processor_model_devices=processor_devices,
        cuda_available=cuda_available,
        processor_device_status=processor_device_status,
    )
    verification_reasons = [
        *(f"manifest: {reason}" for reason in manifest_verification["reasons"]),
        *(f"device: {reason}" for reason in device_verification["reasons"]),
    ]
    model_files = {
        path.relative_to(model_dir).as_posix(): _required_file_record(path)
        for path in sorted(model_dir.rglob("*"))
        if path.is_file()
    }
    return {
        "model_dir": str(model_dir),
        "resources_json": _optional_file_record(resources_json),
        "model_manifest": _optional_file_record(model_manifest),
        "model_artifacts": {
            "files": model_files,
            "file_count": len(model_files),
            "total_bytes": sum(int(item["bytes"]) for item in model_files.values()),
        },
        "environment_manifest": (
            {
                **_required_file_record(environment_manifest),
                "declared_schema": (declared_environment or {}).get("schema"),
                "declared_bundle_id": (declared_environment or {}).get("bundle_id"),
                "declared_version": (declared_environment or {}).get("version"),
                "parse_error": environment_error,
            }
            if environment_manifest.is_file()
            else None
        ),
        "live_runtime": {
            "python": {
                "implementation": platform.python_implementation(),
                "version": platform.python_version(),
                "executable": sys.executable,
                "prefix": sys.prefix,
            },
            "visible_distribution_versions": packages,
            "torch": {
                "version": str(torch.__version__) if torch is not None else None,
                "compiled_cuda_version": torch.version.cuda if torch is not None else None,
                "cuda_available": cuda_available,
                "error": torch_error,
                "cudnn_version": cudnn_version,
                "current_cuda_device": torch.cuda.current_device() if cuda_available else None,
                "visible_cuda_devices": devices,
            },
            "requested_neural_device": requested_device,
            "pipeline_device": pipeline_device,
            "stanza_processor_parameter_devices": processor_devices,
            "stanza_processor_device_inventory": processor_inventory,
        },
        "verification": {
            "verified": not verification_reasons,
            "reasons": verification_reasons,
            "selected_model_bundle_id": manifest_verification.get(
                "selected_model_bundle_id"
            ),
            "manifest": manifest_verification,
            "device": device_verification,
        },
    }


def _worker_report_impl(args: argparse.Namespace, text: str) -> dict[str, Any]:
    source_snapshot = _software_provenance()
    Analyzer, version = _load_analyzer()
    mode_flags = _analyzer_mode_flags(args.worker_mode)
    neural = mode_flags["neural"]
    neural_use_gpu = {
        "auto": None,
        "cpu": False,
        "gpu": True,
    }[args.neural_device]
    analyzer = None
    close_report = None
    try:
        initialization_start = time.perf_counter_ns()
        analyzer = Analyzer(
            args.resource_dir,
            disambiguate=mode_flags["disambiguate"],
            guess=not args.no_guesser,
            fixlist=args.fixlist,
            guess_limit=args.guess_limit,
            neural=neural,
            neural_model_dir=args.neural_model_dir,
            neural_use_gpu=neural_use_gpu,
            ud_profile=args.ud_profile,
        )
        initialization_ms = (time.perf_counter_ns() - initialization_start) / 1_000_000
        resource_snapshot = _resource_provenance(analyzer)
        backend_runtime = resource_snapshot["backend_runtime"]
        neural_resources = (
            _neural_worker_provenance(
                analyzer,
                model_dir_value=args.neural_model_dir,
                requested_device=args.neural_device,
            )
            if neural
            else None
        )

        for _ in range(args.worker_warmups):
            analyzer.analyze(
                text,
                disambiguate=mode_flags["disambiguate"],
                generate_all=args.generate_all,
            )

        durations_ms: list[float] = []
        token_counts: list[int] = []
        for _ in range(args.worker_runs):
            started = time.perf_counter_ns()
            document = analyzer.analyze(
                text,
                disambiguate=mode_flags["disambiguate"],
                generate_all=args.generate_all,
            )
            durations_ms.append((time.perf_counter_ns() - started) / 1_000_000)
            token_counts.append(_analyzer_token_count(document))
        if len(set(token_counts)) != 1:
            raise BenchmarkError(f"analyzer emitted inconsistent token counts: {token_counts}")

        if _resource_provenance(analyzer) != resource_snapshot:
            raise BenchmarkError(
                "resource manifest, artifacts, or backend runtime changed while "
                "the worker was running"
            )
        if neural:
            final_neural_resources = _neural_worker_provenance(
                analyzer,
                model_dir_value=args.neural_model_dir,
                requested_device=args.neural_device,
            )
            if final_neural_resources != neural_resources:
                raise BenchmarkError("neural runtime changed while the worker was running")
    finally:
        if analyzer is not None:
            close_report = _close_analyzer_with_report(analyzer)

    final_source_snapshot = _software_provenance()
    if final_source_snapshot != source_snapshot:
        raise BenchmarkError("benchmark or qazmorph source changed while the worker was running")
    assert close_report is not None
    if _resource_provenance(analyzer) != resource_snapshot:
        raise BenchmarkError(
            "resource manifest, artifacts, or backend runtime changed before worker exit"
        )
    guesser_diagnostics = close_report["guesser_diagnostics_after_close"]
    runtime_validity = _runtime_validity(backend_runtime, neural_resources)

    return {
        "qazmorph_version": version,
        "software": source_snapshot,
        "resource_version": analyzer.backend.resource_version,
        "resource_dir": str(analyzer.backend.resource_dir),
        "resource_manifest": resource_snapshot["manifest"],
        "resource_provenance": resource_snapshot,
        "backend_runtime": backend_runtime,
        "runtime_validity": runtime_validity,
        "neural_resources": neural_resources,
        "initialization_ms": initialization_ms,
        "durations_ms": durations_ms,
        "output_tokens_per_call": token_counts[0],
        "timing_scope": {
            "initialization_ms": (
                "Analyzer constructor only, after qazmorph import; includes backend/resource "
                "validation and neural model loading when enabled"
            ),
            "durations_ms": (
                "one Analyzer.analyze call over the complete workload; includes HFST/CG "
                "subprocesses, productive OOV lookup, and neural inference as configured; "
                "excludes Analyzer construction, warm-ups, provenance hashing, close, JSON "
                "serialization, worker startup, and parent/worker I/O"
            ),
        },
        "guesser_diagnostics": guesser_diagnostics,
        "candidate_lattice": _candidate_lattice_completeness(guesser_diagnostics),
        "persistent_guesser_child": close_report,
        "rss_bytes": {
            "python_worker_peak_after_analyzer_close": _rss_bytes(resource.RUSAGE_SELF),
            "python_worker_current_after_analyzer_close": _current_rss_bytes(),
            "waited_children_peak_after_analyzer_close": _rss_bytes(resource.RUSAGE_CHILDREN),
        },
    }


def _worker_report(args: argparse.Namespace, text: str) -> dict[str, Any]:
    try:
        return _worker_report_impl(args, text)
    except BenchmarkError:
        raise
    except Exception as exc:
        raise BenchmarkError(f"{args.worker_mode} worker failed: {exc}") from exc


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _required_file_record(path: Path) -> dict[str, int | str]:
    if not path.is_file():
        raise BenchmarkError(f"required provenance file is missing: {path}")
    return {
        "path": str(path.resolve()),
        "bytes": path.stat().st_size,
        "sha256": _sha256_file(path),
    }


def _optional_file_record(path: Path) -> dict[str, int | str] | None:
    return _required_file_record(path) if path.is_file() else None


def _resource_provenance(analyzer: Any) -> dict[str, Any]:
    manifest = dict(analyzer.backend.manifest)
    resource_dir = Path(analyzer.backend.resource_dir).resolve()
    manifest_path = resource_dir / "manifest.json"
    manifest_files = manifest.get("files")
    if not isinstance(manifest_files, dict) or not manifest_files:
        raise BenchmarkError("resource manifest has no artifact inventory")
    return {
        "resource_dir": str(resource_dir),
        "resource_version": analyzer.backend.resource_version,
        "manifest": manifest,
        "manifest_file": _required_file_record(manifest_path),
        "resource_artifacts": {
            str(name): _required_file_record(resource_dir / str(name))
            for name in sorted(manifest_files)
        },
        "backend_runtime": analyzer.backend.runtime_provenance(),
    }


def _parent_resource_file_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Independently re-read a worker's full manifest and artifact inventory."""

    resource_dir = Path(str(snapshot["resource_dir"]))
    manifest_path = resource_dir / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"cannot re-read resource manifest {manifest_path}: {exc}") from exc
    if not isinstance(manifest, dict):
        raise BenchmarkError(f"resource manifest root is not an object: {manifest_path}")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise BenchmarkError("resource manifest has no artifact inventory")
    return {
        "resource_dir": str(resource_dir.resolve()),
        "resource_version": snapshot.get("resource_version"),
        "manifest": manifest,
        "manifest_file": _required_file_record(manifest_path),
        "resource_artifacts": {
            str(name): _required_file_record(resource_dir / str(name))
            for name in sorted(files)
        },
    }


def _resource_static_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        key: snapshot[key]
        for key in (
            "resource_dir",
            "resource_version",
            "manifest",
            "manifest_file",
            "resource_artifacts",
        )
    }


def _software_provenance() -> dict[str, Any]:
    """Hash the exact benchmark and project sources imported by each worker."""

    paths = [Path(__file__).resolve(), *sorted((SOURCE_ROOT / "qazmorph").glob("*.py"))]
    files = {
        path.relative_to(PROJECT_ROOT).as_posix(): {
            "bytes": path.stat().st_size,
            "sha256": _sha256_file(path),
        }
        for path in paths
    }
    identity = json.dumps(
        files, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "files": files,
        "bundle_sha256": hashlib.sha256(identity).hexdigest(),
    }


def _neural_resource_provenance(
    model_dir_value: str | Path, worker_snapshot: dict[str, Any]
) -> dict[str, Any]:
    """Parent-side rehash and verifier replay outside worker wall timings."""

    model_dir = Path(model_dir_value).expanduser().resolve()
    resources_json = model_dir / "resources.json"
    model_manifest = model_dir / "manifest.json"
    if _optional_file_record(resources_json) != worker_snapshot.get("resources_json"):
        raise BenchmarkError("neural resources.json changed while the benchmark was running")
    if _optional_file_record(model_manifest) != worker_snapshot.get("model_manifest"):
        raise BenchmarkError("neural model manifest changed while the benchmark was running")
    environment_snapshot = worker_snapshot.get("environment_manifest")
    environment_path = Path(sys.prefix).resolve() / "qazmorph-neural-environment.json"
    current_environment = _optional_file_record(environment_path)
    if environment_snapshot is None:
        if current_environment is not None:
            raise BenchmarkError(
                "neural environment manifest appeared while the benchmark was running"
            )
    elif not isinstance(environment_snapshot, dict):
        raise BenchmarkError("neural worker emitted invalid environment provenance")
    else:
        for field in ("path", "bytes", "sha256"):
            if current_environment is None or current_environment[field] != environment_snapshot.get(field):
                raise BenchmarkError(
                    "neural environment manifest changed while the benchmark was running"
                )
    model_files = {
        path.relative_to(model_dir).as_posix(): _required_file_record(path)
        for path in sorted(model_dir.rglob("*"))
        if path.is_file()
    }
    current_artifacts = {
        "files": model_files,
        "file_count": len(model_files),
        "total_bytes": sum(int(item["bytes"]) for item in model_files.values()),
    }
    if current_artifacts != worker_snapshot.get("model_artifacts"):
        raise BenchmarkError("neural model artifacts changed while the benchmark was running")
    worker_verification = worker_snapshot.get("verification")
    if not isinstance(worker_verification, dict):
        raise BenchmarkError("neural worker omitted verifier provenance")
    parent_manifest_verification = _neural_manifest_verification(
        model_dir, environment_path
    )
    if parent_manifest_verification != worker_verification.get("manifest"):
        raise BenchmarkError(
            "parent neural manifest verification differs from the worker snapshot"
        )
    return {
        **worker_snapshot,
        "parent_reverification": {
            "complete": True,
            "model_artifacts_unchanged": True,
            "environment_manifest_unchanged": True,
            "manifest_verifier_replayed": True,
        },
    }


def _misc_map(value: str) -> dict[str, str | None]:
    if value == "_":
        return {}
    result: dict[str, str | None] = {}
    for item in value.split("|"):
        if "=" in item:
            key, item_value = item.split("=", 1)
            result[key] = item_value
        else:
            result[item] = None
    return result


def _decode_ud_spaces(value: str) -> str:
    replacements = {"s": " ", "n": "\n", "t": "\t", "r": "\r", "p": "|", "\\": "\\"}
    output: list[str] = []
    index = 0
    while index < len(value):
        if value[index] == "\\" and index + 1 < len(value):
            output.append(replacements.get(value[index + 1], value[index + 1]))
            index += 2
        else:
            output.append(value[index])
            index += 1
    return "".join(output)


def _conllu_texts(path: Path) -> Iterator[str]:
    """Yield sentence text without interpreting morphology columns.

    Performance corpora sometimes use CoNLL-U-shaped files with analyzer-native
    tags in FEATS.  Benchmark extraction only needs FORM/MISC, so it deliberately
    does not couple workload loading to the stricter UD evaluator.
    """

    text_comment: str | None = None
    surface_rows: list[tuple[str, str, str]] = []

    def flush() -> str | None:
        nonlocal text_comment, surface_rows
        if text_comment is not None:
            value = text_comment
        elif surface_rows:
            pieces: list[str] = []
            covered_until = 0
            selected: list[tuple[str, str]] = []
            for token_id, form, misc in surface_rows:
                if "-" in token_id:
                    try:
                        start_text, end_text = token_id.split("-", 1)
                        start, end = int(start_text), int(end_text)
                    except ValueError as exc:
                        raise BenchmarkError(
                            f"{path}: invalid multiword token ID {token_id!r}"
                        ) from exc
                    selected.append((form, misc))
                    covered_until = max(covered_until, end)
                    continue
                if "." in token_id:
                    continue
                try:
                    integer_id = int(token_id)
                except ValueError as exc:
                    raise BenchmarkError(f"{path}: invalid token ID {token_id!r}") from exc
                if integer_id <= covered_until:
                    continue
                selected.append((form, misc))
            previous_misc: dict[str, str | None] | None = None
            for index, (form, misc_value) in enumerate(selected):
                misc = _misc_map(misc_value)
                if index == 0:
                    if misc.get("SpacesBefore") is not None:
                        pieces.append(_decode_ud_spaces(str(misc["SpacesBefore"])))
                elif misc.get("SpacesBefore") is not None:
                    pieces.append(_decode_ud_spaces(str(misc["SpacesBefore"])))
                elif previous_misc is not None and previous_misc.get("SpacesAfter") is not None:
                    pieces.append(_decode_ud_spaces(str(previous_misc["SpacesAfter"])))
                elif previous_misc is None or previous_misc.get("SpaceAfter") != "No":
                    pieces.append(" ")
                pieces.append(form)
                previous_misc = misc
            if previous_misc is not None and previous_misc.get("SpacesAfter") is not None:
                pieces.append(_decode_ud_spaces(str(previous_misc["SpacesAfter"])))
            value = "".join(pieces)
        else:
            value = None
        text_comment = None
        surface_rows = []
        return value

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.rstrip("\r\n")
            if not line:
                sentence_text = flush()
                if sentence_text is not None:
                    yield sentence_text
                continue
            if line.startswith("#"):
                comment = line[1:].strip()
                if "=" in comment:
                    key, value = comment.split("=", 1)
                    if key.strip() == "text":
                        text_comment = value.lstrip()
                continue
            columns = line.split("\t")
            if len(columns) != 10:
                raise BenchmarkError(
                    f"{path}:{line_number}: expected 10 tab-separated columns, got {len(columns)}"
                )
            surface_rows.append((columns[0], columns[1], columns[9]))

    sentence_text = flush()
    if sentence_text is not None:
        yield sentence_text


def _discover_inputs(values: Sequence[str], input_format: str) -> list[Path]:
    paths: list[Path] = []
    seen: set[Path] = set()
    for value in values:
        candidate = Path(value).expanduser()
        if not candidate.exists():
            raise BenchmarkError(f"input does not exist: {candidate}")
        if candidate.is_dir():
            if input_format == "text":
                raise BenchmarkError(f"text input must be a file, not a directory: {candidate}")
            discovered = sorted(candidate.rglob("*.conllu"))
            if not discovered:
                raise BenchmarkError(f"directory contains no .conllu files: {candidate}")
        else:
            discovered = [candidate]
        for path in discovered:
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                paths.append(resolved)
    return paths


def _input_record(path: Path, selected_format: str) -> dict[str, Any]:
    return {
        **_required_file_record(path),
        "format": selected_format,
    }


def _rehash_inputs(inputs: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        _input_record(Path(str(item["path"])), str(item["format"]))
        for item in inputs
    ]


def _load_workload(args: argparse.Namespace) -> tuple[str, list[dict[str, Any]], str]:
    input_paths = _discover_inputs(args.input, args.input_format)
    chunks: list[str] = []
    metadata: list[dict[str, Any]] = []
    for path in input_paths:
        selected_format = args.input_format
        if selected_format == "auto":
            selected_format = "conllu" if path.suffix.lower() == ".conllu" else "text"
        before = _input_record(path, selected_format)
        if selected_format == "conllu":
            chunks.extend(_conllu_texts(path))
        else:
            chunks.append(path.read_text(encoding="utf-8"))
        after = _input_record(path, selected_format)
        if after != before:
            raise BenchmarkError(f"input changed while it was being loaded: {path}")
        metadata.append(before)

    if args.text is not None:
        chunks.append(args.text)
    if not chunks:
        chunks.append(BUILTIN_TEXT)
        source_kind = "built-in Kazakh sample"
    else:
        source_kind = "provided input"

    workload = "\n".join(chunk for chunk in chunks if chunk)
    if args.repeat_workload > 1:
        workload = "\n".join(workload for _ in range(args.repeat_workload))
    if args.max_chars is not None:
        workload = workload[: args.max_chars]
    if not workload or not workload.strip():
        raise BenchmarkError("benchmark workload is empty")
    return workload, metadata, source_kind


def _worker_command(
    args: argparse.Namespace,
    *,
    kind: str,
    mode: str,
    runs: int,
    warmups: int,
) -> list[str]:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--_worker-kind",
        kind,
        "--_worker-mode",
        mode,
        "--_worker-runs",
        str(runs),
        "--_worker-warmups",
        str(warmups),
        "--guess-limit",
        str(args.guess_limit),
    ]
    if args.resource_dir:
        command.extend(("--resource-dir", args.resource_dir))
    command.extend(("--ud-profile", args.ud_profile))
    if args.fixlist:
        command.extend(("--fixlist", args.fixlist))
    if args.no_guesser:
        command.append("--no-guesser")
    if args.generate_all:
        command.append("--generate-all")
    if args.neural_model_dir:
        command.extend(("--neural-model-dir", args.neural_model_dir))
    command.extend(("--neural-device", args.neural_device))
    return command


def _invoke_worker(
    args: argparse.Namespace,
    text: str,
    *,
    kind: str,
    mode: str,
    runs: int,
    warmups: int,
) -> tuple[dict[str, Any], float]:
    command = _worker_command(args, kind=kind, mode=mode, runs=runs, warmups=warmups)
    environment = os.environ.copy()
    environment["PYTHONHASHSEED"] = "0"
    started = time.perf_counter_ns()
    try:
        completed = subprocess.run(
            command,
            input=text,
            text=True,
            encoding="utf-8",
            capture_output=True,
            check=False,
            timeout=args.timeout_seconds,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BenchmarkError(f"{kind} {mode} worker failed: {exc}") from exc
    wall_ms = (time.perf_counter_ns() - started) / 1_000_000
    if completed.returncode:
        diagnostic = completed.stderr.strip() or completed.stdout.strip()
        raise BenchmarkError(
            f"{kind} {mode} worker exited with {completed.returncode}: {diagnostic}"
        )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise BenchmarkError(
            f"{kind} {mode} worker returned invalid JSON: {completed.stdout[:500]!r}"
        ) from exc
    return report, wall_ms


def _throughput(
    *, text: str, output_tokens: int, calls: int, elapsed_ms: float
) -> dict[str, float | int | None]:
    elapsed_seconds = elapsed_ms / 1000.0
    if elapsed_seconds <= 0:
        return {
            "calls": calls,
            "elapsed_seconds": elapsed_seconds,
            "calls_per_second": None,
            "tokens_per_second": None,
            "characters_per_second": None,
            "utf8_bytes_per_second": None,
        }
    return {
        "calls": calls,
        "elapsed_seconds": round(elapsed_seconds, 6),
        "calls_per_second": round(calls / elapsed_seconds, 3),
        "tokens_per_second": round(output_tokens * calls / elapsed_seconds, 3),
        "characters_per_second": round(len(text) * calls / elapsed_seconds, 3),
        "utf8_bytes_per_second": round(len(text.encode("utf-8")) * calls / elapsed_seconds, 3),
    }


def _memory_summary(reports: Sequence[dict[str, Any]]) -> dict[str, Any]:
    keys = (
        "python_worker_peak_after_analyzer_close",
        "python_worker_current_after_analyzer_close",
        "waited_children_peak_after_analyzer_close",
    )
    output: dict[str, Any] = {}
    for key in keys:
        values = [
            int(report["rss_bytes"][key])
            for report in reports
            if report["rss_bytes"].get(key) is not None
        ]
        output[key] = {
            "samples_bytes": values,
            "maximum_bytes": max(values) if values else None,
            "mean_bytes": round(statistics.fmean(values), 1) if values else None,
        }
    return output


def _worker_provenance(
    report: dict[str, Any]
) -> tuple[str, str, str, str, str, str, str]:
    return (
        str(report["qazmorph_version"]),
        json.dumps(report["software"], ensure_ascii=False, sort_keys=True),
        str(report["resource_dir"]),
        json.dumps(report["resource_manifest"], ensure_ascii=False, sort_keys=True),
        json.dumps(report["resource_provenance"], ensure_ascii=False, sort_keys=True),
        json.dumps(report["backend_runtime"], ensure_ascii=False, sort_keys=True),
        json.dumps(report.get("neural_resources"), ensure_ascii=False, sort_keys=True),
    )


def _benchmark_mode(args: argparse.Namespace, text: str, mode: str) -> dict[str, Any]:
    cold_reports: list[dict[str, Any]] = []
    cold_wall_ms: list[float] = []
    for _ in range(args.cold_runs):
        report, wall_ms = _invoke_worker(
            args, text, kind="cold", mode=mode, runs=1, warmups=0
        )
        cold_reports.append(report)
        cold_wall_ms.append(wall_ms)

    token_counts = {int(report["output_tokens_per_call"]) for report in cold_reports}
    if len(token_counts) != 1:
        raise BenchmarkError(f"cold workers emitted inconsistent token counts: {sorted(token_counts)}")
    output_tokens = token_counts.pop()
    cold_analysis_ms = [float(report["durations_ms"][0]) for report in cold_reports]
    cold_initialization_ms = [float(report["initialization_ms"]) for report in cold_reports]

    warm_report, warm_process_wall_ms = _invoke_worker(
        args,
        text,
        kind="warm",
        mode=mode,
        runs=args.runs,
        warmups=args.warmup_runs,
    )
    provenance = _worker_provenance(warm_report)
    if any(_worker_provenance(report) != provenance for report in cold_reports):
        raise BenchmarkError(
            f"{mode} workers used different qazmorph code or resource manifests"
        )
    if int(warm_report["output_tokens_per_call"]) != output_tokens:
        raise BenchmarkError(
            "cold and warm workers emitted different token counts: "
            f"{output_tokens} versus {warm_report['output_tokens_per_call']}"
        )
    warm_durations_ms = [float(value) for value in warm_report["durations_ms"]]
    lattice_reports = [report["candidate_lattice"] for report in cold_reports] + [
        warm_report["candidate_lattice"]
    ]

    return {
        "output_tokens_per_call": output_tokens,
        "cold": {
            "definition": (
                "one analysis in each fresh Python process; OS page caches are not cleared"
            ),
            "runs": args.cold_runs,
            "fresh_process_wall_latency_ms": {
                "scope": (
                    "parent perf_counter around subprocess.run: process spawn, workload stdin "
                    "transfer, imports, Analyzer initialization, analysis, provenance hashing, "
                    "Analyzer close/waits, worker JSON serialization, and stdout/stderr capture"
                ),
                "summary": _summary(cold_wall_ms),
                "samples": [round(value, 3) for value in cold_wall_ms],
            },
            "analysis_latency_ms": {
                "scope": cold_reports[0]["timing_scope"]["durations_ms"],
                "summary": _summary(cold_analysis_ms),
                "samples": [round(value, 3) for value in cold_analysis_ms],
            },
            "analyzer_initialization_latency_ms": {
                "scope": cold_reports[0]["timing_scope"]["initialization_ms"],
                "summary": _summary(cold_initialization_ms),
                "samples": [round(value, 3) for value in cold_initialization_ms],
            },
            "throughput_including_process_start": _throughput(
                text=text,
                output_tokens=output_tokens,
                calls=args.cold_runs,
                elapsed_ms=sum(cold_wall_ms),
            ),
            "analysis_only_throughput": _throughput(
                text=text,
                output_tokens=output_tokens,
                calls=args.cold_runs,
                elapsed_ms=sum(cold_analysis_ms),
            ),
            "rss": _memory_summary(cold_reports),
            "persistent_guesser_children": [
                report["persistent_guesser_child"] for report in cold_reports
            ],
            "guesser_diagnostics_by_worker": [
                report["guesser_diagnostics"] for report in cold_reports
            ],
        },
        "warm": {
            "definition": "repeated measured calls through one Analyzer after warm-up calls",
            "warmup_runs": args.warmup_runs,
            "measured_runs": args.runs,
            "analysis_latency_ms": {
                "scope": warm_report["timing_scope"]["durations_ms"],
                "summary": _summary(warm_durations_ms),
                "samples": [round(value, 3) for value in warm_durations_ms],
            },
            "throughput": _throughput(
                text=text,
                output_tokens=output_tokens,
                calls=args.runs,
                elapsed_ms=sum(warm_durations_ms),
            ),
            "analyzer_initialization_latency_ms": round(
                float(warm_report["initialization_ms"]), 3
            ),
            "analyzer_initialization_scope": warm_report["timing_scope"]["initialization_ms"],
            "worker_process_wall_ms": round(warm_process_wall_ms, 3),
            "worker_process_wall_scope": (
                "parent perf_counter around the complete warm-worker subprocess.run; includes "
                "untimed warm-ups and all setup/provenance/close/IPC overhead"
            ),
            "rss": warm_report["rss_bytes"],
            "persistent_guesser_child": warm_report["persistent_guesser_child"],
            "guesser_diagnostics": warm_report["guesser_diagnostics"],
        },
        "candidate_lattice": {
            "complete_across_all_workers": all(
                bool(report["complete"]) for report in lattice_reports
            ),
            "cold_workers": [report["candidate_lattice"] for report in cold_reports],
            "warm_worker": warm_report["candidate_lattice"],
            "scope": (
                "all warm-up and measured Analyzer.analyze calls made by every worker in "
                "this mode"
            ),
        },
        "resource_version": warm_report["resource_version"],
        "resource_dir": warm_report["resource_dir"],
        "resource_manifest": warm_report["resource_manifest"],
        "resource_provenance": warm_report["resource_provenance"],
        "backend_runtime": warm_report["backend_runtime"],
        "runtime_validity": warm_report["runtime_validity"],
        "neural_resources": warm_report.get("neural_resources"),
        "qazmorph_version": warm_report["qazmorph_version"],
        "software": warm_report["software"],
    }


def _cpu_model() -> str | None:
    cpuinfo = Path("/proc/cpuinfo")
    if not cpuinfo.is_file():
        return platform.processor() or None
    try:
        for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lower().startswith("model name") and ":" in line:
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or None


def _available_cpu_count() -> int | None:
    try:
        return len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        return os.cpu_count()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Measure fresh-process and warmed-instance qazmorph performance. "
            "No datasets are downloaded."
        )
    )
    parser.add_argument("input", nargs="*", help="existing text or CoNLL-U files")
    parser.add_argument("--text", help="literal text to append to the workload")
    parser.add_argument(
        "--input-format", choices=("auto", "text", "conllu"), default="auto"
    )
    parser.add_argument("--resource-dir", help="directory containing compiled qazmorph resources")
    parser.add_argument("--fixlist", help="optional qazmorph JSONL/TSV fixlist")
    parser.add_argument("--output", default="-", help="JSON output path (default: stdout)")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    parser.add_argument(
        "--mode",
        choices=("lattice", "cg", "contextual", "neural", "both", "all"),
        default="both",
        help=(
            "lattice, CG top-1, neural top-1, both=lattice+CG (default), or all; "
            "contextual is an alias for cg"
        ),
    )
    parser.add_argument("--cold-runs", type=int, default=3, metavar="N")
    parser.add_argument("--warmup-runs", type=int, default=2, metavar="N")
    parser.add_argument("--runs", type=int, default=10, metavar="N")
    parser.add_argument("--repeat-workload", type=int, default=1, metavar="N")
    parser.add_argument("--max-chars", type=int, metavar="N")
    parser.add_argument("--timeout-seconds", type=float, default=300.0, metavar="SECONDS")
    parser.add_argument("--no-guesser", action="store_true")
    parser.add_argument("--guess-limit", type=int, default=8, metavar="N")
    parser.add_argument(
        "--ud-profile",
        choices=("universal", "ktb"),
        default="universal",
        help="UD projection profile (default: universal)",
    )
    parser.add_argument("--generate-all", action="store_true")
    parser.add_argument("--neural-model-dir", help="Stanza Kazakh model directory")
    parser.add_argument(
        "--neural-device",
        choices=("auto", "cpu", "gpu"),
        default="auto",
        help="neural inference device (default: auto)",
    )

    # Private worker protocol. The orchestrator sends workload text over stdin.
    parser.add_argument(
        "--_worker-kind",
        dest="worker_kind",
        choices=("cold", "warm"),
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--_worker-mode",
        dest="worker_mode",
        choices=("lattice", "cg", "neural"),
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--_worker-runs", dest="worker_runs", type=int, default=1, help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--_worker-warmups",
        dest="worker_warmups",
        type=int,
        default=0,
        help=argparse.SUPPRESS,
    )
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    positive = {
        "--cold-runs": args.cold_runs,
        "--runs": args.runs,
        "--repeat-workload": args.repeat_workload,
        "--guess-limit": args.guess_limit,
    }
    for flag, value in positive.items():
        if value < 1:
            parser.error(f"{flag} must be positive")
    if args.warmup_runs < 0:
        parser.error("--warmup-runs cannot be negative")
    if args.max_chars is not None and args.max_chars < 1:
        parser.error("--max-chars must be positive")
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")


def run(args: argparse.Namespace) -> dict[str, Any]:
    source_snapshot = _software_provenance()
    text, inputs, source_kind = _load_workload(args)
    if args.mode == "both":
        modes = ("lattice", "cg")
    elif args.mode == "all":
        modes = ("lattice", "cg", "neural")
    elif args.mode == "contextual":
        modes = ("cg",)
    else:
        modes = (args.mode,)

    fixlist_metadata = None
    if args.fixlist:
        fixlist_path = Path(args.fixlist).expanduser().resolve()
        fixlist_metadata = _required_file_record(fixlist_path)
    results: dict[str, dict[str, Any]] = {}
    parent_resource_snapshots: dict[str, dict[str, Any]] = {}
    for mode in modes:
        result = _benchmark_mode(args, text, mode)
        worker_resource = result["resource_provenance"]
        parent_snapshot = _parent_resource_file_snapshot(worker_resource)
        if parent_snapshot != _resource_static_snapshot(worker_resource):
            raise BenchmarkError(
                f"parent and {mode} worker observed different resource manifest/artifacts"
            )
        results[mode] = result
        parent_resource_snapshots[mode] = parent_snapshot
    provenance = {
        (
            result["qazmorph_version"],
            json.dumps(result["software"], ensure_ascii=False, sort_keys=True),
            result["resource_dir"],
            json.dumps(result["resource_manifest"], ensure_ascii=False, sort_keys=True),
            json.dumps(result["resource_provenance"], ensure_ascii=False, sort_keys=True),
            json.dumps(result["backend_runtime"], ensure_ascii=False, sort_keys=True),
        )
        for result in results.values()
    }
    if len(provenance) != 1:
        raise BenchmarkError(
            "benchmark workers did not use identical code/resources/backend runtimes"
        )
    if any(result["software"] != source_snapshot for result in results.values()):
        raise BenchmarkError("workers did not use the parent source snapshot")
    official_runtime = all(
        result["runtime_validity"]["official_runtime"] is True
        for result in results.values()
    )
    valid_for_official_performance_claims = all(
        result["runtime_validity"]["valid_for_official_performance_claims"] is True
        for result in results.values()
    )
    non_official_reasons = sorted(
        {
            f"{mode}: {reason}"
            for mode, result in results.items()
            for reason in result["runtime_validity"]["non_official_reasons"]
        }
    )

    final_inputs = _rehash_inputs(inputs)
    if final_inputs != inputs:
        raise BenchmarkError("an input changed while the benchmark was running")

    if args.fixlist:
        fixlist_path = Path(args.fixlist).expanduser().resolve()
        final_fixlist_metadata = _required_file_record(fixlist_path)
        if final_fixlist_metadata != fixlist_metadata:
            raise BenchmarkError("fixlist changed while the benchmark was running")

    final_source_snapshot = _software_provenance()
    if final_source_snapshot != source_snapshot:
        raise BenchmarkError("benchmark or qazmorph source changed while the benchmark ran")

    for mode, result in results.items():
        final_resource = _parent_resource_file_snapshot(result["resource_provenance"])
        if final_resource != parent_resource_snapshots[mode]:
            raise BenchmarkError(
                f"{mode} resource manifest or artifacts changed while the benchmark ran"
            )
    if "neural" in results:
        neural_snapshot = results["neural"]["neural_resources"]
        results["neural"]["neural_resources"] = _neural_resource_provenance(
            neural_snapshot["model_dir"], neural_snapshot
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "definitions": {
            "cold": "fresh Python process; operating-system page caches are left intact",
            "warm": "one Analyzer instance, fixed warm-up count, then fixed measured calls",
            "latency_unit": "milliseconds per complete workload",
            "token_throughput_unit": "non-space analyzer output tokens per second",
            "rss_note": (
                "Python ru_maxrss is sampled after Analyzer.close. RUSAGE_CHILDREN ru_maxrss "
                "is sampled after persistent-child waits and is the largest peak among "
                "waited children, not an aggregate or simultaneous Python+child peak. The "
                "persistent guesser child also has a live /proc RSS/HWM sample before close "
                "when Linux exposes it."
            ),
        },
        "environment": {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "python_executable": sys.executable,
            "cpu_model": _cpu_model(),
            "logical_cpus_visible": _available_cpu_count(),
            "environment_threads": {
                name: os.environ.get(name)
                for name in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS")
            },
        },
        "configuration": {
            "mode": args.mode,
            "resolved_modes": list(modes),
            "cold_runs": args.cold_runs,
            "warmup_runs": args.warmup_runs,
            "measured_warm_runs": args.runs,
            "guesser": not args.no_guesser,
            "guess_limit": args.guess_limit,
            "ud_profile": args.ud_profile,
            "generate_all": args.generate_all,
            "repeat_workload": args.repeat_workload,
            "max_chars": args.max_chars,
            "timeout_seconds_per_worker": args.timeout_seconds,
            "fixlist": fixlist_metadata,
            "neural_model_dir": (
                str(Path(args.neural_model_dir).expanduser().resolve())
                if args.neural_model_dir
                else None
            ),
            "neural_device": args.neural_device if "neural" in modes else None,
        },
        "workload": {
            "source_kind": source_kind,
            "inputs": inputs,
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "characters": len(text),
            "utf8_bytes": len(text.encode("utf-8")),
            "lines": len(text.splitlines()),
        },
        "integrity": {
            "software_snapshot_before_work": source_snapshot,
            "software_reverified_after_work": True,
            "inputs_rehashed_after_work": True,
            "fixlist_rehashed_after_work": bool(args.fixlist),
            "resource_manifests_and_artifacts_rehashed_by_parent": True,
            "neural_artifacts_and_verifier_rechecked_after_work": (
                "neural" in results
            ),
            "official_runtime": official_runtime,
            "valid_for_official_performance_claims": (
                valid_for_official_performance_claims
            ),
            "non_official_reasons": non_official_reasons,
        },
        "results": results,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.worker_kind is not None:
        if args.worker_mode is None:
            parser.error("--_worker-mode is required in worker mode")
        if args.worker_runs < 1 or args.worker_warmups < 0:
            parser.error("invalid private worker iteration count")
        try:
            report = _worker_report(args, sys.stdin.read())
            sys.stdout.write(json.dumps(report, ensure_ascii=False, separators=(",", ":")) + "\n")
        except (BenchmarkError, OSError, UnicodeError, ValueError) as exc:
            parser.exit(2, f"benchmark.py worker: error: {exc}\n")
        return 0

    _validate_args(parser, args)
    try:
        report = run(args)
        encoded = json.dumps(
            report,
            ensure_ascii=False,
            indent=2 if args.pretty else None,
            sort_keys=True,
            separators=None if args.pretty else (",", ":"),
        ) + "\n"
        if args.output == "-":
            sys.stdout.write(encoded)
        else:
            Path(args.output).expanduser().write_text(encoded, encoding="utf-8")
    except (BenchmarkError, OSError, UnicodeError, ValueError) as exc:
        parser.exit(2, f"benchmark.py: error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
