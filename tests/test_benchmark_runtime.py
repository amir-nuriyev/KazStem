from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "qazmorph_benchmark_runtime_test", ROOT / "scripts" / "benchmark.py"
)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


class _FakeWorker:
    def __init__(self) -> None:
        self._process = None


class _FakeGuesser:
    def __init__(self, diagnostics: dict[str, int]) -> None:
        self._worker = _FakeWorker()
        self._diagnostics = diagnostics

    @property
    def diagnostics(self) -> dict[str, int]:
        return dict(self._diagnostics)


class _FakeBackend:
    resource_version = "test-resource"
    resource_dir = Path("/remote/test-resource")
    runtime_dir = Path("/remote/test-runtime")
    manifest = {"version": resource_version, "bundle_id": "test-bundle"}

    @staticmethod
    def runtime_provenance() -> dict[str, object]:
        return {"executables": {"hfst-proc": {"sha256": "exact"}}}


def _worker_args() -> argparse.Namespace:
    return argparse.Namespace(
        worker_mode="lattice",
        neural_device="cpu",
        resource_dir=None,
        no_guesser=False,
        fixlist=None,
        guess_limit=8,
        ud_profile="universal",
        neural_model_dir=None,
        worker_warmups=0,
        worker_runs=1,
        generate_all=False,
    )


def _mode_result(software: dict[str, object]) -> dict[str, object]:
    resource_provenance = {
        "resource_dir": "/resource",
        "resource_version": "resource",
        "manifest": {"bundle_id": "resource"},
        "manifest_file": {"path": "/resource/manifest.json", "bytes": 1, "sha256": "m"},
        "resource_artifacts": {
            "analyzer.bin": {
                "path": "/resource/analyzer.bin",
                "bytes": 1,
                "sha256": "a",
            }
        },
        "backend_runtime": {"executables": {"hfst-proc": "runtime"}},
    }
    return {
        "qazmorph_version": "test",
        "software": software,
        "resource_dir": "/resource",
        "resource_manifest": {"bundle_id": "resource"},
        "resource_provenance": resource_provenance,
        "backend_runtime": {"executables": {"hfst-proc": "runtime"}},
        "runtime_validity": {
            "official_runtime": True,
            "valid_for_official_performance_claims": True,
            "non_official_reasons": [],
        },
        "neural_resources": None,
    }


class BenchmarkRuntimeTests(unittest.TestCase):
    def test_worker_constructor_and_calls_use_mode_specific_flags(self) -> None:
        resource_snapshot = {
            "resource_dir": "/remote/test-resource",
            "resource_version": "test-resource",
            "manifest": dict(_FakeBackend.manifest),
            "manifest_file": {"path": "/manifest", "bytes": 1, "sha256": "m"},
            "resource_artifacts": {"a": {"path": "/a", "bytes": 1, "sha256": "a"}},
            "backend_runtime": _FakeBackend.runtime_provenance(),
        }
        neural_snapshot = {
            "verification": {
                "verified": True,
                "reasons": [],
                "selected_model_bundle_id": "model",
                "manifest": {"verified": True},
                "device": {"verified": True},
            }
        }

        for mode in ("lattice", "cg", "neural"):
            with self.subTest(mode=mode):
                constructor_calls: list[dict[str, object]] = []
                analysis_calls: list[dict[str, object]] = []

                class Analyzer:
                    def __init__(self, *args: object, **kwargs: object) -> None:
                        constructor_calls.append(dict(kwargs))
                        self.backend = _FakeBackend()
                        self.guesser = _FakeGuesser({})

                    def analyze(self, *args: object, **kwargs: object) -> object:
                        analysis_calls.append(dict(kwargs))
                        return SimpleNamespace(
                            tokens=[SimpleNamespace(text="сөз", kind="word")]
                        )

                    def close(self) -> None:
                        pass

                args = _worker_args()
                args.worker_mode = mode
                args.worker_warmups = 1
                with mock.patch.object(
                    benchmark, "_load_analyzer", return_value=(Analyzer, "test")
                ), mock.patch.object(
                    benchmark, "_resource_provenance", return_value=resource_snapshot
                ), mock.patch.object(
                    benchmark,
                    "_neural_worker_provenance",
                    return_value=neural_snapshot,
                ):
                    benchmark._worker_report_impl(args, "сөз")

                self.assertEqual(len(constructor_calls), 1)
                self.assertEqual(
                    {
                        "disambiguate": constructor_calls[0]["disambiguate"],
                        "neural": constructor_calls[0]["neural"],
                    },
                    benchmark._analyzer_mode_flags(mode),
                )
                self.assertEqual(len(analysis_calls), 2)
                self.assertEqual(
                    [call["disambiguate"] for call in analysis_calls],
                    [mode == "cg", mode == "cg"],
                )

    def test_schema_and_bounded_lookup_completeness(self) -> None:
        self.assertEqual(benchmark.SCHEMA_VERSION, "qazmorph.benchmark.v3")
        complete = benchmark._candidate_lattice_completeness({})
        self.assertTrue(complete["complete"])
        for event in (
            "cap_aborts",
            "timeouts",
            "failures",
            "cycle_truncations",
            "unsafe_resource_skips",
        ):
            with self.subTest(event=event):
                report = benchmark._candidate_lattice_completeness({event: 1})
                self.assertFalse(report["complete"])
                self.assertEqual(report["incomplete_event_counts"][event], 1)
        unsafe = benchmark._candidate_lattice_completeness(
            {"productive_resource_safe": 0}
        )
        self.assertFalse(unsafe["complete"])
        self.assertEqual(
            unsafe["incomplete_event_counts"]["unsafe_resource_configuration"],
            1,
        )
        informational = benchmark._candidate_lattice_completeness(
            {"protocol_restarts": 3, "productive_resource_safe": 1}
        )
        self.assertTrue(informational["complete"])
        self.assertEqual(
            informational["informational_event_counts"],
            {"protocol_restarts": 3},
        )

    def test_backend_runtime_is_part_of_worker_identity(self) -> None:
        base = {
            "qazmorph_version": "1",
            "software": {"bundle_sha256": "source"},
            "resource_dir": "/resource",
            "resource_manifest": {"bundle_id": "resource"},
            "resource_provenance": {"manifest_file": {"sha256": "one"}},
            "backend_runtime": {"executables": {"hfst-proc": "one"}},
            "neural_resources": None,
        }
        changed = {**base, "backend_runtime": {"executables": {"hfst-proc": "two"}}}
        self.assertNotEqual(
            benchmark._worker_provenance(base), benchmark._worker_provenance(changed)
        )

    def test_success_report_closes_analyzer_and_uses_post_close_diagnostics(self) -> None:
        class Analyzer:
            instance = None

            def __init__(self, *args: object, **kwargs: object) -> None:
                type(self).instance = self
                self.backend = _FakeBackend()
                self.guesser = _FakeGuesser(
                    {
                        "cache_hits": 0,
                        "cache_misses": 1,
                        "lookup_queries": 1,
                        "prefilter_skips": 0,
                        "timeouts": 0,
                        "failures": 0,
                        "cache_entries": 1,
                        "worker_starts": 1,
                        "cap_aborts": 0,
                        "idle_restarts": 0,
                        "protocol_restarts": 2,
                    }
                )
                self.closed = False

            def analyze(self, *args: object, **kwargs: object) -> object:
                return SimpleNamespace(
                    tokens=[SimpleNamespace(text="сөз", kind="word")]
                )

            def close(self) -> None:
                self.closed = True
                self.guesser._diagnostics["cap_aborts"] = 1

        resource_snapshot = {
            "resource_dir": "/remote/test-resource",
            "resource_version": "test-resource",
            "manifest": dict(_FakeBackend.manifest),
            "manifest_file": {"path": "/manifest", "bytes": 1, "sha256": "m"},
            "resource_artifacts": {"a": {"path": "/a", "bytes": 1, "sha256": "a"}},
            "backend_runtime": _FakeBackend.runtime_provenance(),
        }
        with mock.patch.object(
            benchmark, "_load_analyzer", return_value=(Analyzer, "test")
        ), mock.patch.object(
            benchmark, "_resource_provenance", return_value=resource_snapshot
        ):
            report = benchmark._worker_report_impl(_worker_args(), "сөз")
        assert Analyzer.instance is not None
        self.assertTrue(Analyzer.instance.closed)
        self.assertEqual(report["guesser_diagnostics"]["cap_aborts"], 1)
        self.assertEqual(report["guesser_diagnostics"]["protocol_restarts"], 2)
        self.assertEqual(
            report["candidate_lattice"]["informational_event_counts"],
            {"protocol_restarts": 2},
        )
        self.assertFalse(report["candidate_lattice"]["complete"])
        self.assertEqual(report["backend_runtime"], _FakeBackend.runtime_provenance())
        self.assertTrue(
            report["persistent_guesser_child"]["after_close"][
                "original_process_waited"
            ]
        )

    def test_exception_path_still_closes_analyzer(self) -> None:
        class Analyzer:
            instance = None

            def __init__(self, *args: object, **kwargs: object) -> None:
                type(self).instance = self
                self.backend = _FakeBackend()
                self.guesser = _FakeGuesser(
                    {
                        "timeouts": 0,
                        "failures": 0,
                        "cap_aborts": 0,
                    }
                )
                self.closed = False

            def analyze(self, *args: object, **kwargs: object) -> object:
                raise RuntimeError("deliberate analysis failure")

            def close(self) -> None:
                self.closed = True

        resource_snapshot = {
            "resource_dir": "/remote/test-resource",
            "resource_version": "test-resource",
            "manifest": dict(_FakeBackend.manifest),
            "manifest_file": {"path": "/manifest", "bytes": 1, "sha256": "m"},
            "resource_artifacts": {"a": {"path": "/a", "bytes": 1, "sha256": "a"}},
            "backend_runtime": _FakeBackend.runtime_provenance(),
        }
        with mock.patch.object(
            benchmark, "_load_analyzer", return_value=(Analyzer, "test")
        ), mock.patch.object(
            benchmark, "_resource_provenance", return_value=resource_snapshot
        ):
            with self.assertRaisesRegex(RuntimeError, "deliberate analysis failure"):
                benchmark._worker_report_impl(_worker_args(), "сөз")
        assert Analyzer.instance is not None
        self.assertTrue(Analyzer.instance.closed)

    def test_input_is_rehashed_after_workers_finish(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.txt"
            path.write_text("бастапқы", encoding="utf-8")
            args = benchmark.build_parser().parse_args(
                [str(path), "--mode", "lattice", "--cold-runs", "1", "--runs", "1"]
            )
            software = benchmark._software_provenance()

            def mutate(*args: object, **kwargs: object) -> dict[str, object]:
                path.write_text("өзгерген", encoding="utf-8")
                return _mode_result(software)

            with mock.patch.object(
                benchmark, "_benchmark_mode", side_effect=mutate
            ), mock.patch.object(
                benchmark,
                "_parent_resource_file_snapshot",
                side_effect=lambda value: benchmark._resource_static_snapshot(value),
            ):
                with self.assertRaisesRegex(benchmark.BenchmarkError, "input changed"):
                    benchmark.run(args)

    def test_fixlist_is_rehashed_after_workers_finish(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixlist = Path(directory) / "fixlist.jsonl"
            fixlist.write_text('{"surface":"сөз"}\n', encoding="utf-8")
            args = benchmark.build_parser().parse_args(
                [
                    "--text",
                    "сөз",
                    "--mode",
                    "lattice",
                    "--fixlist",
                    str(fixlist),
                    "--cold-runs",
                    "1",
                    "--runs",
                    "1",
                ]
            )
            software = benchmark._software_provenance()

            def mutate(*args: object, **kwargs: object) -> dict[str, object]:
                fixlist.write_text('{"surface":"басқа"}\n', encoding="utf-8")
                return _mode_result(software)

            with mock.patch.object(
                benchmark, "_benchmark_mode", side_effect=mutate
            ), mock.patch.object(
                benchmark,
                "_parent_resource_file_snapshot",
                side_effect=lambda value: benchmark._resource_static_snapshot(value),
            ):
                with self.assertRaisesRegex(benchmark.BenchmarkError, "fixlist changed"):
                    benchmark.run(args)

    def test_parent_source_is_rechecked_after_workers_finish(self) -> None:
        initial = {"files": {}, "bundle_sha256": "before"}
        final = {"files": {}, "bundle_sha256": "after"}
        args = benchmark.build_parser().parse_args(
            ["--text", "сөз", "--mode", "lattice", "--cold-runs", "1", "--runs", "1"]
        )
        with mock.patch.object(
            benchmark, "_software_provenance", side_effect=[initial, final]
        ), mock.patch.object(
            benchmark, "_benchmark_mode", return_value=_mode_result(initial)
        ), mock.patch.object(
            benchmark,
            "_parent_resource_file_snapshot",
            side_effect=lambda value: benchmark._resource_static_snapshot(value),
        ):
            with self.assertRaisesRegex(benchmark.BenchmarkError, "source changed"):
                benchmark.run(args)


if __name__ == "__main__":
    unittest.main()
