from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, filename: str):
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


evaluation = load_script("qazmorph_evaluation_hardening_test", "evaluate_ud.py")
benchmark = load_script("qazmorph_benchmark_hardening_test", "benchmark.py")


class _Backend:
    def __init__(self, root: Path, manifest: dict[str, object]) -> None:
        self.resource_dir = root
        self.resource_version = "test-resource"
        self.manifest = manifest

    @staticmethod
    def runtime_provenance() -> dict[str, object]:
        return {
            "official": True,
            "verified": True,
            "non_official_reasons": [],
            "executables": {"hfst-proc": {"sha256": "runtime"}},
        }


def resource_fixture(root: Path) -> SimpleNamespace:
    artifact = root / "analyzer.bin"
    artifact.write_bytes(b"analyzer")
    manifest = {"bundle_id": "b" * 64, "files": {artifact.name: {}}}
    (root / "manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    return SimpleNamespace(backend=_Backend(root, manifest))


def neural_fixture(root: Path) -> tuple[Path, Path, str, str]:
    project = root / "project"
    scripts = project / "scripts"
    model = root / "model"
    prefix = root / "prefix"
    scripts.mkdir(parents=True)
    model.mkdir()
    prefix.mkdir()
    (scripts / "write_neural_manifest.py").write_text("# verifier\n", encoding="utf-8")
    (scripts / "neural_assets.lock.json").write_text("{}\n", encoding="utf-8")
    model_bundle = "1" * 64
    environment_bundle = "2" * 64
    (model / "manifest.json").write_text(
        json.dumps({"bundle_id": model_bundle}), encoding="utf-8"
    )
    environment = prefix / "qazmorph-neural-environment.json"
    environment.write_text(
        json.dumps(
            {
                "bundle_id": environment_bundle,
                "model_bundle_id": model_bundle,
                "schema": "qazmorph-neural-environment-manifest-v2",
                "version": "test",
            }
        ),
        encoding="utf-8",
    )
    return project, model, model_bundle, environment_bundle


class ResourceProvenanceTests(unittest.TestCase):
    def test_evaluator_hashes_both_manifest_and_every_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            analyzer = resource_fixture(root)
            before = evaluation._resource_provenance(analyzer)
            (root / "analyzer.bin").write_bytes(b"changed!")
            after = evaluation._resource_provenance(analyzer)

        self.assertEqual(before["manifest_file"], after["manifest_file"])
        self.assertNotEqual(before["resource_artifacts"], after["resource_artifacts"])
        with self.assertRaisesRegex(
            evaluation.EvaluationError, "different full resource provenance"
        ):
            evaluation._require_matching_resource_provenance(
                before, after, stage="test"
            )

    def test_benchmark_parent_independently_rehashes_worker_resource(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            analyzer = resource_fixture(root)
            worker = benchmark._resource_provenance(analyzer)
            parent = benchmark._parent_resource_file_snapshot(worker)
            self.assertEqual(parent, benchmark._resource_static_snapshot(worker))

            (root / "analyzer.bin").write_bytes(b"changed!")
            changed = benchmark._parent_resource_file_snapshot(worker)
            self.assertNotEqual(changed, parent)


class NeuralVerificationTests(unittest.TestCase):
    def test_checked_in_verifier_binds_selected_model_and_environment(self) -> None:
        for module in (evaluation, benchmark):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as directory:
                project, model, model_bundle, environment_bundle = neural_fixture(
                    Path(directory)
                )
                environment = (
                    Path(directory) / "prefix" / "qazmorph-neural-environment.json"
                )
                completed = SimpleNamespace(
                    returncode=0, stdout=environment_bundle + "\n", stderr=""
                )
                with mock.patch.object(module, "PROJECT_ROOT", project), mock.patch.object(
                    module.subprocess, "run", return_value=completed
                ) as invoked:
                    rendered = module._neural_manifest_verification(model, environment)

                self.assertTrue(rendered["verified"])
                self.assertEqual(rendered["selected_model_bundle_id"], model_bundle)
                self.assertEqual(rendered["environment_bundle_id"], environment_bundle)
                self.assertIn("--verify-environment-manifest", invoked.call_args.args[0])

    def test_verifier_failure_is_nonfatal_but_nonofficial(self) -> None:
        for module in (evaluation, benchmark):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as directory:
                project, model, _model_bundle, _environment_bundle = neural_fixture(
                    Path(directory)
                )
                environment = (
                    Path(directory) / "prefix" / "qazmorph-neural-environment.json"
                )
                completed = SimpleNamespace(
                    returncode=9, stdout="", stderr="deliberate mismatch"
                )
                with mock.patch.object(module, "PROJECT_ROOT", project), mock.patch.object(
                    module.subprocess, "run", return_value=completed
                ):
                    rendered = module._neural_manifest_verification(model, environment)

                self.assertFalse(rendered["verified"])
                self.assertTrue(
                    any("deliberate mismatch" in reason for reason in rendered["reasons"])
                )

    def test_device_verification_requires_pipeline_and_every_processor_to_agree(self) -> None:
        for module in (evaluation, benchmark):
            with self.subTest(module=module.__name__):
                valid = module._neural_device_verification(
                    requested_device="gpu",
                    pipeline_device="cuda:0",
                    processor_model_devices={
                        "tokenize": ["cuda:0"],
                        "pos": ["cuda:0"],
                    },
                    cuda_available=True,
                )
                mismatch = module._neural_device_verification(
                    requested_device="cpu",
                    pipeline_device="cuda:0",
                    processor_model_devices={"pos": ["cuda:0"]},
                    cuda_available=True,
                )
                unknown = module._neural_device_verification(
                    requested_device="auto",
                    pipeline_device="cpu",
                    processor_model_devices={"pos": None},
                    cuda_available=False,
                )
                mixed_unknown = module._neural_device_verification(
                    requested_device="gpu",
                    pipeline_device="cuda:0",
                    processor_model_devices={"pos": ["cuda:0", "meta"]},
                    processor_device_status={"pos": "model_parameters_observed"},
                    cuda_available=True,
                )
                incomplete = module._neural_device_verification(
                    requested_device="gpu",
                    pipeline_device="cuda:0",
                    processor_model_devices={"pos": ["cuda:0"]},
                    processor_device_status={"pos": "unresolved_model_device"},
                    cuda_available=True,
                )
                self.assertTrue(valid["verified"])
                self.assertFalse(mismatch["verified"])
                self.assertFalse(unknown["verified"])
                self.assertFalse(mixed_unknown["verified"])
                self.assertFalse(incomplete["verified"])

    def test_neural_failure_propagates_to_evaluator_and_benchmark_validity(self) -> None:
        neural = {
            "verification": {
                "verified": False,
                "reasons": ["manifest mismatch"],
                "selected_model_bundle_id": "1" * 64,
                "manifest": {"verified": False},
                "device": {"verified": True},
            }
        }
        evaluator = evaluation._apply_neural_validity(
            {
                "official_runtime": True,
                "valid_for_official_result_claims": True,
                "non_official_reasons": [],
            },
            neural,
        )
        performance = benchmark._runtime_validity(
            {"official": True, "non_official_reasons": []}, neural
        )
        self.assertFalse(evaluator["valid_for_official_result_claims"])
        self.assertFalse(performance["valid_for_official_performance_claims"])


class BenchmarkAggregateValidityTests(unittest.TestCase):
    def test_invalid_neural_mode_makes_aggregate_performance_nonofficial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            analyzer = resource_fixture(root)
            resource = benchmark._resource_provenance(analyzer)
            software = benchmark._software_provenance()
            neural = {
                "model_dir": str(root),
                "verification": {
                    "verified": False,
                    "reasons": ["custom model is not lock-verified"],
                    "selected_model_bundle_id": None,
                    "manifest": {"verified": False},
                    "device": {"verified": True},
                },
            }
            mode_result = {
                "qazmorph_version": "test",
                "software": software,
                "resource_dir": resource["resource_dir"],
                "resource_manifest": resource["manifest"],
                "resource_provenance": resource,
                "backend_runtime": resource["backend_runtime"],
                "runtime_validity": benchmark._runtime_validity(
                    resource["backend_runtime"], neural
                ),
                "neural_resources": neural,
            }
            args = benchmark.build_parser().parse_args(
                ["--text", "сөз", "--mode", "neural", "--cold-runs", "1", "--runs", "1"]
            )
            with mock.patch.object(
                benchmark, "_benchmark_mode", return_value=mode_result
            ), mock.patch.object(
                benchmark,
                "_neural_resource_provenance",
                side_effect=lambda _model, snapshot: snapshot,
            ):
                report = benchmark.run(args)

        self.assertFalse(
            report["integrity"]["valid_for_official_performance_claims"]
        )
        self.assertTrue(
            any(
                "custom model" in reason
                for reason in report["integrity"]["non_official_reasons"]
            )
        )


if __name__ == "__main__":
    unittest.main()
