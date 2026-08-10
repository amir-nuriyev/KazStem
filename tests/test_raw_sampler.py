from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "prepare_multidomain_sample.py"
SPEC = importlib.util.spec_from_file_location("qazmorph_test_raw_sampler", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
sampler = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sampler
SPEC.loader.exec_module(sampler)


class RawSamplerTests(unittest.TestCase):
    def test_dataset_access_is_refused_before_import_off_h100(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = argparse.Namespace(
                output=Path(temporary) / "sample.txt",
                rows=1,
                expected_host="arboghast",
                expected_sha256=None,
                expected_first_id=None,
                expected_last_id=None,
            )
            with patch.object(sampler.socket, "gethostname", return_value="macbook"):
                with self.assertRaisesRegex(sampler.SampleError, "refusing dataset access"):
                    sampler.run(args)

    def test_nonpositive_row_count_is_rejected_before_dataset_import(self) -> None:
        args = argparse.Namespace(
            output=Path("unused"),
            rows=0,
            expected_host="arboghast",
            expected_sha256=None,
            expected_first_id=None,
            expected_last_id=None,
        )
        with patch.object(sampler.socket, "gethostname", return_value="arboghast"):
            with self.assertRaisesRegex(sampler.SampleError, "rows must be positive"):
                sampler.run(args)


if __name__ == "__main__":
    unittest.main()
