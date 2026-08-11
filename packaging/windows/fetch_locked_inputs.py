#!/usr/bin/env python3
"""Download only the exact Windows runtime inputs bound by its source lock."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import os
from pathlib import Path
import sys
import urllib.request
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from write_platform_runtime_manifest import ManifestError, load_source_lock  # noqa: E402


class FetchError(RuntimeError):
    pass


def fetch(record: dict[str, object], destination: Path) -> tuple[str, int, str]:
    filename = str(record["filename"])
    expected_bytes = int(record["bytes"])
    expected_sha256 = str(record["sha256"])
    target = destination / filename
    temporary = destination / f".{filename}.part"
    if target.exists() or temporary.exists():
        raise FetchError(f"refusing to overwrite download path: {target}")
    request = urllib.request.Request(
        str(record["url"]),
        headers={"User-Agent": "KazStem/0.2.3 locked-release-builder"},
    )
    digest = hashlib.sha256()
    observed = 0
    try:
        with urllib.request.urlopen(request, timeout=120) as response, temporary.open(
            "xb"
        ) as output:
            final_url = urlsplit(response.url)
            if final_url.scheme != "https" or not final_url.netloc:
                raise FetchError(f"download redirected outside HTTPS: {filename}")
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                observed += len(block)
                if observed > expected_bytes:
                    raise FetchError(f"download exceeds locked size: {filename}")
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        observed_sha256 = digest.hexdigest()
        if (observed, observed_sha256) != (expected_bytes, expected_sha256):
            raise FetchError(
                f"download identity mismatch: {filename}: "
                f"{observed} bytes sha256={observed_sha256}"
            )
        os.replace(temporary, target)
        return filename, observed, observed_sha256
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--archives", required=True, type=Path)
    parser.add_argument("--sources", required=True, type=Path)
    args = parser.parse_args()

    lock = load_source_lock(args.lock.resolve(strict=True))
    outputs = {
        "archives": args.archives.resolve(),
        "corresponding_sources": args.sources.resolve(),
    }
    for path in outputs.values():
        path.mkdir(parents=True, exist_ok=False)
    tasks = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        for field, destination in outputs.items():
            for record in lock[field]:
                tasks.append(pool.submit(fetch, record, destination))
        results = sorted(future.result() for future in as_completed(tasks))
    for filename, size, digest in results:
        print(f"{digest}  {size:>10}  {filename}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FetchError, ManifestError, OSError) as error:
        raise SystemExit(f"error: {error}") from error
