from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGING_ROOT = PROJECT_ROOT / "packaging"
LINUX_TOOLS = PACKAGING_ROOT / "linux"
sys.path.insert(0, str(PACKAGING_ROOT))
sys.path.insert(0, str(LINUX_TOOLS))

from process_supervisor import run_bounded  # noqa: E402
import release_common as common  # noqa: E402
from tests.test_linux_release_tooling import fixture_seccomp_library  # noqa: E402


def record(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


@unittest.skipUnless(platform.system() == "Linux", "Linux seccomp contract")
class LinuxNetworkBoundaryTests(unittest.TestCase):
    def test_socket_io_uring_clone_untraced_and_clone3_are_denied(self) -> None:
        library_path = fixture_seccomp_library()
        if "libseccomp" not in library_path.name:
            self.skipTest("libseccomp.so.2 is unavailable")
        wrapper = LINUX_TOOLS / "run_no_network.py"
        library = ctypes.CDLL(str(library_path))
        library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
        library.seccomp_syscall_resolve_name.restype = ctypes.c_int
        numbers = {
            name: library.seccomp_syscall_resolve_name(name.encode("ascii"))
            for name in ("clone", "clone3", "io_uring_setup")
        }
        if any(number < 0 for number in numbers.values()):
            self.skipTest("host architecture lacks required hostile syscall probes")
        wrapper_record = record(wrapper)
        library_record = record(library_path)
        child = r"""
import ctypes, errno, socket, sys
try:
    socket.socket()
except PermissionError as error:
    assert error.errno == errno.EPERM
else:
    raise SystemExit("socket unexpectedly succeeded")
libc = ctypes.CDLL(None, use_errno=True)
clone, clone3, io_uring_setup = map(int, sys.argv[1:])
assert libc.syscall(io_uring_setup, 1, 0) == -1 and ctypes.get_errno() == errno.EPERM
assert libc.syscall(clone, 0x00800000 | 17, 0, 0, 0, 0) == -1 and ctypes.get_errno() == errno.EPERM
assert libc.syscall(clone3, 0, 0) == -1 and ctypes.get_errno() == errno.ENOSYS
"""
        command = [
            sys.executable,
            str(wrapper),
            "--library",
            str(library_path),
            "--library-bytes",
            str(library_record["bytes"]),
            "--library-sha256",
            str(library_record["sha256"]),
            "--wrapper-bytes",
            str(wrapper_record["bytes"]),
            "--wrapper-sha256",
            str(wrapper_record["sha256"]),
            "--receipt-fd",
            "{supervisor_fd:boundary}",
        ]
        for name in common.NETWORK_BOUNDARY_DENIED_SYSCALLS:
            command.extend(["--deny-syscall", name])
        command.extend(
            [
                "--",
                sys.executable,
                "-c",
                child,
                str(numbers["clone"]),
                str(numbers["clone3"]),
                str(numbers["io_uring_setup"]),
            ]
        )
        with tempfile.TemporaryDirectory() as temporary:
            result = run_bounded(
                command,
                cwd=Path(temporary),
                environment=os.environ.copy(),
                timeout=10,
                max_stdout=4096,
                max_stderr=4096,
                extra_stream_caps={"boundary": 64 * 1024},
            )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        receipt = json.loads(result.extra_streams["boundary"])
        self.assertTrue(receipt["clone_untraced_denied"])
        self.assertEqual(receipt["resolved_syscalls"], common.NETWORK_BOUNDARY_DENIED_SYSCALLS)


if __name__ == "__main__":
    unittest.main()
