from __future__ import annotations

import os
from pathlib import Path
import platform
import sys
import tempfile
import time
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "packaging"))

from process_supervisor import SupervisionError, run_bounded  # noqa: E402


class ProcessSupervisorTests(unittest.TestCase):
    def _run(self, root: Path, code: str, **overrides: object):
        arguments = {
            "cwd": root,
            "environment": os.environ.copy(),
            "timeout": 3,
            "max_stdout": 1024,
            "max_stderr": 1024,
        }
        arguments.update(overrides)
        return run_bounded([sys.executable, "-c", code], **arguments)

    def test_bounds_streams_without_limiting_work_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self._run(
                root,
                "from pathlib import Path; Path('large').write_bytes(b'x' * 2_000_000); print('ok')",
            )
            self.assertEqual(result.stdout, b"ok\n")
            self.assertEqual((root / "large").stat().st_size, 2_000_000)
            if platform.system() == "Linux" and Path(
                f"/run/user/{os.getuid()}/bus"
            ).exists():
                self.assertEqual(
                    result.containment,
                    "linux-systemd-user-slice-cgroup-v2+prctl-subreaper-proc-starttime-pidfd",
                )
                self.assertEqual(result.cgroup_tasks_max, 4097)
                self.assertTrue(result.cgroup_kill_written)
                self.assertTrue(result.cgroup_populated_zero)
            with self.assertRaisesRegex(SupervisionError, "stdout.*capture cap"):
                self._run(root, "import os; os.write(1, b'x' * 2048)")

    def test_timeout_and_inherited_pipe_descendant_are_cleaned_quickly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            started = time.monotonic()
            with self.assertRaisesRegex(SupervisionError, "timeout"):
                self._run(root, "import time; time.sleep(10)", timeout=0.1)
            self.assertLess(time.monotonic() - started, 2)

    def test_dedicated_extra_stream_is_concurrently_capped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = (
                "import sys; "
                "output=open(sys.argv[1],'wb',buffering=0); "
                "output.write(b'trace-data'); output.close()"
            )
            result = run_bounded(
                [sys.executable, "-c", code, "{supervisor_fd:trace}"],
                cwd=root,
                environment=os.environ.copy(),
                timeout=3,
                max_stdout=1024,
                max_stderr=1024,
                extra_stream_caps={"trace": 1024},
            )
            self.assertEqual(result.extra_streams, {"trace": b"trace-data"})
            flood = code.replace("b'trace-data'", "b'x' * 2048")
            with self.assertRaisesRegex(SupervisionError, "extra:trace.*capture cap"):
                run_bounded(
                    [sys.executable, "-c", flood, "{supervisor_fd:trace}"],
                    cwd=root,
                    environment=os.environ.copy(),
                    timeout=3,
                    max_stdout=1024,
                    max_stderr=1024,
                    extra_stream_caps={"trace": 1024},
                )
            started = time.monotonic()
            with self.assertRaisesRegex(SupervisionError, "descendant"):
                self._run(
                    root,
                    "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)'])",
                )
            self.assertLess(time.monotonic() - started, 2)

    @unittest.skipUnless(platform.system() == "Linux", "Linux subreaper contract")
    def test_setsid_escape_is_killed_and_reaped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pid_path = root / "escaped.pid"
            child = (
                "import os,time; "
                f"open({str(pid_path)!r},'w').write(str(os.getpid())); "
                "time.sleep(30)"
            )
            parent = (
                "import os,subprocess,sys,time\n"
                "subprocess.Popen([sys.executable,'-c',"
                + repr(child)
                + "],start_new_session=True,stdin=subprocess.DEVNULL,"
                "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)\n"
                f"deadline=time.monotonic()+1\ntarget={str(pid_path)!r}\n"
                "while not os.path.exists(target) and time.monotonic()<deadline:\n"
                " time.sleep(0.01)\n"
            )
            with self.assertRaisesRegex(SupervisionError, "descendant"):
                self._run(root, parent)
            pid = int(pid_path.read_text(encoding="ascii"))
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    @unittest.skipUnless(platform.system() == "Linux", "Linux subreaper contract")
    def test_fork_cap_failure_cleans_every_observed_detached_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pid_path = root / "forks.pid"
            child = "import time; time.sleep(30)"
            parent = (
                "import os,subprocess,sys,time\n"
                f"target={str(pid_path)!r}\n"
                "for _index in range(24):\n"
                " p=subprocess.Popen([sys.executable,'-c',"
                + repr(child)
                + "],start_new_session=True,stdin=subprocess.DEVNULL,"
                "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)\n"
                " with open(target,'a',encoding='ascii') as output:\n"
                "  output.write(str(p.pid)+'\\n'); output.flush(); os.fsync(output.fileno())\n"
                " time.sleep(0.003)\n"
                "time.sleep(30)\n"
            )
            with self.assertRaisesRegex(
                SupervisionError, "fork inventory cap|descendant"
            ):
                self._run(root, parent, fork_cap=4)
            pids = [
                int(value)
                for value in pid_path.read_text(encoding="ascii").splitlines()
            ]
            # The systemd slice counts its worker and direct child, so the
            # kernel pids.max gate may stop this fixture before the userspace
            # cumulative fork counter reaches four detached children.
            self.assertGreaterEqual(len(pids), 1)
            self.assertLessEqual(len(pids), 3)
            for pid in pids:
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)

    @unittest.skipUnless(platform.system() == "Linux", "Linux cgroup contract")
    def test_continuous_fork_relay_is_kernel_bounded_and_leaves_no_survivor(self) -> None:
        if not Path(f"/run/user/{os.getuid()}/bus").exists():
            self.skipTest("systemd user manager unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identities = root / "relay-identities"
            relay = (
                "import os,time\n"
                "os.setsid()\n"
                f"target={str(identities)!r}\n"
                "deadline=time.monotonic()+10\n"
                "while time.monotonic()<deadline:\n"
                " try:\n"
                "  child=os.fork()\n"
                " except OSError:\n"
                "  time.sleep(0.001); continue\n"
                " if child==0:\n"
                "  value=open('/proc/self/stat').read(); start=value[value.rfind(')')+2:].split()[19]\n"
                "  with open(target,'a') as output: output.write(f'{os.getpid()} {start}\\n')\n"
                "  time.sleep(0.01); os._exit(0)\n"
                " os.waitpid(child,0)\n"
            )
            parent = (
                "import os,subprocess,sys,time\n"
                "subprocess.Popen([sys.executable,'-c',"
                + repr(relay)
                + "],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
                "stderr=subprocess.DEVNULL,close_fds=True)\n"
                "time.sleep(1)\n"
            )
            started = time.monotonic()
            with self.assertRaisesRegex(
                SupervisionError, "fork inventory cap|descendant|cgroup"
            ):
                self._run(root, parent, fork_cap=8, timeout=3)
            self.assertLess(time.monotonic() - started, 6)
            for line in identities.read_text(encoding="ascii").splitlines():
                raw_pid, raw_start = line.split()
                stat_path = Path(f"/proc/{raw_pid}/stat")
                if not stat_path.exists():
                    continue
                value = stat_path.read_text(encoding="ascii")
                current_start = value[value.rfind(")") + 2 :].split()[19]
                self.assertNotEqual(current_start, raw_start)


if __name__ == "__main__":
    unittest.main()
