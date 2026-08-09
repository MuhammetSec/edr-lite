"""Tests for process discovery, using a fake psutil so no real processes are touched."""
import os
import sys
import types
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def install_fake_psutil():
    """Register a stub psutil module and return it for test control."""
    fake = types.ModuleType("psutil")

    class NoSuchProcess(Exception):
        pass

    class AccessDenied(Exception):
        pass

    fake.NoSuchProcess = NoSuchProcess
    fake.AccessDenied = AccessDenied
    fake.processes = []
    fake.process_iter = lambda attrs=None: iter(list(fake.processes))
    sys.modules["psutil"] = fake
    return fake


fake_psutil = install_fake_psutil()

from monitor import ProcessMonitor  # noqa: E402


_DEFAULT = object()


def proc(pid, create_time, name="x", cmdline=_DEFAULT):
    return SimpleNamespace(
        info={
            "pid": pid,
            "name": name,
            "exe": f"/usr/bin/{name}",
            "cmdline": [name] if cmdline is _DEFAULT else cmdline,
            "create_time": create_time,
            "username": "tester",
        }
    )


class TestProcessMonitor(unittest.TestCase):
    def setUp(self):
        fake_psutil.processes = []
        self.monitor = ProcessMonitor()

    def test_reports_new_processes_once(self):
        fake_psutil.processes = [proc(100, 1.0), proc(101, 2.0)]
        self.assertEqual(len(self.monitor.scan()), 2)
        self.assertEqual(self.monitor.scan(), [])

    def test_recycled_pid_is_treated_as_a_new_process(self):
        """A PID reused by the OS must not be silently swallowed."""
        fake_psutil.processes = [proc(100, 1.0, name="old")]
        self.assertEqual(len(self.monitor.scan()), 1)

        # Same PID, different start time: a different process entirely.
        fake_psutil.processes = [proc(100, 9.0, name="new")]
        rediscovered = self.monitor.scan()
        self.assertEqual(len(rediscovered), 1)
        self.assertEqual(rediscovered[0]["name"], "new")

    def test_exited_processes_are_pruned(self):
        """The seen set tracks live processes, so it stays bounded."""
        fake_psutil.processes = [proc(i, float(i)) for i in range(50)]
        self.monitor.scan()
        self.assertEqual(len(self.monitor.seen), 50)

        fake_psutil.processes = [proc(0, 0.0)]
        self.monitor.scan()
        self.assertEqual(len(self.monitor.seen), 1)

    def test_cmdline_is_normalised_to_a_string(self):
        fake_psutil.processes = [proc(1, 1.0, cmdline=["bash", "-c", "echo hi"])]
        self.assertEqual(self.monitor.scan()[0]["cmdline"], "bash -c echo hi")

    def test_missing_cmdline_becomes_empty_string(self):
        fake_psutil.processes = [proc(1, 1.0, cmdline=None)]
        self.assertEqual(self.monitor.scan()[0]["cmdline"], "")


if __name__ == "__main__":
    unittest.main()
