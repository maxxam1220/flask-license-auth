import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from ocr_worker import IsolatedOCR, OCRMemoryLimitError, _MemoryGuard, _MIB


class FakeProcess:
    instances = []

    def __init__(self, code=0):
        self.pid = 98765000 + len(self.instances)
        self.returncode = code
        self.killed = False
        self.waited = False
        self.instances.append(self)

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.waited = True
        if self.returncode is None:
            raise subprocess.TimeoutExpired("TEST ONLY", timeout)
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


class IsolatedOCRTests(unittest.TestCase):
    def setUp(self):
        FakeProcess.instances = []
        no_guard = patch.object(IsolatedOCR, "_memory_guard", return_value=None)
        no_guard.start(); self.addCleanup(no_guard.stop)
        def kill_group(pid, _signal):
            next(process for process in FakeProcess.instances if process.pid == pid).kill()
        safe_signal = patch("ocr_worker.os.killpg", side_effect=kill_group, create=True)
        safe_signal.start(); self.addCleanup(safe_signal.stop)

    def test_result_and_temporary_files_cleanup_without_secret_inheritance(self):
        observed = {}
        expected = {"lines": [{"id": 0, "text": "測試文字", "score": .99, "box": []}],
                    "engine": "TEST ONLY", "elapsed": .1}
        def launch(command, **kwargs):
            observed.update(command=command, **kwargs)
            output = Path(command[command.index("--output") + 1])
            observed["result_path"] = output
            self.assertTrue(output.parent.exists())
            output.write_text(json.dumps(expected, ensure_ascii=False), encoding="utf-8")
            return FakeProcess()
        with patch.dict(os.environ, {"LABELCHECK_DATABASE_URL": "private", "LABELCHECK_PASSWORD": "private",
                "LABELCHECK_SECRET": "private", "PGPASSWORD": "private", "OPENAI_API_KEY": "private",
                "RENDER_API_TOKEN": "private"}), patch("ocr_worker.subprocess.Popen", side_effect=launch):
            self.assertEqual(IsolatedOCR("models").recognize("a photo.jpg"), expected)
        for key in ("LABELCHECK_DATABASE_URL", "LABELCHECK_PASSWORD", "LABELCHECK_SECRET",
                    "PGPASSWORD", "OPENAI_API_KEY", "RENDER_API_TOKEN"):
            self.assertNotIn(key, observed["env"])
        self.assertFalse(observed["shell"])
        self.assertTrue(observed["close_fds"])
        self.assertEqual(observed["start_new_session"], os.name == "posix")
        self.assertEqual(observed["stdout"], subprocess.DEVNULL)
        self.assertEqual(observed["stderr"], subprocess.DEVNULL)
        self.assertEqual(observed["command"][2], str(Path("a photo.jpg").resolve()))
        self.assertEqual(observed["command"][4], str(Path("models").resolve()))
        self.assertFalse(observed["result_path"].parent.exists())
        self.assertTrue(FakeProcess.instances[0].waited)

    def test_timeout_kills_reaps_cleans_partial_output_and_releases_lock(self):
        folders = []
        def launch(command, **kwargs):
            output = Path(command[-1]); folders.append(output.parent)
            output.write_text("partial", encoding="utf-8")
            return FakeProcess(None)
        worker = IsolatedOCR("models", timeout=.1)
        with patch("ocr_worker.subprocess.Popen", side_effect=launch):
            for _ in range(2):
                with patch("ocr_worker.time.monotonic", side_effect=[0, 1]):
                    with self.assertRaisesRegex(RuntimeError, "exceeded"):
                        worker.recognize("photo.jpg")
        self.assertTrue(all(process.killed and process.waited for process in FakeProcess.instances))
        self.assertTrue(all(not folder.exists() for folder in folders))
        self.assertFalse(worker.lock.locked())

    def test_crash_never_returns_partial_result(self):
        paths = []
        def launch(command, **kwargs):
            output = Path(command[-1]); paths.append(output)
            output.write_text('{"lines":[]}', encoding="utf-8")
            return FakeProcess(-9)
        with patch("ocr_worker.subprocess.Popen", side_effect=launch):
            with self.assertRaisesRegex(RuntimeError, "code -9"):
                IsolatedOCR("models").recognize("photo.jpg")
        self.assertTrue(all(not path.parent.exists() for path in paths))

    def test_missing_or_invalid_worker_result_is_rejected_and_cleaned(self):
        for payload in (None, "not JSON", "[]", '{"lines":[]}', "x" * (4 * 1024 * 1024 + 1)):
            with self.subTest(payload_type=type(payload).__name__):
                paths = []
                def launch(command, **kwargs):
                    output = Path(command[-1]); paths.append(output)
                    if payload is not None:
                        output.write_text(payload, encoding="utf-8")
                    return FakeProcess()
                with patch("ocr_worker.subprocess.Popen", side_effect=launch):
                    with self.assertRaisesRegex(RuntimeError, "valid result"):
                        IsolatedOCR("models").recognize("photo.jpg")
                self.assertTrue(all(not path.parent.exists() for path in paths))

    def test_memory_rejection_kills_partial_result_and_next_job_can_succeed(self):
        paths = []
        def launch(command, **kwargs):
            output = Path(command[-1]); paths.append(output)
            output.write_text('{"lines":[],"engine":"TEST","elapsed":0.1}', encoding="utf-8")
            return FakeProcess(None if len(paths) == 1 else 0)
        guard = Mock()
        guard.observe.side_effect = [None, OCRMemoryLimitError("worker_budget", 361*_MIB, 360*_MIB)]
        worker = IsolatedOCR("models")
        with patch("ocr_worker.subprocess.Popen", side_effect=launch), patch.object(worker, "_memory_guard", return_value=guard):
            with self.assertRaises(OCRMemoryLimitError) as caught:
                worker.recognize("photo.jpg")
        self.assertEqual(caught.exception.kind, "worker_budget")
        self.assertEqual(caught.exception.observed_mb, 361)
        self.assertTrue(FakeProcess.instances[0].killed)
        self.assertTrue(FakeProcess.instances[0].waited)
        self.assertFalse(paths[0].parent.exists())
        self.assertFalse(worker.lock.locked())
        with patch("ocr_worker.subprocess.Popen", side_effect=launch):
            self.assertEqual(worker.recognize("next.jpg")["engine"], "TEST")

    def test_preexisting_pressure_never_starts_worker(self):
        guard = Mock()
        guard.observe.side_effect = OCRMemoryLimitError("service_budget", 417*_MIB, 416*_MIB)
        worker = IsolatedOCR("models")
        with patch.object(worker, "_memory_guard", return_value=guard), patch("ocr_worker.subprocess.Popen") as launch:
            with self.assertRaises(OCRMemoryLimitError):
                worker.recognize("photo.jpg")
        launch.assert_not_called()
        self.assertFalse(worker.lock.locked())

    def test_monitor_loss_stops_a_running_worker(self):
        guard = Mock()
        guard.observe.side_effect = [None, OCRMemoryLimitError("monitor_unavailable")]
        process = FakeProcess(None)
        with patch("ocr_worker.subprocess.Popen", return_value=process):
            with self.assertRaisesRegex(OCRMemoryLimitError, "monitor_unavailable"):
                IsolatedOCR("models")._run(["TEST ONLY"], guard)
        self.assertTrue(process.killed and process.waited)

    def test_allocators_are_bounded_without_overwriting_other_tunables(self):
        with patch("ocr_worker.sys.platform", "linux"), patch.dict(os.environ, {
            "GLIBC_TUNABLES": "glibc.malloc.check=3:glibc.malloc.arena_max=9:glibc.cpu.hwcaps=-AVX2"}):
            env = IsolatedOCR._environment()
        self.assertEqual(env["MALLOC_ARENA_MAX"], "1")
        self.assertEqual(env["MALLOC_TRIM_THRESHOLD_"], "131072")
        self.assertEqual(env["MALLOC_MMAP_THRESHOLD_"], "131072")
        self.assertIn("glibc.malloc.check=3", env["GLIBC_TUNABLES"])
        self.assertIn("glibc.cpu.hwcaps=-AVX2", env["GLIBC_TUNABLES"])
        self.assertNotIn("arena_max=9", env["GLIBC_TUNABLES"])
        self.assertEqual(env["GLIBC_TUNABLES"].count("arena_max="), 1)

    def test_unbounded_settings_are_rejected(self):
        for kwargs in ({"worker_memory_mb": 512}, {"reserve_memory_mb": 0}):
            with self.assertRaises(ValueError):
                IsolatedOCR("models", **kwargs)

    def test_exited_posix_leader_still_has_its_process_group_terminated(self):
        process = FakeProcess(0)
        with patch("ocr_worker.os.name", "posix"), patch("ocr_worker.signal.SIGKILL", 9, create=True), \
                patch("ocr_worker.os.killpg", create=True) as kill_group:
            IsolatedOCR._stop(process)
        kill_group.assert_called_once_with(process.pid, 9)
        self.assertEqual(process.returncode, 0)
        self.assertTrue(process.waited)


class MemoryGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.proc = self.root / "proc"
        (self.proc / "self").mkdir(parents=True)
        self.mount = self.root / "cgroup mount"
        self.mount.mkdir()

    def fixture(self, version=2, location="/", mount_root="/"):
        mount = str(self.mount).replace("\\", "/").replace(" ", "\\040")
        if version == 2:
            membership, suffix = f"0::{location}", "cgroup2 cgroup rw"
            limit_name, usage_name = "memory.max", "memory.current"
        else:
            membership, suffix = f"4:cpu,memory:{location}", "cgroup cgroup rw,memory"
            limit_name, usage_name = "memory.limit_in_bytes", "memory.usage_in_bytes"
        (self.proc / "self" / "cgroup").write_text(membership)
        (self.proc / "self" / "mountinfo").write_text(f"1 2 0:0 {mount_root} {mount} rw - {suffix}")
        (self.mount / limit_name).write_text(str(512*_MIB))
        (self.mount / usage_name).write_text(str(80*_MIB))
        return limit_name, usage_name

    def guard(self, required=True):
        return _MemoryGuard.discover(360*_MIB, 96*_MIB, self.proc, require_cgroup=required)

    def test_v2_and_v1_counters_and_reserved_service_budget(self):
        for version in (2, 1):
            with self.subTest(version=version):
                _, usage = self.fixture(version)
                guard = self.guard()
                guard.observe()
                (self.mount / usage).write_text(str(416*_MIB))
                with self.assertRaises(OCRMemoryLimitError) as caught:
                    guard.observe()
                self.assertEqual(caught.exception.kind, "service_budget")
                self.assertEqual(caught.exception.limit_mb, 416)

    def test_unlimited_leaf_still_monitors_finite_ancestor(self):
        limit, usage = self.fixture(location="/worker")
        leaf = self.mount / "worker"; leaf.mkdir()
        (leaf / limit).write_text("max")
        (leaf / usage).write_text(str(10*_MIB))
        guard = self.guard()
        self.assertEqual(guard.limits, [(self.mount / usage, 512*_MIB)])

    def test_namespace_mount_root_and_missing_current_fail_closed(self):
        _, usage = self.fixture(location="/", mount_root="/host/service")
        guard = self.guard()
        (self.mount / usage).unlink()
        with self.assertRaisesRegex(OCRMemoryLimitError, "monitor_unavailable"):
            guard.observe()

    def test_child_rss_and_diagnostic_file_cache_preserve_conservative_limit(self):
        _, usage = self.fixture()
        (self.mount / usage).write_text(str(300*_MIB))
        (self.mount / "memory.stat").write_text(f"anon {200*_MIB}\ninactive_file {100*_MIB}\n")
        child = self.proc / "123"; child.mkdir()
        (child / "status").write_text("Name:\tTEST\nVmRSS:\t368640 kB\n")
        guard = self.guard()
        with self.assertRaises(OCRMemoryLimitError) as caught:
            guard.observe(123)
        self.assertEqual(caught.exception.kind, "worker_budget")
        self.assertEqual(caught.exception.memory_guard["cgroups"][0]["working_set_peak_mb"], 200)
        (self.mount / usage).write_text(str(417*_MIB))
        with self.assertRaises(OCRMemoryLimitError) as caught:
            guard.observe()
        self.assertEqual(caught.exception.kind, "service_budget")

    def test_render_requires_cgroup_but_local_linux_retains_rss_guard(self):
        with self.assertRaises(OCRMemoryLimitError):
            self.guard()
        local = self.guard(required=False)
        self.assertEqual(local.limits, [])
        child = self.proc / "123"; child.mkdir()
        (child / "status").write_text("VmRSS:\t400000 kB\n")
        with self.assertRaises(OCRMemoryLimitError):
            local.observe(123)


class RealProcessCleanupTests(unittest.TestCase):
    def test_guard_kills_and_reaps_a_real_small_child_without_loading_ocr(self):
        real_popen = subprocess.Popen
        children = []
        def launch(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            children.append(process)
            return process
        guard = Mock()
        guard.observe.side_effect = [None, OCRMemoryLimitError("worker_budget", 361*_MIB, 360*_MIB)]
        with patch("ocr_worker.subprocess.Popen", side_effect=launch):
            with self.assertRaises(OCRMemoryLimitError):
                IsolatedOCR("models")._run([sys.executable, "-c", "import time; time.sleep(30)"], guard)
        self.assertIsNotNone(children[0].poll())


if __name__ == "__main__":
    unittest.main()
