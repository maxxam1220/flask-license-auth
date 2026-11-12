import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from ocr_worker import IsolatedOCR, OCRMemoryLimitError, _MemoryGuard, _MIB, _read_model_diagnostics


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
        cleanup = patch("ocr_worker.release_unused_memory", return_value={"status": "test_cleanup"})
        self.cleanup = cleanup.start(); self.addCleanup(cleanup.stop)
        cache = patch("ocr_worker.advise_model_cache", return_value={"status":"test_cache"})
        self.cache = cache.start(); self.addCleanup(cache.stop)
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
            result = IsolatedOCR("models").recognize("a photo.jpg")
            self.assertEqual({key: value for key, value in result.items() if key != "recovery"}, expected)
            self.assertEqual(result["recovery"], {"attempts": 1, "automatic_retry": False,
                "reason": "", "cleanups": [{"status": "test_cleanup"}],
                "model_cache": [{"stage":"before_attempt", "attempt":1, "status":"test_cache"},
                                {"stage":"after_attempt", "attempt":1, "status":"test_cache"}],
                "model_loading":[{"attempt":1, "status":"unavailable"}]})
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
                with patch("ocr_worker.time.monotonic", side_effect=[0, 0, 0, 1]):
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
        self.assertEqual(caught.exception.recovery["attempts"], 1)
        self.assertFalse(caught.exception.recovery["automatic_retry"])
        self.assertFalse(paths[0].parent.exists())
        self.assertFalse(worker.lock.locked())
        with patch("ocr_worker.subprocess.Popen", side_effect=launch):
            self.assertEqual(worker.recognize("next.jpg")["engine"], "TEST")

    def test_preexisting_pressure_never_starts_worker(self):
        guard = Mock()
        guard.observe.side_effect = OCRMemoryLimitError("service_budget", 417*_MIB, 416*_MIB)
        worker = IsolatedOCR("models")
        with patch.object(worker, "_memory_guard", return_value=guard), patch("ocr_worker.subprocess.Popen") as launch:
            with self.assertRaises(OCRMemoryLimitError) as caught:
                worker.recognize("photo.jpg")
        launch.assert_not_called()
        self.assertFalse(worker.lock.locked())
        self.assertEqual(guard.observe.call_count, 2)
        self.assertEqual(self.cleanup.call_count, 2)
        self.assertEqual(caught.exception.recovery["attempts"], 2)
        self.assertTrue(caught.exception.recovery["automatic_retry"])

    def test_service_pressure_reaps_worker_before_cleanup_and_retries_original_once(self):
        commands, processes, cleanup_states, cache_states = [], [], [], []
        first_guard, retry_guard = Mock(), Mock()
        first_guard.observe.side_effect = [None, OCRMemoryLimitError("service_budget", 417*_MIB, 416*_MIB)]
        retry_guard.metadata.return_value = {"worker_rss_peak_mb": 270}
        def cleanup():
            cleanup_states.append([(p.killed, p.waited) for p in processes])
            return {"status": "test_cleanup"}
        self.cleanup.side_effect = cleanup
        def cache(_directory):
            cache_states.append([(p.killed, p.waited) for p in processes])
            return {"status":"test_cache"}
        self.cache.side_effect = cache
        def launch(command, **kwargs):
            commands.append(command)
            first = len(commands) == 1
            Path(command[-1]).write_text(json.dumps({"lines": [], "engine": "FIRST" if first else "SECOND", "elapsed": .1}))
            Path(command[command.index("--diagnostics")+1]).write_text(json.dumps({"stage":"before_rec_load" if first else "after_inference", "last_advice":{"status":"ok"}}))
            process = FakeProcess(None if first else 0)
            processes.append(process)
            return process
        worker = IsolatedOCR("models")
        with patch.object(worker, "_memory_guard", side_effect=[first_guard, retry_guard]), \
                patch("ocr_worker.subprocess.Popen", side_effect=launch):
            result = worker.recognize("same original photo.jpg")
        self.assertEqual(result["engine"], "SECOND")
        self.assertEqual(cleanup_states, [[], [(True, True)]])
        self.assertEqual(cache_states, [[], [(True, True)], [(True, True)], [(True, True), (os.name == "posix", True)]])
        self.assertEqual(commands[0][:-1], commands[1][:-1])
        self.assertNotEqual(commands[0][-1], commands[1][-1])
        self.assertEqual(result["recovery"]["attempts"], 2)
        self.assertTrue(result["recovery"]["automatic_retry"])
        self.assertEqual(result["recovery"]["reason"], "service_budget")
        self.assertEqual([item["stage"] for item in result["recovery"]["model_loading"]],["before_rec_load","after_inference"])
        self.assertTrue(all(not Path(command[-1]).parent.exists() for command in commands))

    def test_cache_advice_does_not_extend_deadline_or_start_expired_attempt(self):
        now = [10.]
        def cache(_directory):
            now[0] = 12.
            return {"status":"test_cache"}
        self.cache.side_effect = cache
        worker = IsolatedOCR("models", timeout=1)
        with patch("ocr_worker.time.monotonic", side_effect=lambda: now[0]), patch.object(worker, "_run") as run:
            with self.assertRaisesRegex(RuntimeError, "exceeded"):
                worker.recognize("photo.jpg")
        run.assert_not_called()

    def test_retry_cannot_reuse_first_attempts_complete_json(self):
        calls = []
        def run(command, guard, deadline=None):
            calls.append(command)
            if len(calls) == 1:
                Path(command[-1]).write_text('{"lines":[],"engine":"DO NOT ACCEPT","elapsed":0.1}')
                Path(command[command.index("--diagnostics")+1]).write_text('{"stage":"before_rec_load"}')
                raise OCRMemoryLimitError("service_budget", 417*_MIB, 416*_MIB)
            return 0  # Retry exits without its own result.
        worker = IsolatedOCR("models")
        with patch.object(worker, "_run", side_effect=run):
            with self.assertRaisesRegex(RuntimeError, "valid result") as caught:
                worker.recognize("photo.jpg")
        self.assertEqual(len(calls), 2)
        self.assertEqual(caught.exception.recovery["attempts"], 2)
        self.assertEqual(caught.exception.recovery["model_loading"][1],{"attempt":2,"status":"unavailable"})
        self.assertTrue(all(not Path(command[-1]).parent.exists() for command in calls))

    def test_model_diagnostics_are_bounded_and_optional(self):
        with TemporaryDirectory() as folder:
            path=Path(folder)/"diagnostics.json"
            for payload in (None,"x"*8193,"not JSON","[]",'{"stage":3}'):
                if payload is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_text(payload)
                self.assertEqual(_read_model_diagnostics(path),{"status":"unavailable"})
            path.write_text('{"stage":"before_rec_load","last_advice":{"status":"ok"}}')
            self.assertEqual(_read_model_diagnostics(path),{"stage":"before_rec_load","last_advice":{"status":"ok"}})

    def test_worker_budget_and_unavailable_monitor_are_not_retried(self):
        for kind in ("worker_budget", "monitor_unavailable"):
            with self.subTest(kind=kind):
                worker = IsolatedOCR("models")
                with patch.object(worker, "_run", side_effect=OCRMemoryLimitError(kind)) as run:
                    with self.assertRaises(OCRMemoryLimitError) as caught:
                        worker.recognize("photo.jpg")
                self.assertEqual(run.call_count, 1)
                self.assertEqual(caught.exception.recovery["attempts"], 1)
                self.assertFalse(caught.exception.recovery["automatic_retry"])

    def test_retry_uses_the_original_total_timeout_deadline(self):
        now, deadlines = [10.], []
        def run(command, guard, deadline=None):
            deadlines.append(deadline)
            if len(deadlines) == 1:
                now[0] = 10.8
                raise OCRMemoryLimitError("service_budget")
            Path(command[-1]).write_text('{"lines":[],"engine":"TEST","elapsed":0.1}')
            return 0
        worker = IsolatedOCR("models", timeout=1)
        with patch("ocr_worker.time.monotonic", side_effect=lambda: now[0]), patch.object(worker, "_run", side_effect=run):
            result = worker.recognize("photo.jpg")
        self.assertEqual(deadlines, [11., 11.])
        self.assertEqual(result["recovery"]["attempts"], 2)

    def test_cleanup_does_not_extend_timeout_or_launch_an_expired_retry(self):
        now, cleanups = [10.], []
        def cleanup():
            cleanups.append(True)
            if len(cleanups) == 2:
                now[0] = 12.
            return {"status": "test_cleanup"}
        self.cleanup.side_effect = cleanup
        worker = IsolatedOCR("models", timeout=1)
        with patch("ocr_worker.time.monotonic", side_effect=lambda: now[0]), \
                patch.object(worker, "_run", side_effect=OCRMemoryLimitError("service_budget")) as run:
            with self.assertRaisesRegex(RuntimeError, "exceeded") as caught:
                worker.recognize("photo.jpg")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(caught.exception.recovery["attempts"], 2)
        self.assertTrue(caught.exception.recovery["automatic_retry"])

    def test_monitor_loss_stops_a_running_worker(self):
        guard = Mock()
        guard.observe.side_effect = [None, OCRMemoryLimitError("monitor_unavailable")]
        process = FakeProcess(None)
        with patch("ocr_worker.subprocess.Popen", return_value=process):
            with self.assertRaisesRegex(OCRMemoryLimitError, "monitor_unavailable"):
                IsolatedOCR("models")._run(["TEST ONLY"], guard)
        self.assertTrue(process.killed and process.waited)

    def test_vmrss_exit_race_waits_briefly_and_accepts_only_complete_result(self):
        for reason in ("worker_status_missing", "worker_rss_missing"):
            with self.subTest(reason=reason):
                guard = Mock()
                guard.observe.side_effect = [None, OCRMemoryLimitError("monitor_unavailable", reason=reason)]
                guard.metadata.return_value = {"worker_rss_peak_mb": 200}
                process = FakeProcess(None)
                timeouts = []
                def finish(timeout=None):
                    timeouts.append(timeout)
                    process.returncode = 0
                    process.waited = True
                    return 0
                process.wait = finish
                def launch(command, **kwargs):
                    Path(command[-1]).write_text('{"lines":[],"engine":"TEST","elapsed":0.1}', encoding="utf-8")
                    return process
                worker = IsolatedOCR("models")
                with patch.object(worker, "_memory_guard", return_value=guard), \
                        patch("ocr_worker.subprocess.Popen", side_effect=launch):
                    result = worker.recognize("photo.jpg")
                self.assertEqual(result["engine"], "TEST")
                self.assertEqual(timeouts[0], .05)

    def test_missing_vmrss_that_does_not_exit_still_fails_closed(self):
        guard = Mock()
        guard.observe.side_effect = [None, OCRMemoryLimitError("monitor_unavailable", reason="worker_rss_missing")]
        process = FakeProcess(None)
        with patch("ocr_worker.subprocess.Popen", return_value=process):
            with self.assertRaises(OCRMemoryLimitError) as caught:
                IsolatedOCR("models")._run(["TEST ONLY"], guard)
        self.assertEqual(caught.exception.reason, "worker_rss_missing")
        self.assertTrue(process.killed and process.waited)

    def test_cgroup_read_error_never_gets_exit_grace(self):
        guard = Mock()
        guard.observe.side_effect = [None, OCRMemoryLimitError("monitor_unavailable", reason="cgroup_usage_read")]
        process = FakeProcess(None)
        original_wait = process.wait
        process.wait = Mock(side_effect=original_wait)
        with patch("ocr_worker.subprocess.Popen", return_value=process):
            with self.assertRaises(OCRMemoryLimitError):
                IsolatedOCR("models")._run(["TEST ONLY"], guard)
        self.assertTrue(process.killed)
        self.assertEqual(process.wait.call_args_list[0].kwargs["timeout"], 5)

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
        for kwargs in ({"worker_memory_mb": 1281}, {"reserve_memory_mb": 0}, {"worker_memory_mb": True}):
            with self.assertRaises(ValueError):
                IsolatedOCR("models", **kwargs)


class RuntimeMemoryTests(unittest.TestCase):
    def setUp(self):
        environment=patch.dict(os.environ,{"LABELCHECK_OCR_WORKER_MB":"", "LABELCHECK_OCR_RESERVE_MB":""})
        environment.start();self.addCleanup(environment.stop)

    @staticmethod
    def guard(*capacities):
        return _MemoryGuard([(Path(f"unused-{i}"),size*_MIB) for i,size in enumerate(capacities)],360*_MIB,96*_MIB)

    def test_auto_budget_follows_smallest_ancestor_and_refreshes_each_attempt(self):
        large=self.guard(2048,4096)
        smaller=self.guard(2048,512)
        with patch("ocr_worker.sys.platform","linux"), \
             patch.object(_MemoryGuard,"discover",side_effect=[large,smaller]) as discover:
            worker=IsolatedOCR("models")
            first=worker._memory_guard(); second=worker._memory_guard()
        self.assertEqual((first.worker_limit,first.reserve),(1280*_MIB,256*_MIB))
        self.assertEqual((second.worker_limit,second.reserve),(360*_MIB,96*_MIB))
        self.assertEqual(len(second.limits),2)  # No ancestor usage protection is discarded.
        self.assertEqual(discover.call_count,2)

    def test_environment_may_tighten_but_not_expand_safe_budget(self):
        with patch("ocr_worker.sys.platform","linux"), \
             patch.object(_MemoryGuard,"discover",side_effect=lambda *a,**k:self.guard(2048)), \
             patch.dict(os.environ,{"LABELCHECK_OCR_WORKER_MB":"768", "LABELCHECK_OCR_RESERVE_MB":"320"}):
            guard=IsolatedOCR("models")._memory_guard()
        self.assertEqual((guard.worker_limit,guard.reserve),(768*_MIB,320*_MIB))
        with patch("ocr_worker.sys.platform","linux"), \
             patch.object(_MemoryGuard,"discover",return_value=self.guard(512)), \
             patch.dict(os.environ,{"LABELCHECK_OCR_WORKER_MB":"768"}), \
             self.assertRaises(OCRMemoryLimitError) as caught:
            IsolatedOCR("models")._memory_guard()
        self.assertEqual(caught.exception.reason,"unsafe_memory_configuration")

    def test_detector_argument_uses_each_actual_worker_budget(self):
        for capacity,expected in ((512,"1280"),(2048,"1600")):
            commands=[]
            def run(command,guard,deadline=None):
                commands.append(command)
                Path(command[-1]).write_text('{"lines":[],"engine":"TEST","elapsed":0.1}',encoding="utf-8")
                return 0
            with self.subTest(capacity=capacity), patch("ocr_worker.sys.platform","linux"), \
                 patch.object(_MemoryGuard,"discover",return_value=self.guard(capacity)), \
                 patch.object(IsolatedOCR,"_run",side_effect=run), \
                 patch("ocr_worker.release_unused_memory",return_value={"status":"ok"}), \
                 patch("ocr_worker.advise_model_cache",return_value={"status":"ok"}):
                worker=IsolatedOCR("models")
                result=worker.recognize("photo.jpg")
            command=commands[0]
            self.assertEqual(command[command.index("--det-limit")+1],expected)
            self.assertEqual(result["memory_guard"]["policy"]["det_limit"],int(expected))
            self.assertFalse(worker.lock.locked())
            self.assertEqual(worker._activity,"idle")

    def test_status_is_readonly_reports_capacity_current_and_pressure(self):
        with TemporaryDirectory() as folder:
            path=Path(folder)/"memory.current"
            path.write_text(str(400*_MIB))
            path.with_name("memory.stat").write_text(f"inactive_file {100*_MIB}\n")
            def discovered(*args,**kwargs):
                return _MemoryGuard([(path,2048*_MIB)],360*_MIB,96*_MIB)
            with patch("ocr_worker.sys.platform","linux"),patch.object(_MemoryGuard,"discover",side_effect=discovered), \
                 patch("ocr_worker.read_process_rss_mb",return_value=81.2), \
                 patch("ocr_worker.release_unused_memory") as cleanup,patch("ocr_worker.advise_model_cache") as advice:
                worker=IsolatedOCR("models")
                result=worker.read_memory_status()
                self.assertEqual(result["status"],"ok")
                self.assertEqual((result["service_limit_mb"],result["service_current_mb"],result["working_set_mb"]),(2048,400,300))
                self.assertEqual((result["worker_limit_mb"],result["service_stop_mb"],result["det_limit"]),(1280,1792,1600))
                self.assertNotIn(folder,str(result))
                path.write_text(str(1800*_MIB))
                self.assertEqual(worker.read_memory_status()["status"],"pressure")
                path.unlink()
                unavailable=worker.read_memory_status()
                self.assertEqual(unavailable["status"],"unavailable")
                self.assertIsNone(unavailable["service_current_mb"])
            cleanup.assert_not_called();advice.assert_not_called()

    def test_windows_status_explicitly_reports_no_cgroup_monitor(self):
        with patch("ocr_worker.sys.platform","win32"),patch("ocr_worker.read_process_rss_mb",return_value=None):
            result=IsolatedOCR("models").read_memory_status()
        self.assertEqual(result["status"],"unsupported_platform")
        self.assertFalse(result["monitor_supported"])
        self.assertIsNone(result["service_limit_mb"])

    def test_larger_capacity_enforces_its_new_rss_and_service_limits(self):
        with TemporaryDirectory() as folder:
            root=Path(folder);usage=root/"memory.current"
            usage.write_text(str(1700*_MIB))
            process=root/"123";process.mkdir()
            status=process/"status";status.write_text(f"VmRSS:\t{1100*1024} kB\n")
            original=_MemoryGuard([(usage,2048*_MIB)],360*_MIB,96*_MIB,root)
            with patch("ocr_worker.sys.platform","linux"),patch.object(_MemoryGuard,"discover",return_value=original):
                guard=IsolatedOCR("models")._memory_guard()
            guard.observe(123)  # The larger plan is no longer capped at 360 MiB.
            usage.write_text(str(1792*_MIB))
            with self.assertRaises(OCRMemoryLimitError) as caught:
                guard.observe(123)
            self.assertEqual((caught.exception.kind,caught.exception.limit_mb),("service_budget",1792))
            usage.write_text(str(1500*_MIB));status.write_text(f"VmRSS:\t{1280*1024} kB\n")
            with self.assertRaises(OCRMemoryLimitError) as caught:
                guard.observe(123)
            self.assertEqual((caught.exception.kind,caught.exception.limit_mb),("worker_budget",1280))

    def test_readonly_status_reports_every_ancestor_when_first_is_under_pressure(self):
        with TemporaryDirectory() as folder:
            root=Path(folder);leaf=root/"leaf";parent=root/"parent"
            leaf.write_text(str(420*_MIB));parent.write_text(str(600*_MIB))
            guard=_MemoryGuard([(leaf,512*_MIB),(parent,2048*_MIB)],360*_MIB,96*_MIB)
            with patch("ocr_worker.sys.platform","linux"),patch.object(_MemoryGuard,"discover",return_value=guard):
                result=IsolatedOCR("models").read_memory_status()
            self.assertEqual(result["status"],"pressure")
            self.assertEqual([row["current_mb"] for row in result["cgroups"]],[420,600])
            self.assertEqual(result["available_mb"],0)

    def test_cleanup_busy_never_collects_evicts_or_stops_a_worker(self):
        worker=IsolatedOCR("models")
        worker.lock.acquire()
        try:
            with patch("ocr_worker.release_unused_memory") as cleanup, \
                 patch("ocr_worker.advise_model_cache") as advice,patch.object(worker,"_stop") as stop:
                result=worker.cleanup_memory()
            self.assertEqual(result,{"status":"busy","busy":True})
            cleanup.assert_not_called();advice.assert_not_called();stop.assert_not_called()
        finally:
            worker.lock.release()

    def test_cleanup_holds_lock_and_reports_actual_before_after_without_file_changes(self):
        worker=IsolatedOCR("models")
        def collect():
            self.assertTrue(worker.lock.locked())
            self.assertEqual(worker._activity,"cleanup")
            return {"status":"ok","rss_before_mb":100,"rss_after_mb":100}
        with patch.object(worker,"read_memory_status",side_effect=[{"service_current_mb":200},{"service_current_mb":201}]), \
             patch("ocr_worker.release_unused_memory",side_effect=collect), \
             patch("ocr_worker.advise_model_cache",return_value={"status":"partial","failed":["model"]}):
            result=worker.cleanup_memory()
        self.assertEqual(result["status"],"partial")
        self.assertEqual(result["before"]["service_current_mb"],200)
        self.assertEqual(result["after"]["service_current_mb"],201)  # No invented reclaimed amount.
        self.assertFalse(worker.lock.locked())
        self.assertEqual(worker._activity,"idle")

    def test_cleanup_exception_always_releases_shared_lock(self):
        worker=IsolatedOCR("models")
        with patch.object(worker,"read_memory_status",return_value={}), \
             patch("ocr_worker.release_unused_memory",side_effect=RuntimeError("TEST")), \
             self.assertRaises(RuntimeError):
            worker.cleanup_memory()
        self.assertFalse(worker.lock.locked())
        self.assertEqual(worker._activity,"idle")

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

    def pressure_run(self, advice, *, used=385, inactive=100, rss=224, waits=None, clock=None, deadline=None):
        self.fixture()
        (self.mount/"memory.current").write_text(str(int(used*_MIB)))
        (self.mount/"memory.stat").write_text(f"inactive_file {int(inactive*_MIB)}\n")
        process=FakeProcess(None)
        (self.proc/str(process.pid)).mkdir()
        status=self.proc/str(process.pid)/"status"
        status.write_text(f"State:\tR (running)\nVmRSS:\t{int(rss*1024)} kB\n")
        guard=self.guard()
        worker=IsolatedOCR("models")
        def wait(timeout=None):
            process.waited=True
            if process.returncode is not None:
                return process.returncode
            if waits:
                return waits(process)
            process.returncode=0
            return 0
        process.wait=wait
        def stop(value):
            value.kill();value.wait(timeout=5)
        with patch("ocr_worker.subprocess.Popen",return_value=process), \
             patch.object(worker,"_stop",side_effect=stop), \
             patch("ocr_worker.advise_model_cache",side_effect=lambda path:advice(guard,status)) as cache:
            if clock is None:
                code=worker._run(["TEST"],guard,deadline=deadline)
            else:
                with patch("ocr_worker.time.monotonic",side_effect=lambda:clock[0]):
                    code=worker._run(["TEST"],guard,deadline=deadline)
        return code,guard,cache,process

    def test_proactive_cache_relief_remeasures_current_usage_before_resuming_poll(self):
        def advice(guard,status):
            self.assertEqual(guard.worker_current,224*_MIB)
            (self.mount/"memory.current").write_text(str(310*_MIB))
            (self.mount/"memory.stat").write_text(f"inactive_file {25*_MIB}\n")
            return {"status":"ok","advised":["TEST allowlist"]}
        code,guard,cache,process=self.pressure_run(advice)
        self.assertEqual(code,0)
        self.assertEqual(cache.call_count,1)
        event=guard.metadata()["proactive_cache"][0]
        self.assertEqual(event["before"]["cgroups"][0]["current_mb"],385)
        self.assertEqual(event["after"]["cgroups"][0]["current_mb"],310)
        self.assertEqual(event["after_status"],"safe")
        self.assertEqual(guard.group_peaks,[385*_MIB])
        self.assertFalse(guard.cache_pressure(guard.last_cache_reclaim+1))
        self.assertTrue(process.killed and process.waited)

    def test_unreclaimed_cache_still_hits_unchanged_service_limit(self):
        def wait(process):
            (self.mount/"memory.current").write_text(str(int(416.5*_MIB)))
            raise subprocess.TimeoutExpired("TEST",.01)
        with self.assertRaises(OCRMemoryLimitError) as caught:
            self.pressure_run(lambda guard,status:{"status":"ok","advised":["TEST"]},waits=wait)
        self.assertEqual(caught.exception.kind,"service_budget")
        self.assertEqual(caught.exception.limit_mb,416)
        self.assertEqual(len(caught.exception.memory_guard["proactive_cache"]),1)
        self.assertEqual(caught.exception.memory_guard["proactive_cache"][0]["after"]["cgroups"][0]["current_mb"],385)

    def test_crossing_stop_limit_or_worker_limit_never_triggers_cache_advice(self):
        for used,rss,kind in ((416.5,224,"service_budget"),(385,361,"worker_budget")):
            calls=[]
            with self.subTest(kind=kind),self.assertRaises(OCRMemoryLimitError) as caught:
                self.pressure_run(lambda guard,status:calls.append(True) or {},used=used,rss=rss)
            self.assertEqual(caught.exception.kind,kind)
            self.assertEqual(calls,[])

    def test_immediate_post_advice_recheck_enforces_all_guards(self):
        for failure in ("service_budget","worker_budget","monitor_unavailable"):
            def advice(guard,status):
                if failure=="service_budget":
                    (self.mount/"memory.current").write_text(str(417*_MIB))
                elif failure=="worker_budget":
                    status.write_text("State:\tR (running)\nVmRSS:\t369664 kB\n")
                else:
                    (self.mount/"memory.current").unlink()
                return {"status":"ok"}
            with self.subTest(failure=failure),self.assertRaises(OCRMemoryLimitError) as caught:
                self.pressure_run(advice)
            self.assertEqual(caught.exception.kind,failure)
            self.assertEqual(caught.exception.memory_guard["proactive_cache"][0]["after_status"],failure)

    def test_low_cache_or_low_current_usage_does_not_spend_reclaim_budget(self):
        for used,inactive in ((383,100),(385,15)):
            code,guard,cache,process=self.pressure_run(lambda guard,status:{},used=used,inactive=inactive)
            self.assertEqual(code,0)
            cache.assert_not_called()
            self.assertEqual(guard.cache_reclaims,[])

    def test_ancestor_over_budget_is_not_bypassed_by_a_reclaimable_leaf(self):
        self.fixture()
        (self.mount/"memory.current").write_text(str(385*_MIB))
        (self.mount/"memory.stat").write_text(f"inactive_file {100*_MIB}\n")
        ancestor=self.root/"ancestor";ancestor.mkdir()
        (ancestor/"memory.current").write_text(str(417*_MIB))
        guard=_MemoryGuard([(self.mount/"memory.current",512*_MIB),(ancestor/"memory.current",512*_MIB)],360*_MIB,96*_MIB,self.proc)
        with patch("ocr_worker.advise_model_cache") as cache,patch("ocr_worker.subprocess.Popen") as launch:
            with self.assertRaises(OCRMemoryLimitError) as caught:
                IsolatedOCR("models")._run(["TEST"],guard)
        self.assertEqual(caught.exception.kind,"service_budget")
        cache.assert_not_called();launch.assert_not_called()

    def test_reclaim_frequency_count_and_original_deadline_are_bounded(self):
        clock=[10.];advice_times=[];polls=[0]
        def advice(guard,status):
            advice_times.append(clock[0]);return {"status":"ok"}
        def wait(process):
            polls[0]+=1;clock[0]+=.05
            if polls[0]>=30:
                process.returncode=0;return 0
            raise subprocess.TimeoutExpired("TEST",.01)
        code,guard,cache,process=self.pressure_run(advice,waits=wait,clock=clock,deadline=15.)
        self.assertEqual(code,0)
        self.assertEqual(len(advice_times),8)
        self.assertTrue(all(b-a>=.1 for a,b in zip(advice_times,advice_times[1:])))
        self.assertEqual(len(guard.metadata()["proactive_cache"]),8)
        fresh=self.guard()
        self.assertEqual(fresh.cache_reclaims,[])
        self.assertIsNone(fresh.last_cache_reclaim)
        clock[0]=10.
        def slow_advice(guard,status):
            clock[0]=12.;return {"status":"ok"}
        with self.assertRaisesRegex(RuntimeError,"exceeded"):
            self.pressure_run(slow_advice,clock=clock,deadline=11.)

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
        with self.assertRaisesRegex(OCRMemoryLimitError, "monitor_unavailable") as caught:
            guard.observe()
        self.assertEqual(caught.exception.reason, "cgroup_usage_read")
        self.assertEqual(caught.exception.monitor_detail["exception"], "FileNotFoundError")

    def test_missing_child_memory_map_preserves_diagnostic_reason_and_state(self):
        self.fixture()
        guard = self.guard()
        with self.assertRaises(OCRMemoryLimitError) as caught:
            guard.observe(123)
        self.assertEqual(caught.exception.reason, "worker_status_missing")
        child = self.proc / "123"; child.mkdir()
        (child / "status").write_text("Name:\tTEST\nState:\tZ (zombie)\n")
        with self.assertRaises(OCRMemoryLimitError) as caught:
            guard.observe(123)
        self.assertEqual(caught.exception.reason, "worker_rss_missing")
        self.assertEqual(caught.exception.monitor_detail["worker_state"], "Z")
        self.assertIn("worker_rss_missing", str(caught.exception))

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
