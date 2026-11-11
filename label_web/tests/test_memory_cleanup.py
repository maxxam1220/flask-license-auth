import ctypes
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import memory_cleanup


class MemoryCleanupTests(unittest.TestCase):
    def tearDown(self):
        memory_cleanup._malloc_trim.cache_clear()

    def test_gc_precedes_trim_and_reports_measured_rss_without_claiming_a_guarantee(self):
        events = []
        trim = Mock(side_effect=lambda pad: events.append(("trim", pad)) or 1)
        with patch.object(memory_cleanup.sys, "platform", "linux"), \
             patch.object(memory_cleanup, "_rss_mb", side_effect=[150.0, 120.5]), \
             patch.object(memory_cleanup.gc, "collect", side_effect=lambda: events.append(("gc",)) or 4), \
             patch.object(memory_cleanup, "_malloc_trim", return_value=trim):
            result = memory_cleanup.release_unused_memory()
        self.assertEqual(events, [("gc",), ("trim", 0)])
        self.assertEqual(result, {"gc_collected": 4, "trim_supported": True, "trim_released": True,
                                 "rss_before_mb": 150.0, "rss_after_mb": 120.5, "status": "ok"})

    def test_no_releasable_pages_is_a_normal_result(self):
        with patch.object(memory_cleanup.sys, "platform", "linux"), \
             patch.object(memory_cleanup, "_rss_mb", side_effect=[120.0, 121.0]), \
             patch.object(memory_cleanup.gc, "collect", return_value=0), \
             patch.object(memory_cleanup, "_malloc_trim", return_value=Mock(return_value=0)):
            result = memory_cleanup.release_unused_memory()
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["trim_released"])
        self.assertEqual(result["rss_after_mb"], 121.0)

    def test_non_linux_does_not_load_or_call_foreign_allocator(self):
        with patch.object(memory_cleanup.sys, "platform", "win32"), \
             patch.object(memory_cleanup.gc, "collect", return_value=2), \
             patch.object(memory_cleanup.ctypes, "CDLL") as load:
            result = memory_cleanup.release_unused_memory()
        load.assert_not_called()
        self.assertEqual(result["status"], "unsupported_platform")
        self.assertEqual(result["gc_collected"], 2)
        self.assertIsNone(result["rss_before_mb"])

    def test_foreign_function_uses_current_process_and_exact_signature(self):
        trim = Mock(return_value=1)
        with patch.object(memory_cleanup.ctypes, "CDLL", return_value=SimpleNamespace(malloc_trim=trim)) as load:
            resolved = memory_cleanup._malloc_trim()
            self.assertIs(memory_cleanup._malloc_trim(), resolved)
        load.assert_called_once_with(None)
        self.assertEqual(trim.argtypes, [ctypes.c_size_t])
        self.assertIs(trim.restype, ctypes.c_int)

    def test_allocator_without_symbol_is_optional_and_does_not_leak_details(self):
        for loader in (Mock(return_value=SimpleNamespace()), Mock(side_effect=OSError("private libc path"))):
            memory_cleanup._malloc_trim.cache_clear()
            with patch.object(memory_cleanup.sys, "platform", "linux"), \
                 patch.object(memory_cleanup, "_rss_mb", return_value=None), \
                 patch.object(memory_cleanup.gc, "collect", return_value=0), \
                 patch.object(memory_cleanup.ctypes, "CDLL", loader):
                result = memory_cleanup.release_unused_memory()
            self.assertEqual(result["status"], "trim_unavailable")
            self.assertFalse(result["trim_supported"])
            self.assertNotIn("private", str(result))

    def test_collection_failure_is_contained_and_lock_released(self):
        with patch.object(memory_cleanup, "_rss_mb", return_value=100.0), \
             patch.object(memory_cleanup.gc, "collect", side_effect=RuntimeError("private diagnostics")):
            result = memory_cleanup.release_unused_memory()
        self.assertEqual(result["status"], "cleanup_failed")
        self.assertNotIn("private", str(result))
        self.assertTrue(memory_cleanup._CLEANUP_LOCK.acquire(blocking=False))
        memory_cleanup._CLEANUP_LOCK.release()

    def test_overlapping_cleanup_does_not_reenter_gc_or_wait(self):
        memory_cleanup._CLEANUP_LOCK.acquire()
        try:
            with patch.object(memory_cleanup.gc, "collect") as collect:
                result = memory_cleanup.release_unused_memory()
            collect.assert_not_called()
            self.assertEqual(result["status"], "busy")
        finally:
            memory_cleanup._CLEANUP_LOCK.release()

    def test_rss_uses_current_vmrss_and_missing_or_invalid_data_is_unknown(self):
        samples = [("VmHWM:\t999999 kB\nVmRSS:\t65536 kB\n", 64.0),
                   ("VmHWM:\t999999 kB\n", None), ("VmRSS:\t-3 kB\n", None),
                   ("VmRSS:\tbad kB\n", None), ("VmRSS:\t123 MB\n", None)]
        for content, expected in samples:
            with patch.object(memory_cleanup.sys, "platform", "linux"), \
                 patch.object(memory_cleanup.Path, "read_text", return_value=content):
                self.assertEqual(memory_cleanup._rss_mb(), expected)
        with patch.object(memory_cleanup.sys, "platform", "linux"), \
             patch.object(memory_cleanup.Path, "read_text", side_effect=PermissionError):
            self.assertIsNone(memory_cleanup._rss_mb())

    @unittest.skipUnless(sys.platform == "linux", "native malloc_trim smoke requires Linux")
    def test_native_cleanup_preserves_live_objects(self):
        canary = bytearray(b"still-live" * 10000)
        result = memory_cleanup.release_unused_memory()
        self.assertEqual(canary, b"still-live" * 10000)
        self.assertIn(result["status"], {"ok", "trim_unavailable"})
        self.assertIsInstance(result["rss_after_mb"], (int, float))


if __name__ == "__main__":
    unittest.main()
