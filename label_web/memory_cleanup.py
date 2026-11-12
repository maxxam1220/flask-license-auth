"""Best-effort release of unused parent heap pages between OCR workloads.

This does not free live Python objects, change memory limits, or guarantee a
smaller working set. Call it after dropping temporary image/result references.
GNU's Gnulib manual documents platform availability and refers to the man page:
https://www.gnu.org/software/gnulib/manual/gnulib.pdf
https://man7.org/linux/man-pages/man3/malloc_trim.3.html
"""
import ctypes
from functools import lru_cache
import gc
from pathlib import Path
import sys
import threading


_CLEANUP_LOCK = threading.Lock()


def _rss_mb():
    """Linux current RSS, not the historical maximum from getrusage."""
    if sys.platform != "linux":
        return None
    try:
        for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
            if line.startswith("VmRSS:"):
                parts = line.split()
                if len(parts) == 3 and parts[2] == "kB" and int(parts[1]) >= 0:
                    return round(int(parts[1]) / 1024, 2)
                return None
    except (OSError, UnicodeError, ValueError):
        pass
    return None


def read_process_rss_mb():
    """Expose a read-only best-effort current-process measurement to the UI."""
    return _rss_mb()


@lru_cache(maxsize=1)
def _malloc_trim():
    # The running process already has its allocator loaded. Do not invoke
    # find_library (which may launch helper commands) or guess a library path.
    try:
        allocator = ctypes.CDLL(None)
        trim = allocator.malloc_trim
        trim.argtypes = [ctypes.c_size_t]
        trim.restype = ctypes.c_int
        return trim
    except (AttributeError, OSError, TypeError):
        return None


def release_unused_memory():
    """Collect unreachable cycles, then ask Linux libc to return free pages.

All diagnostics are small, fixed-shape data. Missing platform facilities or a
cleanup failure never replaces the OCR result with an exception. RSS can grow
while other request threads allocate, even when malloc_trim reports success.
"""
    result = {"gc_collected": None, "trim_supported": False, "trim_released": False,
              "rss_before_mb": None, "rss_after_mb": None, "status": "ok"}
    if not _CLEANUP_LOCK.acquire(blocking=False):
        result["status"] = "busy"
        return result
    try:
        result["rss_before_mb"] = _rss_mb()
        result["gc_collected"] = gc.collect()
        if sys.platform == "linux":
            trim = _malloc_trim()
            if trim is None:
                result["status"] = "trim_unavailable"
            else:
                result["trim_supported"] = True
                result["trim_released"] = trim(0) == 1
        else:
            result["status"] = "unsupported_platform"
        result["rss_after_mb"] = _rss_mb()
    except Exception:
        # Do not expose exception text or make a cleanup failure break a job.
        result["status"] = "cleanup_failed"
    finally:
        _CLEANUP_LOCK.release()
    return result
