"""Release native memory per photo and stop an oversized Linux OCR worker early.

The cgroup watchdog is a conservative early stop, not a kernel memory sandbox.
It keeps a reserve below the service limit; a delegated, separate cgroup would
be required for a hard per-worker RSS limit. RLIMIT_RSS does not enforce one on
modern Linux, and RLIMIT_AS would constrain ONNX's virtual address reservations.
"""
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
from tempfile import TemporaryDirectory
import threading
import sys
import time


_MIB = 1024 * 1024
_POLL_SECONDS = .01


class OCRMemoryLimitError(RuntimeError):
    """The OCR job was stopped without accepting any partial recognition."""

    def __init__(self, kind, observed_bytes=None, limit_bytes=None, reason=None):
        self.kind = kind
        self.reason = reason
        self.monitor_detail = None
        self.observed_mb = round(observed_bytes / _MIB, 1) if observed_bytes is not None else None
        self.limit_mb = round(limit_bytes / _MIB, 1) if limit_bytes is not None else None
        self.memory_guard = None
        detail = f" ({self.observed_mb} MiB / {self.limit_mb} MiB)" if self.observed_mb is not None else ""
        if reason:
            detail += f" [{reason}]"
        super().__init__(f"OCR memory protection: {kind}{detail}; worker stopped to preserve the web service")


def _unescape_mount(value):
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)


class _MemoryGuard:
    def __init__(self, limits, worker_limit_bytes, reserve_bytes, proc_root=Path("/proc")):
        # Each ancestor has its own current usage and limit: an ancestor can
        # include sibling processes, so only inspecting the leaf is insufficient.
        self.limits = limits
        self.worker_limit = worker_limit_bytes
        self.reserve = reserve_bytes
        self.proc_root = proc_root
        self.worker_peak = 0
        self.group_peaks = [0] * len(limits)
        self.inactive_file = [0] * len(limits)
        self.working_set_peaks = [0] * len(limits)
        self.oom_score_applied = False

    @classmethod
    def discover(cls, worker_limit_bytes, reserve_bytes, proc_root=Path("/proc"), require_cgroup=True):
        """Resolve v1/v2 controller mounts and finite ancestor limits read-only."""
        try:
            memberships = {}
            for line in (proc_root / "self" / "cgroup").read_text().splitlines():
                _, controllers, location = line.split(":", 2)
                if not controllers:
                    memberships["cgroup2"] = location
                elif "memory" in controllers.split(","):
                    memberships["cgroup"] = location
            limits, seen = [], set()
            for line in (proc_root / "self" / "mountinfo").read_text().splitlines():
                before, after = line.split(" - ", 1)
                mount_fields, fs_fields = before.split(), after.split()
                kind = fs_fields[0]
                if kind not in memberships or (kind == "cgroup" and "memory" not in fs_fields[2].split(",")):
                    continue
                mount_root = PurePosixPath(_unescape_mount(mount_fields[3]))
                location = PurePosixPath(memberships[kind])
                # A namespace-relative membership of '/' maps to the mount root.
                if location == PurePosixPath("/"):
                    relative = PurePosixPath(".")
                else:
                    try:
                        relative = location.relative_to(mount_root)
                    except ValueError:
                        continue
                if ".." in relative.parts:
                    continue
                mount = Path(_unescape_mount(mount_fields[4]))
                current = mount.joinpath(*relative.parts)
                limit_name, usage_name = (("memory.max", "memory.current") if kind == "cgroup2"
                                          else ("memory.limit_in_bytes", "memory.usage_in_bytes"))
                while True:
                    limit_path = current / limit_name
                    if limit_path.exists() and limit_path not in seen:
                        seen.add(limit_path)
                        value = limit_path.read_text().strip()
                        if value != "max":
                            limit = int(value)
                            # v1 uses a near-LONG_MAX sentinel for unlimited.
                            if 0 < limit < (1 << 60):
                                limits.append((current / usage_name, limit))
                    if current == mount:
                        break
                    current = current.parent
            if not limits:
                raise ValueError("no finite readable memory cgroup")
        except (OSError, ValueError, IndexError) as cause:
            if require_cgroup:
                raise OCRMemoryLimitError("monitor_unavailable", reason=f"cgroup_discovery:{type(cause).__name__}") from None
            limits = []  # Local Linux without a service cgroup still gets an RSS cap.
        return cls(limits, worker_limit_bytes, reserve_bytes, proc_root)

    def observe(self, pid=None):
        phase, state = "cgroup_usage_read", None
        try:
            for index, (path, limit) in enumerate(self.limits):
                used = int(path.read_text().strip())
                if used < 0:
                    raise ValueError("invalid cgroup counter")
                self.group_peaks[index] = max(self.group_peaks[index], used)
                # Diagnostic only: do not assume that every inactive file page
                # can be reclaimed before a burst allocation exhausts the cgroup.
                try:
                    stats = dict(line.split() for line in path.with_name("memory.stat").read_text().splitlines())
                    inactive = int(stats.get("total_inactive_file", stats.get("inactive_file", 0)))
                    self.inactive_file[index] = max(0, min(inactive, used))
                except (OSError, ValueError):
                    self.inactive_file[index] = 0
                working = used - self.inactive_file[index]
                self.working_set_peaks[index] = max(self.working_set_peaks[index], working)
                threshold = limit - self.reserve
                if used >= threshold:
                    raise OCRMemoryLimitError("service_budget", used, max(0, threshold))
            if pid is not None:
                phase = "worker_status_read"
                status = (self.proc_root / str(pid) / "status").read_text()
                state_match = re.search(r"^State:\s+(\S)", status, re.MULTILINE)
                state = state_match[1] if state_match else None
                phase = "worker_rss_missing"
                match = re.search(r"^VmRSS:\s+(\d+)\s+kB$", status, re.MULTILINE)
                if match is None:
                    raise ValueError("missing RSS counter")
                rss = int(match[1]) * 1024
                self.worker_peak = max(self.worker_peak, rss)
                if rss >= self.worker_limit:
                    raise OCRMemoryLimitError("worker_budget", rss, self.worker_limit)
        except OCRMemoryLimitError as error:
            error.memory_guard = self.metadata()
            raise
        except (OSError, ValueError) as cause:
            if phase == "worker_status_read" and isinstance(cause, FileNotFoundError):
                phase = "worker_status_missing"
            error = OCRMemoryLimitError("monitor_unavailable", reason=phase)
            # Do not log /proc contents, photo text, or arbitrary exception paths.
            error.monitor_detail = {"operation": phase, "exception": type(cause).__name__,
                                    "errno": getattr(cause, "errno", None), "worker_state": state}
            error.memory_guard = self.metadata()
            error.args = (f"{error}; monitor={json.dumps(error.monitor_detail, separators=(',', ':'))}",)
            raise error from None

    def prefer_worker_for_oom(self, pid):
        # Raising our child's score needs no privilege. This is defense in depth,
        # not a substitute for the watchdog (memory.oom.group can kill a group).
        try:
            (self.proc_root / str(pid) / "oom_score_adj").write_text("1000")
            self.oom_score_applied = True
        except OSError:
            pass

    def metadata(self):
        return {"worker_rss_peak_mb": round(self.worker_peak / _MIB, 1),
                "worker_rss_limit_mb": round(self.worker_limit / _MIB, 1),
                "reserve_mb": round(self.reserve / _MIB, 1), "poll_interval_ms": 10,
                "oom_score_adj_applied": self.oom_score_applied,
                "cgroups": [{"peak_mb": round(peak / _MIB, 1),
                             "limit_mb": round(limit / _MIB, 1),
                             "stop_at_mb": round((limit - self.reserve) / _MIB, 1),
                             "inactive_file_mb": round(self.inactive_file[index] / _MIB, 1),
                             "working_set_peak_mb": round(self.working_set_peaks[index] / _MIB, 1)}
                            for index, ((_, limit), peak) in enumerate(zip(self.limits, self.group_peaks))]}


class IsolatedOCR:
    def __init__(self, model_dir, timeout=180, worker_memory_mb=360, reserve_memory_mb=96):
        self.model_dir = Path(model_dir).resolve()
        self.timeout = timeout
        # These are trusted deployment settings, never photo/request parameters.
        # Keep accidental configuration changes within this service's 512MiB plan.
        if not 128 <= worker_memory_mb <= 384 or not 64 <= reserve_memory_mb <= 192:
            raise ValueError("OCR memory settings exceed the supported safety bounds")
        self.worker_memory = int(worker_memory_mb * _MIB)
        self.reserve_memory = int(reserve_memory_mb * _MIB)
        self.lock = threading.Lock()

    @staticmethod
    def _environment():
        # Inference needs model files, not the web application's credentials.
        denied = ("SECRET", "PASSWORD", "TOKEN", "CREDENTIAL", "DATABASE", "POSTGRES")
        env = {key: value for key, value in os.environ.items()
               if not any(part in key.upper() for part in denied)
               and not key.upper().endswith(("_KEY", "_KEYS"))
               and not key.upper().startswith(("PG", "LABELCHECK_"))}
        env.update(PYTHONIOENCODING="utf-8", PYTHONUTF8="1",
                   OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1", MKL_NUM_THREADS="1",
                   MALLOC_ARENA_MAX="1", MALLOC_TRIM_THRESHOLD_="131072", MALLOC_MMAP_THRESHOLD_="131072")
        if sys.platform.startswith("linux"):
            # GNU's tunables supersede the legacy variables. Replace only these
            # three allocator settings, retaining unrelated security tunables.
            tuning = {"glibc.malloc.arena_max": "1", "glibc.malloc.trim_threshold": "131072",
                      "glibc.malloc.mmap_threshold": "131072"}
            retained = [entry for entry in env.get("GLIBC_TUNABLES", "").split(":")
                        if entry and entry.split("=", 1)[0] not in tuning]
            env["GLIBC_TUNABLES"] = ":".join(retained + [f"{key}={value}" for key, value in tuning.items()])
        return env

    def _memory_guard(self):
        if not sys.platform.startswith("linux"):
            return None
        on_render = os.environ.get("RENDER", "").lower() == "true" or bool(os.environ.get("RENDER_SERVICE_ID"))
        return _MemoryGuard.discover(self.worker_memory, self.reserve_memory, require_cgroup=on_render)

    @staticmethod
    def _stop(process):
        try:
            if os.name == "posix":
                # The leader can exit while descendants remain in its session.
                # Stop the group even when poll() has already reaped the leader.
                os.killpg(process.pid, signal.SIGKILL)
            elif process.poll() is None:
                process.kill()
        except ProcessLookupError:
            pass
        except OSError:
            if process.poll() is None:
                process.kill()
        process.wait(timeout=5)

    def _run(self, command, guard):
        if guard is not None:
            guard.observe()  # No model process is started under existing pressure.
        process = subprocess.Popen(command, shell=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=self._environment(), close_fds=True, start_new_session=os.name == "posix",
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        deadline = time.monotonic() + self.timeout
        try:
            if guard is not None:
                guard.prefer_worker_for_oom(process.pid)
            while process.poll() is None:
                if guard is not None:
                    try:
                        guard.observe(process.pid)
                    except OCRMemoryLimitError as error:
                        # During exit Linux can remove the memory map (and VmRSS)
                        # before waitpid can reap the child. Only that child-/proc
                        # race gets a bounded grace period. A cgroup read failure
                        # remains fail-closed, even if the child has just exited.
                        if error.kind == "monitor_unavailable" and error.reason in {
                                "worker_status_missing", "worker_rss_missing"}:
                            try:
                                process.wait(timeout=.05)
                            except subprocess.TimeoutExpired:
                                raise error from None
                            break
                        raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError(f"OCR worker exceeded {self.timeout} seconds")
                try:
                    process.wait(timeout=min(_POLL_SECONDS, remaining) if guard is not None else remaining)
                except subprocess.TimeoutExpired:
                    pass
            return process.returncode
        finally:
            self._stop(process)

    def recognize(self, image_path):
        with self.lock, TemporaryDirectory(prefix="labelcheck-ocr-") as folder:
            output = Path(folder) / "result.json"
            command = [sys.executable, str(Path(__file__).with_name("ocr_engine.py")),
                       str(Path(image_path).resolve()), "--model-dir", str(self.model_dir),
                       "--output", str(output)]
            guard = self._memory_guard()
            returncode = self._run(command, guard)
            if returncode != 0:
                raise RuntimeError(f"OCR worker exited with code {returncode}")
            try:
                if output.stat().st_size > 4 * 1024 * 1024:
                    raise ValueError("oversized result")
                result = json.loads(output.read_text(encoding="utf-8"))
                if not isinstance(result, dict) or not isinstance(result.get("lines"), list):
                    raise ValueError("invalid result")
                if not isinstance(result.get("engine"), str) or not isinstance(result.get("elapsed"), (int, float)):
                    raise ValueError("missing result metadata")
            except (OSError, ValueError):
                raise RuntimeError("OCR worker did not produce a valid result") from None
            if guard is not None:
                result["memory_guard"] = guard.metadata()
            return result
