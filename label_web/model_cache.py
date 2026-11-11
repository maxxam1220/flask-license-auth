"""Best-effort cache advice for this service's three immutable OCR model files.

POSIX_FADV_DONTNEED is advisory. A successful call neither changes file contents
nor proves that any bytes were reclaimed. It does not change the memory guard.
https://man7.org/linux/man-pages/man2/posix_fadvise.2.html
"""
import os
from pathlib import Path
import stat
import sys


MODEL_FILENAMES = (
    "PP-OCRv6_det_small.onnx",
    "ch_ppocr_mobile_v2.0_cls_mobile.onnx",
    "PP-OCRv6_rec_medium.onnx",
)


def advise_model_cache(model_dir):
    """Advise only regular, non-symlink allowlisted files; never scan a tree.

The deployment-owned directory is opened once, and each fixed basename is
opened relative to that directory fd with O_NOFOLLOW. Every fd is closed even
when the advisory syscall is unsupported or fails. No data is read or written.
"""
    result = {"status":"unsupported", "supported":False, "advised":[], "skipped":[], "failed":[]}
    facilities = ("posix_fadvise", "POSIX_FADV_DONTNEED", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
    if sys.platform != "linux" or any(not hasattr(os, name) for name in facilities):
        return result
    result.update(status="ok", supported=True)
    directory_fd = None
    try:
        directory_fd = os.open(Path(model_dir), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        for name in MODEL_FILENAMES:
            fd = None
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory_fd)
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    result["skipped"].append(name)
                    continue
                # Offset zero and length zero cover the entire file; no partial
                # page is deliberately discarded and no fsync/write is needed.
                os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
                result["advised"].append(name)
            except FileNotFoundError:
                result["skipped"].append(name)
            except (OSError, TypeError, ValueError):
                result["failed"].append(name)
            finally:
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        if name not in result["failed"]:
                            result["failed"].append(name)
        if result["failed"]:
            result["status"] = "partial"
    except (OSError, TypeError, ValueError):
        result["status"] = "unavailable"
    finally:
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except OSError:
                result["status"] = "partial"
    return result
