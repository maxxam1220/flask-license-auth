"""Run each OCR job in a fresh process so native model memory is released."""
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import threading
import sys


class IsolatedOCR:
    def __init__(self, model_dir, timeout=180):
        self.model_dir = Path(model_dir).resolve()
        self.timeout = timeout
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
                   OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1", MKL_NUM_THREADS="1")
        return env

    def recognize(self, image_path):
        with self.lock, TemporaryDirectory(prefix="labelcheck-ocr-") as folder:
            output = Path(folder) / "result.json"
            command = [sys.executable, str(Path(__file__).with_name("ocr_engine.py")),
                       str(Path(image_path).resolve()), "--model-dir", str(self.model_dir),
                       "--output", str(output)]
            try:
                completed = subprocess.run(command, shell=False, check=False,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    env=self._environment(), timeout=self.timeout, close_fds=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            except subprocess.TimeoutExpired:
                # subprocess.run kills and reaps the child before raising.
                raise RuntimeError(f"OCR worker exceeded {self.timeout} seconds") from None
            if completed.returncode != 0:
                raise RuntimeError(f"OCR worker exited with code {completed.returncode}")
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
            return result
