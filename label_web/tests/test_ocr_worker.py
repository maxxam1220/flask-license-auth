import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from ocr_worker import IsolatedOCR


class IsolatedOCRTests(unittest.TestCase):
    def test_result_and_temporary_files_cleanup_without_secret_inheritance(self):
        observed = {}
        expected = {"lines": [{"id": 0, "text": "測試文字", "score": .99, "box": []}],
                    "engine": "TEST ONLY", "elapsed": .1}

        def run(command, **kwargs):
            observed.update(command=command, **kwargs)
            result_path = Path(command[command.index("--output") + 1])
            observed["result_path"] = result_path
            self.assertTrue(result_path.parent.exists())
            result_path.write_text(json.dumps(expected, ensure_ascii=False), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)

        with patch.dict(os.environ, {"LABELCHECK_DATABASE_URL": "private", "LABELCHECK_PASSWORD": "private",
                "LABELCHECK_SECRET": "private", "PGPASSWORD": "private", "OPENAI_API_KEY": "private",
                "RENDER_API_TOKEN": "private"}), patch("ocr_worker.subprocess.run", side_effect=run):
            self.assertEqual(IsolatedOCR("models").recognize("a photo.jpg"), expected)
        for key in ("LABELCHECK_DATABASE_URL", "LABELCHECK_PASSWORD", "LABELCHECK_SECRET",
                    "PGPASSWORD", "OPENAI_API_KEY", "RENDER_API_TOKEN"):
            self.assertNotIn(key, observed["env"])
        self.assertFalse(observed["shell"])
        self.assertTrue(observed["close_fds"])
        self.assertEqual(observed["stdout"], subprocess.DEVNULL)
        self.assertEqual(observed["stderr"], subprocess.DEVNULL)
        self.assertEqual(observed["command"][2], str(Path("a photo.jpg").resolve()))
        self.assertEqual(observed["command"][4], str(Path("models").resolve()))
        self.assertFalse(observed["result_path"].parent.exists())

    def test_timeout_cleans_partial_output_and_allows_next_attempt(self):
        folders = []

        def timeout(command, **kwargs):
            output = Path(command[-1]); folders.append(output.parent)
            output.write_text("partial", encoding="utf-8")
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        worker = IsolatedOCR("models", timeout=.1)
        with patch("ocr_worker.subprocess.run", side_effect=timeout):
            for _ in range(2):
                with self.assertRaisesRegex(RuntimeError, "exceeded"):
                    worker.recognize("photo.jpg")
        self.assertTrue(all(not folder.exists() for folder in folders))
        self.assertFalse(worker.lock.locked())

    def test_crash_never_returns_partial_result(self):
        paths = []

        def crash(command, **kwargs):
            output = Path(command[-1]); paths.append(output)
            output.write_text('{"lines":[]}', encoding="utf-8")
            return subprocess.CompletedProcess(command, -9)

        with patch("ocr_worker.subprocess.run", side_effect=crash):
            with self.assertRaisesRegex(RuntimeError, "code -9"):
                IsolatedOCR("models").recognize("photo.jpg")
        self.assertTrue(all(not path.parent.exists() for path in paths))

    def test_missing_or_invalid_worker_result_is_rejected_and_cleaned(self):
        for payload in (None, "not JSON", "[]", '{"lines":[]}', "x" * (4 * 1024 * 1024 + 1)):
            with self.subTest(payload_type=type(payload).__name__):
                paths = []

                def invalid(command, **kwargs):
                    output = Path(command[-1]); paths.append(output)
                    if payload is not None:
                        output.write_text(payload, encoding="utf-8")
                    return subprocess.CompletedProcess(command, 0)

                with patch("ocr_worker.subprocess.run", side_effect=invalid):
                    with self.assertRaisesRegex(RuntimeError, "valid result"):
                        IsolatedOCR("models").recognize("photo.jpg")
                self.assertTrue(all(not path.parent.exists() for path in paths))


if __name__ == "__main__":
    unittest.main()
