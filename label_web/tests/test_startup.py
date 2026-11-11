import os
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch


class StartupTests(unittest.TestCase):
    def test_remote_minimum_password_boundary(self):
        for size, accepted in [(7,False),(8,True)]:
            with self.subTest(length=size), patch.dict(os.environ, {"LABELCHECK_HOST":"0.0.0.0","LABELCHECK_PASSWORD":"x"*size,"PORT":"10000"}, clear=True), patch("sys.argv",["run.py"]), patch("server.create_app") as create, patch("waitress.serve") as serve:
                if accepted:
                    runpy.run_path(str(Path(__file__).resolve().parents[1]/"run.py"),run_name="__main__")
                    create.assert_called_once()
                    serve.assert_called_once()
                else:
                    with self.assertRaises(SystemExit):
                        runpy.run_path(str(Path(__file__).resolve().parents[1]/"run.py"),run_name="__main__")
                    create.assert_not_called()


if __name__ == "__main__":
    unittest.main()
