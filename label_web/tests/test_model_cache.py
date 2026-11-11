import errno
import json
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import model_cache
from ocr_engine import _install_model_cache_cleanup, _write_model_diagnostic


class ModelCacheTests(unittest.TestCase):
    def setup_linux(self, open_mock, fstat_mock=None, advise_mock=None):
        replacements = {"O_DIRECTORY":65536, "O_NOFOLLOW":131072, "O_CLOEXEC":524288, "O_NONBLOCK":2048,
                        "POSIX_FADV_DONTNEED":4, "posix_fadvise":advise_mock or Mock(), "open":open_mock,
                        "fstat":fstat_mock or Mock(return_value=SimpleNamespace(st_mode=stat.S_IFREG)), "close":Mock()}
        for key,value in replacements.items():
            context=patch.object(model_cache.os,key,value,create=True)
            context.start();self.addCleanup(context.stop)
        context=patch.object(model_cache.sys,"platform","linux")
        context.start();self.addCleanup(context.stop)
        return replacements

    def test_only_fixed_regular_models_are_advised_readonly_and_all_fds_close(self):
        mocks=self.setup_linux(Mock(side_effect=[10,11,12,13]))
        result=model_cache.advise_model_cache("trusted-models")
        self.assertEqual(result["advised"],list(model_cache.MODEL_FILENAMES))
        self.assertEqual(result["status"],"ok")
        self.assertNotIn("reclaimed_bytes",result)
        calls=mocks["open"].call_args_list
        self.assertEqual(calls[0].args[0],Path("trusted-models"))
        self.assertTrue(calls[0].args[1] & model_cache.os.O_NOFOLLOW)
        for call,name in zip(calls[1:],model_cache.MODEL_FILENAMES):
            self.assertEqual(call.args[0],name)
            self.assertEqual(call.kwargs,{"dir_fd":10})
            self.assertTrue(call.args[1] & model_cache.os.O_NOFOLLOW)
            self.assertFalse(call.args[1] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
        self.assertEqual([x.args for x in mocks["posix_fadvise"].call_args_list],[(11,0,0,4),(12,0,0,4),(13,0,0,4)])
        self.assertEqual([x.args[0] for x in mocks["close"].call_args_list],[11,12,13,10])

    def test_symlink_missing_and_special_file_do_not_receive_advice(self):
        mocks=self.setup_linux(Mock(side_effect=[10,OSError(errno.ELOOP,"private symlink path"),FileNotFoundError("private path"),13]),
                               Mock(return_value=SimpleNamespace(st_mode=stat.S_IFIFO)))
        result=model_cache.advise_model_cache("trusted-models")
        mocks["posix_fadvise"].assert_not_called()
        self.assertEqual(result["status"],"partial")
        self.assertEqual(result["failed"],[model_cache.MODEL_FILENAMES[0]])
        self.assertEqual(result["skipped"],list(model_cache.MODEL_FILENAMES[1:]))
        self.assertEqual([x.args[0] for x in mocks["close"].call_args_list],[13,10])
        self.assertNotIn("private",str(result))

    def test_advice_errors_are_contained_and_descriptors_close(self):
        mocks=self.setup_linux(Mock(side_effect=[10,11,12,13]),advise_mock=Mock(side_effect=OSError(errno.ENOSYS,"private detail")))
        result=model_cache.advise_model_cache("trusted-models")
        self.assertEqual(result["failed"],list(model_cache.MODEL_FILENAMES))
        self.assertEqual(result["advised"],[])
        self.assertEqual(mocks["close"].call_count,4)
        self.assertNotIn("private",str(result))

    def test_directory_symlink_or_permission_failure_is_nonfatal(self):
        mocks=self.setup_linux(Mock(side_effect=OSError(errno.ELOOP,"private directory")))
        result=model_cache.advise_model_cache("trusted-models")
        self.assertEqual(result["status"],"unavailable")
        mocks["close"].assert_not_called()
        mocks["posix_fadvise"].assert_not_called()
        self.assertNotIn("private",str(result))

    def test_non_linux_never_opens_or_modifies_files(self):
        with patch.object(model_cache.sys,"platform","win32"),patch.object(model_cache.os,"open") as opened:
            result=model_cache.advise_model_cache("unused")
        opened.assert_not_called()
        self.assertEqual(result["status"],"unsupported")
        self.assertFalse(result["supported"])

    def test_lazy_load_cleanup_preserves_order_models_and_repeated_calls(self):
        events,diagnostics=[],[]
        engine=SimpleNamespace(text_det=None,text_cls=None,text_rec=None)
        def loader(kind):
            def load():
                events.append("load_"+kind)
                if getattr(engine,"text_"+kind) is None:
                    setattr(engine,"text_"+kind,object())
                return getattr(engine,"text_"+kind)
            return load
        for kind in ("det","cls","rec"):
            setattr(engine,"_load_"+kind+"_model",loader(kind))
        with patch("ocr_engine.release_unused_memory",side_effect=lambda:events.append("trim") or {"status":"ok"}), \
             patch("ocr_engine.advise_model_cache",side_effect=lambda directory:events.append("advise") or {"status":"ok"}):
            _install_model_cache_cleanup(engine,"trusted",diagnostics)
            self.assertEqual(events,[])  # No eager model loading.
            original=engine._load_det_model()
            self.assertIs(original,engine._load_det_model())
            events.append("detector_inference")
            engine._load_cls_model();engine._load_rec_model()
        self.assertEqual(events,["load_det","trim","advise","load_det","detector_inference",
                                 "load_cls","trim","advise","load_rec","trim","advise"])
        self.assertEqual([item["stage"] for item in diagnostics],["after_det_load","after_cls_load","after_rec_load"])

    def test_failed_model_load_preserves_before_stage_and_prior_advice(self):
        with TemporaryDirectory() as directory:
            path=Path(directory)/"diagnostics.json"
            diagnostics=[{"stage":"after_engine_init","status":"ok","advised":list(model_cache.MODEL_FILENAMES)}]
            engine=SimpleNamespace(text_det=None,_load_det_model=Mock(side_effect=RuntimeError("TEST loader failure")))
            with patch("ocr_engine.release_unused_memory") as cleanup:
                _install_model_cache_cleanup(engine,"trusted",diagnostics,path)
                with self.assertRaisesRegex(RuntimeError,"TEST loader failure"):
                    engine._load_det_model()
            cleanup.assert_not_called()
            observed=json.loads(path.read_text())
            self.assertEqual(observed["stage"],"before_det_load")
            self.assertEqual(observed["last_advice"],diagnostics[0])
            self.assertNotIn("TEST loader failure",path.read_text())
            self.assertFalse(path.with_suffix(".tmp").exists())

    def test_optional_diagnostic_failure_does_not_break_inference(self):
        with patch.object(Path,"write_text",side_effect=PermissionError("private path")):
            _write_model_diagnostic("diagnostics.json","after_engine_init",{"status":"ok"})

    @unittest.skipUnless(sys.platform=="linux","native fadvise requires Linux")
    def test_native_advice_preserves_contents_and_rejects_symlink(self):
        with TemporaryDirectory() as directory:
            root=Path(directory)
            first=root/model_cache.MODEL_FILENAMES[0];first.write_bytes(b"model canary"*1000)
            second=root/model_cache.MODEL_FILENAMES[1];second.symlink_to(first)
            outsider=root/"not-a-current-model.onnx";outsider.write_bytes(b"unrelated")
            result=model_cache.advise_model_cache(root)
            self.assertIn(first.name,result["advised"])
            self.assertIn(second.name,result["failed"])
            self.assertEqual(first.read_bytes(),b"model canary"*1000)
            self.assertEqual(outsider.read_bytes(),b"unrelated")


if __name__=="__main__":
    unittest.main()
