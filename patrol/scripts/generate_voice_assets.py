"""Build fixed public patrol messages locally; never reads accounts or credentials.

One-time build tools (not application/runtime dependencies):
  .venv/Scripts/python.exe -m pip install --target output/voice-asset-tools \
      espeakng-loader==0.2.4 lameenc==1.9.0 soundfile==0.14.0 numpy==2.5.4
  .venv/Scripts/python.exe scripts/generate_voice_assets.py
  .venv/Scripts/python.exe scripts/generate_voice_assets.py --verify-only

eSpeak NG is a formant synthesizer with a noticeably synthetic voice. Validation
checks content mapping and signal integrity, not native-speaker intelligibility.
The engine is used as a build tool only and is not distributed with the website.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "output/voice-asset-tools"
sys.path.insert(0, str(TOOLS))
import numpy as np
import soundfile as sf

ASSETS = ROOT / "static/audio/patrol-v1"
REPORT = ROOT / "output/bundled-voice-assets-report.json"
KINDS = (
    "saved_execute", "saved_inspect", "saved_visit", "already_recorded",
    "waiting_execution", "device_required", "point_unavailable", "offline_stored",
    "sync_confirmed", "sync_partial", "not_saved", "login_required", "receipt_confirmed",
)
VOICES = {"zh-Hant": "cmn", "id": "id", "vi": "vi"}
SOURCES = {
    "engine": "https://github.com/espeak-ng/espeak-ng",
    "engine_license": "https://github.com/espeak-ng/espeak-ng/blob/master/COPYING",
    "audio_output_usage": "https://sourceforge.net/p/espeak/discussion/538921/thread/7be4e8b2/",
    "loader": "https://github.com/thewh1teagle/espeakng-loader",
    "encoder": "https://github.com/chrisstaite/lameenc",
}


def source_messages():
    text = (ROOT / "static/patrol-voice.js").read_text(encoding="utf-8")
    block = re.search(r"const MESSAGES = Object\.freeze\(\{(.*?)\}\)", text, re.S)
    if not block:
        raise ValueError("Cannot locate fixed voice MESSAGES")
    messages = dict(re.findall(r"([a-z_]+):\s*'([^']+)'", block.group(1)))
    if set(messages) != set(KINDS):
        raise ValueError("Voice kinds changed; review the fixed 39-asset contract first")
    translations = json.loads((ROOT / "locales/client.json").read_text(encoding="utf-8"))
    result = []
    for locale, voice in VOICES.items():
        for kind in KINDS:
            source = messages[kind]
            spoken = source if locale == "zh-Hant" else translations[source][locale]
            if not isinstance(spoken, str) or not spoken.strip() or len(spoken) > 160:
                raise ValueError(f"Invalid fixed message: {locale}/{kind}")
            result.append(dict(locale=locale, kind=kind, source=source, text=spoken, voice=voice))
    return result


class EspeakBuilder:
    def __init__(self):
        import espeakng_loader
        self.lib = espeakng_loader.load_library()
        if self.lib is None:
            raise RuntimeError("eSpeak library is unavailable")
        self.lib.espeak_Initialize.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        self.lib.espeak_Initialize.restype = ctypes.c_int
        # SYNCHRONOUS callback output: no device/speaker playback.
        self.sample_rate = self.lib.espeak_Initialize(
            2, 0, str(Path(espeakng_loader.get_data_path()).parent).encode(), 0
        )
        if self.sample_rate <= 0:
            raise RuntimeError("eSpeak initialization failed")
        self.lib.espeak_Info.argtypes = [ctypes.c_void_p]
        self.lib.espeak_Info.restype = ctypes.c_char_p
        self.version = self.lib.espeak_Info(None).decode("utf-8")
        self.library_sha256 = hashlib.sha256(Path(espeakng_loader.get_library_path()).read_bytes()).hexdigest()
        self.lib.espeak_SetVoiceByName.argtypes = [ctypes.c_char_p]
        self.lib.espeak_SetParameter.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
        self.lib.espeak_Synth.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint,
                                        ctypes.c_int, ctypes.c_uint, ctypes.c_uint,
                                        ctypes.c_void_p, ctypes.c_void_p]
        callback_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_short), ctypes.c_int, ctypes.c_void_p)
        self.chunks = []

        def receive(samples, count, _events):
            if samples and count > 0:
                self.chunks.append(ctypes.string_at(samples, count * 2))
            return 0

        self.callback = callback_type(receive)
        self.lib.espeak_SetSynthCallback(self.callback)
        self.lib.espeak_SetParameter(1, 155, 0)  # Deliberate, consistent rate for short workplace prompts.

    def build(self, item, target):
        import lameenc
        if self.lib.espeak_SetVoiceByName(item["voice"].encode()) != 0:
            raise RuntimeError(f"Missing voice: {item['voice']}")
        self.chunks.clear()
        text = item["text"].encode("utf-8")
        # UTF-8 plus end-of-sentence pause, not SSML or arbitrary markup.
        if self.lib.espeak_Synth(text, len(text) + 1, 0, 1, 0, 1 | 0x1000, None, None) != 0:
            raise RuntimeError(f"Synthesis failed: {item['locale']}/{item['kind']}")
        self.lib.espeak_Synchronize()
        samples = np.frombuffer(b"".join(self.chunks), dtype="<i2").astype(np.float64) / 32768
        active = np.flatnonzero(np.abs(samples) > .003)
        if active.size == 0:
            raise ValueError("Synthesizer returned silence")
        # Retain consonant attacks and natural short ending without large blank padding.
        start = max(0, int(active[0]) - round(self.sample_rate * .07))
        end = min(len(samples), int(active[-1]) + round(self.sample_rate * .12) + 1)
        samples = samples[start:end]
        peak = float(np.max(np.abs(samples)))
        rms = float(np.sqrt(np.mean(samples ** 2)))
        gain = min(.1 / rms, .85 / peak)  # approximately -20 dBFS RMS with clipping headroom.
        pcm = np.round(samples * gain * 32767).astype("<i2")
        encoder = lameenc.Encoder()
        encoder.set_bit_rate(64)
        encoder.set_in_sample_rate(self.sample_rate)
        encoder.set_channels(1)
        encoder.set_quality(2)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(encoder.encode(pcm.tobytes()) + encoder.flush())
        return dict(input_peak=peak, input_rms=rms, normalization_gain=gain)

    def close(self):
        self.lib.espeak_Terminate()


def inspect_file(path):
    data = path.read_bytes()
    samples, rate = sf.read(path, dtype="float64", always_2d=True)
    duration = len(samples) / rate
    peak = float(np.max(np.abs(samples)))
    rms = float(np.sqrt(np.mean(samples ** 2)))
    if not .5 <= duration <= 14.5:
        raise ValueError(f"Implausible duration: {path} {duration}")
    if samples.shape[1] != 1 or not .03 <= peak < .99 or rms < .02:
        raise ValueError(f"Silent, clipped, or invalid signal: {path}")
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                duration_seconds=round(duration, 6), sample_rate=rate, channels=samples.shape[1],
                decoded_peak=round(peak, 6), decoded_rms=round(rms, 6),
                decoded_rms_dbfs=round(float(20 * np.log10(rms)), 3))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-only", action="store_true", help="Decode/hash existing assets without synthesis")
    args = parser.parse_args()
    wanted = source_messages()
    builder = None if args.verify_only else EspeakBuilder()
    previous = json.loads((ASSETS / "manifest.json").read_text(encoding="utf-8")) if args.verify_only else None
    results, files = [], []
    try:
        for item in wanted:
            relative = f"{item['locale']}/{item['kind']}.mp3"
            target = ASSETS / relative
            normalization = builder.build(item, target) if builder else {}
            checked = inspect_file(target)
            entry = item | dict(path=f"/static/audio/patrol-v1/{relative}") | {
                key: checked[key] for key in ("bytes", "sha256", "duration_seconds")
            }
            if previous:
                old = next(row for row in previous["files"] if row["path"] == entry["path"])
                if old != entry:
                    raise ValueError(f"Manifest/source mismatch: {relative}")
            files.append(entry)
            results.append(entry | checked | normalization)
    finally:
        if builder:
            builder.close()
    if len(files) != 39 or sum(row["bytes"] for row in files) >= 3_000_000:
        raise ValueError("The fixed complete asset budget is 39 files below 3 MB")
    generated = previous["generator"] if previous else {
        "engine": "eSpeak NG", "version": builder.version,
        "engine_library_sha256": builder.library_sha256,
        "voice_style": "Formant synthesis; noticeably mechanical, not a recorded human voice.",
        "rate_words_per_minute": 155, "encoding": "MP3, mono, 64 kbps",
        "normalization": "Target RMS -20 dBFS, peak limited to 0.85 before MP3 encoding.",
        "reproduce": ".venv/Scripts/python.exe scripts/generate_voice_assets.py",
        "dependencies": {name: importlib.metadata.version(name)
                         for name in ("espeakng-loader", "lameenc", "soundfile", "numpy")},
    }
    manifest = dict(version="patrol-v1", generator=generated, sources=SOURCES, files=files)
    if not args.verify_only:
        (ASSETS / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report = dict(version="patrol-v1", mode="verification" if args.verify_only else "generation",
                  generator=generated, sources=SOURCES, asset_count=len(files),
                  total_bytes=sum(row["bytes"] for row in files),
                  checks={"all_decoded": True, "all_non_silent": True, "all_unclipped": True,
                          "all_messages_match_source": True, "human_listening_review": False,
                          "native_speaker_review": False,
                          "limitation": "Audio input is unavailable in this agent. Decoding/signal checks do not establish intelligibility."},
                  files=results)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"files": len(files), "total_bytes": report["total_bytes"],
                      "duration_min": min(r["duration_seconds"] for r in files),
                      "duration_max": max(r["duration_seconds"] for r in files),
                      "report": str(REPORT)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
