"""Validate and package reviewed fixed voice recordings; never synthesizes at runtime.

Build-only dependencies: numpy, soundfile and lameenc in output/voice-asset-tools.
Input: <locale>/<kind>.wav and sources.json (a provenance object for each locale).
  .venv/Scripts/python.exe scripts/import_voice_assets.py --input-dir output/natural-voice
  .venv/Scripts/python.exe scripts/import_voice_assets.py --verify-only

The 39 original messages and stable public URLs remain unchanged. Normalization
only adjusts amplitude and exterior silence; it does not change pitch or speed.
All recordings are validated before any shipped asset is replaced.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys
import tempfile

from generate_voice_assets import ASSETS, ROOT, inspect_file, source_messages
import numpy as np
import soundfile as sf

REVISION = "natural-female-1"
LOCALES = ("zh-Hant", "id", "vi")


def encode_recording(source, destination):
    import lameenc

    samples, rate = sf.read(source, dtype="float64", always_2d=True)
    if (samples.shape[1] != 1 or not np.isfinite(samples).all()
            or rate not in (16000, 22050, 24000, 32000, 44100, 48000)
            or not .5 <= len(samples) / rate <= 18):
        raise ValueError(f"Invalid source recording: {source}")
    samples = samples[:, 0]
    if np.max(np.abs(samples)) >= 1:
        raise ValueError(f"Clipped source recording: {source}")
    active = np.flatnonzero(np.abs(samples) > .002)
    if not active.size:
        raise ValueError(f"Silent source recording: {source}")
    start = max(0, int(active[0]) - round(rate * .08))
    end = min(len(samples), int(active[-1]) + round(rate * .16) + 1)
    samples = samples[start:end]
    peak = float(np.max(np.abs(samples)))
    rms = float(np.sqrt(np.mean(samples ** 2)))
    gain = min(.1 / rms, .85 / peak)
    pcm = np.round(samples * gain * 32767).astype("<i2")
    encoder = lameenc.Encoder()
    encoder.set_bit_rate(96)
    encoder.set_in_sample_rate(rate)
    encoder.set_channels(1)
    encoder.set_quality(2)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(encoder.encode(pcm.tobytes()) + encoder.flush())
    return {"source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "source_sample_rate": rate, "normalization_gain": round(gain, 8),
            "trim_start_seconds": round(start / rate, 6),
            "trim_end_seconds": round(end / rate, 6)}


def reviewed_sources(value):
    if not isinstance(value, dict) or set(value) != set(LOCALES):
        raise ValueError("sources.json must describe all three languages")
    for locale, item in value.items():
        if not isinstance(item, dict) or any(not item.get(key) for key in ("engine", "voice", "model", "license", "source_url")):
            raise ValueError(f"Incomplete voice provenance: {locale}")
    return value


def verify_pack(directory, manifest):
    if manifest.get("version") != "patrol-v1" or manifest.get("revision") != REVISION:
        raise ValueError("Wrong audio revision")
    sources = reviewed_sources(manifest["sources"])
    entries = manifest["files"]
    wanted = source_messages()
    if len(entries) != 39 or len({item["path"] for item in entries}) != 39:
        raise ValueError("Expected exactly 39 distinct fixed audio files")
    by_path = {item["path"]: item for item in entries}
    results = []
    for item in wanted:
        relative = f"{item['locale']}/{item['kind']}.mp3"
        path = "/static/audio/patrol-v1/" + relative
        entry = by_path[path]
        for key in ("locale", "kind", "source", "text"):
            if entry[key] != item[key]:
                raise ValueError(f"Fixed message mismatch: {path}/{key}")
        if entry["voice"] != sources[item["locale"]]["voice"]:
            raise ValueError(f"Wrong voice provenance: {path}")
        checked = inspect_file(directory / relative)
        for key in ("bytes", "sha256", "duration_seconds"):
            if entry[key] != checked[key]:
                raise ValueError(f"Audio manifest mismatch: {path}/{key}")
        results.append(entry | checked)
    if sum(item["bytes"] for item in results) >= 3_000_000:
        raise ValueError("Complete audio pack must remain below 3 MB")
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob("*.mp3")}
    expected = {f"{item['locale']}/{item['kind']}.mp3" for item in wanted}
    if actual != expected:
        raise ValueError("Unexpected audio file outside the fixed message contract")
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--input-dir", type=Path)
    mode.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    normalization = []
    if args.verify_only:
        manifest = json.loads((ASSETS / "manifest.json").read_text(encoding="utf-8"))
        results = verify_pack(ASSETS, manifest)
    else:
        sources = reviewed_sources(json.loads((args.input_dir / "sources.json").read_text(encoding="utf-8")))
        with tempfile.TemporaryDirectory(prefix="patrol-voice-import-") as temporary:
            staging = Path(temporary)
            entries = []
            for item in source_messages():
                item = dict(item, voice=sources[item["locale"]]["voice"])
                relative = f"{item['locale']}/{item['kind']}.mp3"
                target = staging / relative
                details = encode_recording(args.input_dir / item["locale"] / (item["kind"] + ".wav"), target)
                checked = inspect_file(target)
                entries.append(item | {"path": "/static/audio/patrol-v1/" + relative} |
                               {key: checked[key] for key in ("bytes", "sha256", "duration_seconds")})
                normalization.append({"path": relative} | details)
            manifest = {"version": "patrol-v1", "revision": REVISION,
                        "generator": {"engine": "Pre-generated neural female voices",
                                      "encoding": "MP3, mono, 96 kbps",
                                      "normalization": "Target RMS -20 dBFS; peak <=0.85 before encoding; no pitch/time changes.",
                                      "packaging": "scripts/import_voice_assets.py",
                                      "dependencies": {name: importlib.metadata.version(name) for name in ("lameenc", "soundfile", "numpy")}},
                        "sources": sources, "files": entries}
            results = verify_pack(staging, manifest)
            # Validation is complete. There is no model dependency in production.
            for item in entries:
                relative = f"{item['locale']}/{item['kind']}.mp3"
                target = ASSETS / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((staging / relative).read_bytes())
            (ASSETS / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report = {"revision": REVISION, "mode": "verification" if args.verify_only else "import",
              "asset_count": len(results), "total_bytes": sum(item["bytes"] for item in results),
              "checks": {"all_decoded": True, "all_non_silent": True, "all_unclipped": True,
                         "all_messages_match_source": True, "native_speaker_review": False,
                         "limitation": "Signal and text mapping checks do not establish native pronunciation or subjective naturalness."},
              "sources": manifest["sources"], "files": results, "normalization": normalization}
    path = ROOT / "output/natural-voice" / ("verification.json" if args.verify_only else "import-report.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"files": len(results), "total_bytes": report["total_bytes"], "report": str(path)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
