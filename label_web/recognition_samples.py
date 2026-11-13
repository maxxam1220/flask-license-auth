"""Read-only candidates for OCR evaluation; never automatically approved training truth."""
import hashlib
import json
import math
from pathlib import Path
import re

from flask import Response, abort, jsonify, request
from sqlalchemy import func, select

import database as db
import history_cleanup


MAX_INSPECTIONS = 2000
MAX_OBSERVATIONS = 5000
NOTICE = ("這些是人工訂正的候選資料，尚非核准訓練集，不會自動訓練或更換模型。"
          "匯出僅含文字、照片位置及文字框；請逐張確認框內實際印字、補齊漏框，"
          "再分開訓練與測試資料。同一原照片與衍生裁切不可跨訓練／測試分組。"
          "標準答案不會直接當成照片實印文字。")


def _digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")).encode()).hexdigest()


def _query():
    latest = select(db.corrections.c.inspection_id, func.max(db.corrections.c.revision).label("revision")).group_by(
        db.corrections.c.inspection_id).subquery()
    archived = ~history_cleanup.active_filter()
    return select(db.inspections.c.id.label("inspection_id"), db.inspections.c.image_id,
        db.inspections.c.created_at.label("inspection_created_at"),
        db.inspections.c.ocr["lines"].label("raw_lines"), db.inspections.c.ocr["engine"].as_string().label("engine"),
        db.inspections.c.ocr["preprocessing"].label("preprocessing"),
        db.inspections.c.result["recognition_of"].label("recognition_of"),
        db.inspections.c.template_snapshot["source"]["code"].as_string().label("source_code"),
        db.corrections.c.revision, db.corrections.c.patches,
        db.corrections.c.change, db.corrections.c.created_at.label("corrected_at"),
        db.images.c.sha256, db.images.c.width, db.images.c.height,
        archived.label("archived")).select_from(db.inspections.join(latest,
        latest.c.inspection_id == db.inspections.c.id).join(db.corrections,
        (db.corrections.c.inspection_id == latest.c.inspection_id) &
        (db.corrections.c.revision == latest.c.revision)).outerjoin(db.images,
        db.images.c.id == db.inspections.c.image_id)).order_by(db.inspections.c.id).limit(MAX_INSPECTIONS + 1)


def _box(value, width, height):
    if type(width) is not int or type(height) is not int or width <= 0 or height <= 0:
        return None
    if not isinstance(value, list) or len(value) != 4:
        return None
    points = []
    for point in value:
        if not isinstance(point, (list, tuple)) or len(point) != 2:
            return None
        if any(type(number) not in (int, float) or
               (isinstance(number, float) and not math.isfinite(number)) for number in point):
            return None
        x, y = point
        if not 0 <= x <= width or not 0 <= y <= height:
            return None
        points.append([float(x), float(y)])
    area = abs(sum(points[i][0] * points[(i+1) % 4][1] - points[(i+1) % 4][0] * points[i][1]
                   for i in range(4))) / 2
    return points if area >= 1 else None


def _json_safe(value):
    """A malformed optional score must not break a partially sent JSONL download."""
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _image_available(data_dir, identifier):
    if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", identifier):
        return False
    root = Path(data_dir).resolve() / "images"
    folder = root / identifier
    image = folder / "image.jpg"
    try:
        # Export coordinates refer to normalized image.jpg, never the differently
        # oriented/resized original. No image is decoded, copied, or included.
        return (not root.is_symlink() and not folder.is_symlink() and not image.is_symlink()
                and image.is_file() and image.resolve().parent == folder.resolve()
                and folder.resolve().parent == root.resolve())
    except OSError:
        return False


def collect(engine, data_dir):
    """Bounded, repeatable read of current corrections with conservative deduplication."""
    counts = {key: 0 for key in ("corrected_inspections", "active_inspections", "latest_patches",
        "eligible_observations", "candidates", "duplicate_observations", "conflict_groups",
        "excluded_archived", "excluded_kind", "excluded_invalid", "excluded_missing_image")}
    groups, available = {}, {}
    truncated = False
    with engine.connect() as conn:
        if engine.dialect.name == "postgresql":
            conn = conn.execution_options(isolation_level="REPEATABLE READ")
        with conn.begin():
            rows = conn.execution_options(stream_results=True, yield_per=25).execute(_query()).mappings()
            for row in rows:
                counts["corrected_inspections"] += 1
                if counts["corrected_inspections"] > MAX_INSPECTIONS:
                    truncated = True
                    break
                if row["archived"]:
                    counts["excluded_archived"] += 1
                    continue
                counts["active_inspections"] += 1
                raw_lines = row["raw_lines"] if isinstance(row["raw_lines"], list) else []
                by_id = {}
                for line in raw_lines:
                    if isinstance(line, dict) and type(line.get("id")) is int:
                        by_id.setdefault(line["id"], []).append(line)
                patches = row["patches"] if isinstance(row["patches"], list) else []
                for patch in patches:
                    counts["latest_patches"] += 1
                    if counts["latest_patches"] > MAX_OBSERVATIONS:
                        truncated = True
                        break
                    if not isinstance(patch, dict) or type(patch.get("line_id")) is not int:
                        counts["excluded_invalid"] += 1
                        continue
                    matching = by_id.get(patch["line_id"], [])
                    if len(matching) != 1:
                        counts["excluded_invalid"] += 1
                        continue
                    line = matching[0]
                    box = _box(line.get("box"), row["width"], row["height"])
                    image_hash = row["sha256"]
                    if box is None or not isinstance(image_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", image_hash):
                        counts["excluded_invalid"] += 1
                        continue
                    # Canonical vertex order recognizes the same physical crop
                    # even if the four corners start at a different vertex.
                    key = _digest([image_hash, row["width"], row["height"], sorted(box)])
                    group = groups.setdefault(key, {"sample": None, "texts": set(), "excluded_review": False})
                    if patch.get("kind") != "ocr_misread":
                        counts["excluded_kind"] += 1
                        group["excluded_review"] = True
                        continue
                    target = patch.get("text")
                    if (not isinstance(target, str) or not target.strip() or len(target) > 2000
                            or any(ord(c) < 32 for c in target) or not isinstance(line.get("text"), str)):
                        counts["excluded_invalid"] += 1
                        group["excluded_review"] = True
                        continue
                    if row["image_id"] not in available:
                        available[row["image_id"]] = _image_available(data_dir, row["image_id"])
                    if not available[row["image_id"]]:
                        counts["excluded_missing_image"] += 1
                        # The conflicting target still prevents using another
                        # duplicate's correction without reviewing that conflict.
                        group["texts"].add(target)
                        continue
                    counts["eligible_observations"] += 1
                    group["texts"].add(target)
                    provenance = {"inspection_id": row["inspection_id"], "image_id": row["image_id"],
                        "correction_revision": row["revision"], "line_id": patch["line_id"],
                        "kind": "ocr_misread", "reviewer": patch.get("reviewer", ""),
                        "note": patch.get("note", ""), "corrected_at": patch.get("created_at", row["corrected_at"]),
                        "inspection_created_at": row["inspection_created_at"], "source_code": row["source_code"],
                        "raw_text": line["text"], "raw_score": line.get("score"), "ocr_engine": row["engine"],
                        "ocr_preprocessing": row["preprocessing"], "change": row["change"],
                        "recognition_of": row["recognition_of"]}
                    if group["sample"] is None:
                        group["sample"] = {"schema_version": 1, "sample_id": key,
                            "state": "candidate_needs_crop_review", "training_ready": False,
                            "image": {"id": row["image_id"], "sha256_original": image_hash,
                                "url": f"/media/{row['image_id']}/image.jpg", "width": row["width"], "height": row["height"]},
                            "coordinate_space": "normalized_image.jpg", "box": box,
                            "raw_text": line["text"], "corrected_text": target,
                            "ocr_engine": row["engine"], "ocr_preprocessing": row["preprocessing"],
                            "provenance": [provenance]}
                    else:
                        group["sample"]["provenance"].append(provenance)
                if truncated:
                    break
            rows.close()
    samples = []
    for key in sorted(groups):
        group = groups[key]
        sample = group["sample"]
        if sample is None:
            continue
        if len(group["texts"]) != 1 or group["excluded_review"]:
            counts["conflict_groups"] += 1
            continue
        counts["duplicate_observations"] += len(sample["provenance"]) - 1
        samples.append(sample)
    counts["candidates"] = len(samples)
    summary = {"schema_version": 1, "generated_at": db.now(), "counts": counts,
        "requires_review": True, "training_ready": False, "truncated": truncated,
        "download_available": bool(samples) and not truncated,
        "export_url": "/api/admin/recognition-samples/export",
        "limits": {"inspections": MAX_INSPECTIONS, "observations": MAX_OBSERVATIONS},
        "notice": NOTICE + ("候選資料超過本次安全讀取上限，未開放不完整匯出；需分批審核後再匯出。" if truncated else "")}
    return summary, samples


def register_routes(app, engine, require_admin, data_dir):
    def guard():
        require_admin()
        if request.args:
            abort(400, description="此候選資料介面不接受自訂來源或照片路徑。")

    @app.get("/api/admin/recognition-samples")
    def recognition_sample_summary():
        guard()
        summary, _ = collect(engine, data_dir)
        response = jsonify(summary)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/admin/recognition-samples/export")
    def recognition_sample_export():
        guard()
        summary, samples = collect(engine, data_dir)
        if not summary["download_available"]:
            abort(409, description="目前沒有可匯出的完整候選資料；請先查看候選統計與排除原因。")
        # Each candidate is a line of JSON, not a ready-to-train PaddleOCR label.
        # Bounded metadata only; photo bytes are never loaded into this response.
        exported_at = summary["generated_at"]
        def chunks():
            for sample in samples:
                yield json.dumps(_json_safe({**sample, "exported_at": exported_at}), ensure_ascii=False, allow_nan=False) + "\n"
        response = Response(chunks(), content_type="application/x-ndjson; charset=utf-8")
        response.headers["Content-Disposition"] = 'attachment; filename="ocr-candidates.jsonl"'
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response
