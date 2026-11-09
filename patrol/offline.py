"""Signed, day-scoped offline visits with atomic, idempotent server receipts.

Only accepted submissions enter the database. Phone time is a bounded claim,
not proof of presence; the separate received_at remains the server clock.
"""
from datetime import datetime, time, timedelta, timezone
import hashlib
import hmac
import json
from uuid import UUID

from flask import g, jsonify, render_template, request, send_from_directory, url_for
from itsdangerous import BadData, URLSafeSerializer
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from account_roles import role_label
from daily_rounds import daily2_anytime
from domain import floor_label
from general_workflow import execution_in_slot, new_execution, personal_inspection_in_slot
from images import MAX_INPUT_BYTES, MAX_PHOTOS, PhotoValidationError, photo_storage_used, process_uploads
from issues import open_issue_for
from i18n import client_catalog, t, translate
from models import DeviceBinding, Inspection, InspectionPhoto, OfflineSubmission, PatrolExecution, Point, db
from patrol_access import can_access_point, inspection_team_scope


def iso(value):
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("invalid timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone is required")
    return parsed.astimezone(timezone.utc)


def register_offline(app, *, now, local_dt, naive_utc, period_for, timezone_local,
                     csrf_token, device_binding, lock_current_user,
                     executor_can_scan, point_revision, inspection_in_slot, audit):
    signer = URLSafeSerializer(app.secret_key, salt="patrol-offline-v1")

    def fail(code, message, status=409, retryable=False):
        return jsonify(ok=False, code=code, message=t(message), message_source=message, retryable=retryable), status

    def owner(user, binding):
        return f"u{user.id}v{user.auth_version}b{binding.id}-{user.role}-{user.patrol_category or 'all'}"

    def identity(user, binding):
        return dict(id=user.id, name=user.display_name, role=user.role, category=user.patrol_category,
                    binding_id=binding.id, auth_version=user.auth_version, role_label=role_label(user),
                    ui_language=user.ui_language,
                    inspection_team=inspection_team_scope(user),
                    simple_executor_ui=bool(user.role == 'executor' and user.simple_executor_ui))

    def actor(lock=False):
        if not g.get("user"):
            return None, None, fail("login_required", "請連網登入原帳號後再同步；暫存仍保留。", 401)
        user = lock_current_user() if lock else g.user
        if user.must_change_password:
            return None, None, fail("password_required", "請先完成密碼變更；暫存仍保留。", 403)
        binding = device_binding()
        if binding and lock:
            binding = db.session.scalar(select(DeviceBinding).where(DeviceBinding.id == binding.id)
                                        .with_for_update().execution_options(populate_existing=True))
        if not binding or binding.status != "approved":
            return None, None, fail("device_required", "此瀏覽器尚未核准或綁定已變更；請使用原綁定手機。", 403)
        return user, binding, None

    def stage_for(user, point):
        if not can_access_point(user, point):
            return None
        if user.role == "executor":
            if not executor_can_scan(point):
                return None
            return "execute" if point.workflow_mode == "two_stage" else "visit"
        if point.workflow_mode == "two_stage" and user.role != "inspector":
            return None
        return "inspect"

    def settings(point):
        return dict(id=point.id, token=point.qr_token, revision=point_revision(point),
                    frequency=point.frequency, workflow_mode=point.workflow_mode,
                    start=point.schedule_start.isoformat())

    def consumed(user, point, day, key, slot, stage):
        if stage == "execute":
            return execution_in_slot(point, key, slot)
        if point.workflow_mode in ("spot", "two_stage"):
            return personal_inspection_in_slot(point, user, day, slot)
        return inspection_in_slot(point, key, slot)

    @app.get("/offline")
    def offline_page():
        # This document is intentionally identical across sessions. It contains
        # no user, CSRF token, flash, point or server-provided private content.
        g.patrol_ui_locale = "zh-Hant"  # Also covers macros imported without context.
        # Cache only a public shell and the full static catalog. Never bake the
        # requesting account's locale into a shared service-worker response.
        return render_template("offline.html", ui_locale="zh-Hant", client_i18n=client_catalog("zh-Hant"),
                               simple_executor_ui=False, home_url="/dashboard",
                               t=lambda source, **values: translate(source, "zh-Hant", **values))

    @app.get("/offline-sw.js")
    def offline_worker():
        response = send_from_directory(app.static_folder, "offline-sw.js", mimetype="application/javascript")
        response.headers["Service-Worker-Allowed"] = "/"
        response.headers["Cache-Control"] = "no-cache"
        return response

    @app.get("/api/offline/status")
    def offline_status():
        user, binding, error = actor()
        if error:
            return error
        return jsonify(ok=True, owner=owner(user, binding), identity=identity(user, binding),
                       csrf_token=csrf_token(), server_time=iso(now()))

    @app.get("/api/offline/prepare")
    def offline_prepare():
        user, binding, error = actor()
        if error:
            return error
        instant = now()
        day = local_dt(instant).date()
        capture_until = datetime.combine(day + timedelta(days=1), time.min, timezone_local)
        sync_until = capture_until + timedelta(days=1)
        candidates = []
        for point in db.session.scalars(select(Point).where(Point.active.is_(True),
                Point.deleted_at.is_(None), Point.schedule_start <= day).order_by(Point.floor, Point.code)):
            stage = stage_for(user, point)
            if not stage:
                continue
            key = period_for(point, instant)[0]
            slots = ["am", "pm"] if point.frequency == "daily2" else ["any"]
            # Before the anytime cutover, offline capture is unavailable for
            # legacy morning/afternoon days; never reinterpret historical rules.
            if point.frequency == "daily2" and not daily2_anytime(day):
                continue
            candidates.append((point, stage, key, slots))
        # Prepare an entire route with a fixed number of queries. Loading a
        # receipt for every slot also eagerly loaded its offline mapping and
        # could exhaust the phone's short connection window on a large site.
        personal_ids = [p.id for p, stage, _, _ in candidates if p.workflow_mode in ("spot", "two_stage") and stage != "execute"]
        shared_ids = [p.id for p, _, _, _ in candidates if p.workflow_mode == "standard"]
        execution_ids = [p.id for p, _, _, _ in candidates if p.workflow_mode == "two_stage"]
        keys = {key for _, _, key, _ in candidates}
        personal_used = set(db.session.execute(select(Inspection.point_id, Inspection.slot).where(
            Inspection.point_id.in_(personal_ids), Inspection.user_id == user.id,
            Inspection.personal_day == day)).all()) if personal_ids else set()
        shared_used = set(db.session.execute(select(Inspection.point_id, Inspection.frequency, Inspection.period_key, Inspection.slot).where(
            Inspection.point_id.in_(shared_ids), Inspection.period_key.in_(keys),
            Inspection.legacy_unscheduled.is_(False), Inspection.executor_visit.is_(False))).all()) if shared_ids else set()
        executed_used = set(db.session.execute(select(PatrolExecution.point_id, PatrolExecution.frequency, PatrolExecution.period_key, PatrolExecution.slot).where(
            PatrolExecution.point_id.in_(execution_ids), PatrolExecution.period_key.in_(keys))).all()) if execution_ids else set()
        rows = []
        for point, stage, key, slots in candidates:
            grant = dict(v=1, owner=owner(user, binding), settings=settings(point), stage=stage,
                         day=day.isoformat(), period_key=key, issued_at=iso(instant),
                         capture_until=iso(capture_until), sync_until=iso(sync_until))
            executed = [slot for slot in slots if (point.id, point.frequency, key, slot) in executed_used]
            if stage == "execute":
                used = executed
            elif point.workflow_mode in ("spot", "two_stage"):
                used = [slot for slot in slots if ((point.id, "any") in personal_used or (point.id, slot) in personal_used
                        or (slot == "any" and any((point.id, old_slot) in personal_used for old_slot in ("am", "pm"))))]
            else:
                used = [slot for slot in slots if (point.id, point.frequency, key, slot) in shared_used]
            rows.append(dict(id=point.id, token=point.qr_token, revision=point_revision(point), code=point.code, name=point.name,
                             name_i18n={language: translate(point.name, language) for language in ("id", "vi")},
                             floor=floor_label(point.floor), frequency=point.frequency, workflow_mode=point.workflow_mode,
                             inspection_team=point.inspection_team,
                             stage=stage, period_key=key, slots=slots, used_slots=used, executed_slots=executed,
                             grant=signer.dumps(grant)))
        return jsonify(ok=True, version=1, owner=owner(user, binding), identity=identity(user, binding),
                       server_time=iso(instant), day=day.isoformat(), capture_until=iso(capture_until),
                       sync_until=iso(sync_until), csrf_token=csrf_token(), points=rows)

    def receipt(row, status):
        endpoint = "execution_success" if row.execution_id else "checkin_success"
        args = {"execution_id": row.execution_id} if row.execution_id else {"record_id": row.inspection_id}
        return jsonify(ok=True, status=status, client_id=row.client_id,
                       receipt_url=url_for(endpoint, **args), record_id=row.execution_id or row.inspection_id,
                       received_at=iso(row.received_at), observed_at=iso(row.observed_at))

    def prior_submission(user, client_id):
        return db.session.scalar(select(OfflineSubmission).where(
            OfflineSubmission.user_id == user.id, OfflineSubmission.client_id == client_id))

    @app.post("/api/offline/sync")
    def offline_sync():
        user, binding, error = actor(lock=True)
        if error:
            return error
        try:
            raw_entry = request.form.get("entry", "")
            if len(raw_entry) > 20000:
                raise ValueError("oversized entry")
            entry = json.loads(raw_entry)
            required = {"client_id", "owner", "token", "grant", "slot", "observed_at", "note", "is_abnormal"}
            if not isinstance(entry, dict) or set(entry) != required:
                raise ValueError("invalid entry fields")
            if any(not isinstance(entry[key], str) for key in required - {"is_abnormal"}):
                raise ValueError("invalid entry type")
            if type(entry["is_abnormal"]) is not bool:
                raise ValueError("invalid abnormal state")
            if str(UUID(entry["client_id"])) != entry["client_id"]:
                raise ValueError("invalid visit identifier")
            observed = parse_time(entry["observed_at"])
            note = entry["note"].replace("\r\n", "\n").replace("\r", "\n").strip()
            note.encode("utf-8")  # JSON may contain an invalid lone surrogate.
            if len(note) > 2000 or any((ord(c) < 32 and c not in "\t\n") or ord(c) == 127 for c in note):
                raise ValueError("invalid note")
            uploads = request.files.getlist("photos")
            if len(uploads) > MAX_PHOTOS or set(request.files) - {"photos"}:
                raise ValueError("invalid photo count")
            photo_hashes = []
            for upload in uploads:
                raw = upload.stream.read(MAX_INPUT_BYTES + 1)
                if not upload.filename or not raw or len(raw) > MAX_INPUT_BYTES:
                    raise ValueError("invalid photo size")
                photo_hashes.append(hashlib.sha256(raw).hexdigest())
                upload.stream.seek(0)
            canonical = dict(entry, note=note, observed_at=iso(observed), photos=photo_hashes)
            payload_hash = hashlib.sha256(json.dumps(canonical, sort_keys=True, ensure_ascii=True,
                                                    separators=(",", ":")).encode()).hexdigest()
        except (ValueError, TypeError, OverflowError, RecursionError):
            return fail("invalid_entry", "暫存格式不正確；備註最多 2,000 字、照片最多 3 張且每張 8 MB。資料仍保留。", 400)
        if entry["owner"] != owner(user, binding):
            return fail("owner_changed", "帳號權限或手機綁定已變更，這批暫存無法自動同步；請聯絡管理員。", 403)
        # An acknowledged-lost request must still resolve after its grant has
        # expired or the point was edited. Never create another attendance row.
        previous = prior_submission(user, entry["client_id"])
        if previous:
            if previous.binding_id != binding.id or not hmac.compare_digest(previous.payload_hash, payload_hash):
                return fail("payload_conflict", "這筆暫存編號已收到不同內容，未覆蓋原紀錄；請聯絡管理員。")
            return receipt(previous, "already_synced")
        try:
            grant = signer.loads(entry["grant"])
            if not isinstance(grant, dict) or grant.get("v") != 1 or grant.get("owner") != entry["owner"]:
                raise BadData("invalid owner")
            issued = parse_time(grant["issued_at"])
            capture_until = parse_time(grant["capture_until"])
            sync_until = parse_time(grant["sync_until"])
            point_id = grant["settings"]["id"]
        except (BadData, ValueError, KeyError, TypeError, OverflowError):
            return fail("invalid_grant", "離線準備資料無效；這筆暫存未送出，請聯絡管理員。", 400)
        instant = now()
        if instant >= sync_until:
            return fail("expired", "已超過隔日結束前的補傳期限，暫存仍保留，請聯絡管理員。")
        tolerance = timedelta(minutes=2)
        if (observed < issued - tolerance or observed >= capture_until or observed > instant + tolerance):
            return fail("invalid_time", "手機記錄時間不在有效範圍；暫存仍保留，請檢查手機日期與時間。")
        day = local_dt(observed).date()
        if day.isoformat() != grant["day"]:
            return fail("invalid_time", "手機記錄時間不在有效範圍；暫存仍保留，請檢查手機日期與時間。")
        if db.engine.dialect.name == "sqlite":
            # Obtain the writer reservation without overwriting any admin
            # setting from a stale object, then reread the authoritative row.
            db.session.execute(db.update(Point).where(Point.id == point_id).values(id=Point.id))
        point = db.session.scalar(select(Point).where(Point.id == point_id).with_for_update()
                                  .execution_options(populate_existing=True))
        # Waiting for the point lock can cross midnight. Recheck the server
        # clock after acquiring it instead of using the earlier grant-check time.
        if point and point.pending_frequency and point.frequency_effective_date <= local_dt(now()).date():
            db.session.rollback()
            return fail("point_changed", "點位、頻率或 QR Code 已更新，這筆暫存需要確認，尚未刪除。")
        if (not point or not point.active or point.deleted_at is not None
                or settings(point) != grant["settings"] or point.qr_token != entry["token"]
                or point.schedule_start > day):
            return fail("point_changed", "點位、頻率或 QR Code 已更新，這筆暫存需要確認，尚未刪除。")
        stage = stage_for(user, point)
        if not stage or stage != grant["stage"]:
            return fail("forbidden", "目前角色無法在此點完成這個階段；暫存仍保留。", 403)
        key = period_for(point, observed)[0]
        slot = entry["slot"]
        slots = ("am", "pm") if point.frequency == "daily2" else ("any",)
        if key != grant["period_key"] or slot not in slots:
            return fail("invalid_slot", "暫存日期或次數不符合點位設定；暫存仍保留。")
        if consumed(user, point, day, key, slot, stage):
            return fail("duplicate", "這個日期／次數已有紀錄，這筆暫存尚未合併或刪除。請核對原紀錄。")
        first = execution_in_slot(point, key, slot) if point.workflow_mode == "two_stage" else None
        if stage == "inspect" and point.workflow_mode == "two_stage":
            if first is None:
                return fail("waiting_execution", "等待執行同步；請執行人員先同步，再重試本筆。", retryable=True)
            if first.user_id == user.id:
                return fail("forbidden", "執行與巡檢必須由不同人員完成。", 403)
            if first.created_at > naive_utc(observed):
                return fail("execution_order", "手機巡檢時間早於執行簽到，尚未列為完成；請核對兩支手機時間。")
        if stage in ("execute", "visit") and (note or entry["is_abnormal"] or uploads):
            return fail("invalid_stage_content", "執行／直接簽到只記錄人員、點位與時間，不接受備註或照片。", 400)
        try:
            photos = process_uploads(uploads) if stage == "inspect" else []
        except PhotoValidationError as error:
            return fail("invalid_photos", str(error), 400)
        if photos:
            if db.engine.dialect.name == "postgresql":
                db.session.execute(db.text("SELECT pg_advisory_xact_lock(714032610303)"))
            used = photo_storage_used()
            if used + sum(photo["size_bytes"] for photo in photos) > app.config["PHOTO_STORAGE_LIMIT_BYTES"]:
                return fail("storage_full", "伺服器照片空間不足；整筆暫存保留，請聯絡管理員。", retryable=True)
        received = now()
        if received >= sync_until:
            return fail("expired", "已超過補傳期限；暫存仍保留，請聯絡管理員。")
        # Photo processing can also cross the scheduled cutover while this
        # transaction holds the point lock and prevents activation elsewhere.
        if point.pending_frequency and point.frequency_effective_date <= local_dt(received).date():
            db.session.rollback()
            return fail("point_changed", "點位、頻率或 QR Code 已更新，這筆暫存需要確認，尚未刪除。")
        row = OfflineSubmission(user_id=user.id, binding_id=binding.id, client_id=entry["client_id"],
                                payload_hash=payload_hash, observed_at=naive_utc(observed), received_at=naive_utc(received))
        if stage == "execute":
            record = new_execution(point, user, binding, key, slot, observed)
            row.execution = record
        else:
            record = Inspection(user_id=user.id, point_id=point.id, binding_id=binding.id,
                                created_at=naive_utc(observed), period_key=key, frequency=point.frequency,
                                slot=slot, category=point.category, point_code=point.code, point_name=point.name,
                                point_floor=point.floor, user_name=user.display_name, workflow_mode=point.workflow_mode,
                                execution_id=first.id if first else None,
                                spot_request_id=f"offline:{user.id}:{entry['client_id']}" if point.workflow_mode == "spot" else None,
                                personal_day=day if point.workflow_mode in ("spot", "two_stage") else None,
                                executor_visit=stage == "visit", note=note, is_abnormal=entry["is_abnormal"])
            record.photos.extend(InspectionPhoto(**photo) for photo in photos)
            open_issue_for(record)
            row.inspection = record
        db.session.add(row)
        binding.last_seen_at = naive_utc(received)
        audit("offline_sync", point.code, f"stage={stage}; client_id={entry['client_id']}; observed={iso(observed)}")
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            previous = prior_submission(user, entry["client_id"])
            if previous and previous.binding_id == binding.id and hmac.compare_digest(previous.payload_hash, payload_hash):
                return receipt(previous, "already_synced")
            return fail("duplicate", "同步期間已有相同次數的紀錄；暫存仍保留，請核對。")
        return receipt(row, "saved")
