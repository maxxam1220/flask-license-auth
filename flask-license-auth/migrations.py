# migrations.py
import os
import psycopg2

SQL_CREATE_ALL = """
-- 1) audit_login：登入/授權紀錄
CREATE TABLE IF NOT EXISTS audit_login (
  id           BIGSERIAL PRIMARY KEY,
  event_time   TIMESTAMPTZ NOT NULL DEFAULT now(),
  username     TEXT        NOT NULL,
  role         TEXT,
  allowed_tabs JSONB,
  machine_name TEXT,
  local_ip     TEXT,
  public_ip    TEXT,
  app_version  TEXT,
  client_os    TEXT,
  action       TEXT        NOT NULL,
  note         TEXT,
  source       TEXT,
  extra        JSONB
);
CREATE INDEX IF NOT EXISTS idx_audit_login_time     ON audit_login(event_time DESC);
CREATE INDEX IF NOT EXISTS idx_audit_login_username ON audit_login(username);
CREATE INDEX IF NOT EXISTS idx_audit_login_action   ON audit_login(action);

-- 2) licenses：授權碼
CREATE TABLE IF NOT EXISTS licenses (
  auth_code TEXT PRIMARY KEY,
  expiry    DATE    NOT NULL,
  remaining INTEGER NOT NULL,
  mac       TEXT
);

-- 3) bindings：每台機器綁一組授權碼
CREATE TABLE IF NOT EXISTS bindings (
  mac       TEXT PRIMARY KEY,
  auth_code TEXT NOT NULL REFERENCES licenses(auth_code)
);

-- 4) accounts：線上帳號登入
CREATE TABLE IF NOT EXISTS accounts (
  username     TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL,
  module        TEXT NOT NULL,
  active        BOOLEAN NOT NULL DEFAULT TRUE,
  expires_enc   TEXT,
  expires_at    DATE
);

-- 5) rbac_tabs：role → tabs
CREATE TABLE IF NOT EXISTS rbac_tabs (
  role_name TEXT PRIMARY KEY,
  tabs      JSONB NOT NULL
);

-- 6) rbac_modules：module → tabs
CREATE TABLE IF NOT EXISTS rbac_modules (
  module_name TEXT PRIMARY KEY,
  tabs        JSONB NOT NULL
);
"""

SQL_CREATE_ALL = """
-- 1) audit_login：登入/授權紀錄
CREATE TABLE IF NOT EXISTS audit_login (
  id           BIGSERIAL PRIMARY KEY,
  event_time   TIMESTAMPTZ NOT NULL DEFAULT now(),
  username     TEXT        NOT NULL,
  role         TEXT,
  allowed_tabs JSONB,
  machine_name TEXT,
  local_ip     TEXT,
  public_ip    TEXT,
  app_version  TEXT,
  client_os    TEXT,
  action       TEXT        NOT NULL,
  note         TEXT,
  source       TEXT,
  extra        JSONB
);
CREATE INDEX IF NOT EXISTS idx_audit_login_time     ON audit_login(event_time DESC);
CREATE INDEX IF NOT EXISTS idx_audit_login_username ON audit_login(username);
CREATE INDEX IF NOT EXISTS idx_audit_login_action   ON audit_login(action);

-- 2) licenses：授權碼
CREATE TABLE IF NOT EXISTS licenses (
  auth_code TEXT PRIMARY KEY,
  expiry    DATE    NOT NULL,
  remaining INTEGER NOT NULL,
  mac       TEXT
);

-- 3) bindings：每台機器綁一組授權碼
CREATE TABLE IF NOT EXISTS bindings (
  mac       TEXT PRIMARY KEY,
  auth_code TEXT NOT NULL REFERENCES licenses(auth_code)
);

-- 4) accounts：線上帳號登入
CREATE TABLE IF NOT EXISTS accounts (
  username     TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL,
  module        TEXT NOT NULL,
  active        BOOLEAN NOT NULL DEFAULT TRUE,
  expires_enc   TEXT,
  expires_at    DATE
);

-- 5) rbac_tabs：role → tabs
CREATE TABLE IF NOT EXISTS rbac_tabs (
  role_name TEXT PRIMARY KEY,
  tabs      JSONB NOT NULL
);

-- 6) rbac_modules：module → tabs
CREATE TABLE IF NOT EXISTS rbac_modules (
  module_name TEXT PRIMARY KEY,
  tabs        JSONB NOT NULL
);

-- 7) app_sessions：上線座位 / 連線狀態
CREATE TABLE IF NOT EXISTS app_sessions (
  id           BIGSERIAL PRIMARY KEY,
  app          TEXT NOT NULL DEFAULT 'INVIMB',
  seat         TEXT,                         -- 座位代號/名稱（需要就用，不需要可留空）
  session_id   TEXT NOT NULL UNIQUE,         -- 每次啟動/登入生成一個 UUID
  username     TEXT NOT NULL,
  machine_name TEXT,
  mac          TEXT,
  local_ip     TEXT,
  public_ip    TEXT,
  client_ver   TEXT,
  started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at     TIMESTAMPTZ,
  extra        JSONB
);

-- 常用索引：查「線上中」很快
CREATE INDEX IF NOT EXISTS idx_app_sessions_active
ON app_sessions(app, last_seen_at DESC)
WHERE ended_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_app_sessions_user
ON app_sessions(username, mac);

CREATE INDEX IF NOT EXISTS idx_app_sessions_seat
ON app_sessions(seat);
"""

def _get_dsn():
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL 未設定")
    if "sslmode=" not in dsn:
        dsn += ("&" if "?" in dsn else "?") + "sslmode=require"
    return dsn

def ensure_all_tables():
    """一次把 audit_login + licenses/bindings + accounts + rbac_* 都建好。"""
    dsn = _get_dsn()
    conn = psycopg2.connect(dsn)
    conn.autocommit = True
    with conn, conn.cursor() as cur:
        cur.execute(SQL_CREATE_ALL)
    conn.close()

# 兼容舊名稱：舊程式如果還呼叫 ensure_audit_login_table()，就當成 ensure_all_tables().
def ensure_audit_login_table():
    ensure_all_tables()
