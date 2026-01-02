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
  username      TEXT PRIMARY KEY,
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

-- 7) app_sessions：上線/連線狀態（線上清單靠 last_seen_at + ended_at）
CREATE TABLE IF NOT EXISTS app_sessions (
  id            BIGSERIAL PRIMARY KEY,
  app           TEXT NOT NULL DEFAULT 'INVIMB',
  seat          TEXT,                          -- 座位代號/名稱（可選）
  session_id    UUID NOT NULL UNIQUE,          -- 每次登入/啟動產生 UUID（用它當 API key 最穩）
  username      TEXT NOT NULL,
  role          TEXT,                          -- ✅ 你要篩 role/module 就要有欄位
  module        TEXT,
  machine_name  TEXT,
  mac           TEXT,
  local_ip      TEXT,
  public_ip     TEXT,
  client_ver    TEXT,
  user_agent    TEXT,
  started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at      TIMESTAMPTZ,
  ended_reason  TEXT,                          -- ✅ 踢下線/正常離開原因
  extra         JSONB
);

-- 查線上：ended_at IS NULL + last_seen_at 最近
CREATE INDEX IF NOT EXISTS idx_app_sessions_active
ON app_sessions(app, last_seen_at DESC)
WHERE ended_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_app_sessions_user
ON app_sessions(username, mac);

CREATE INDEX IF NOT EXISTS idx_app_sessions_seat
ON app_sessions(seat);

CREATE INDEX IF NOT EXISTS idx_app_sessions_last_seen
ON app_sessions(last_seen_at DESC);

-- 8) app_settings：線上判定秒數 / 上線限制
CREATE TABLE IF NOT EXISTS app_settings (
  key   TEXT PRIMARY KEY,
  value JSONB NOT NULL
);
"""

def _get_dsn():
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL 未設定")
    if "sslmode=" not in dsn:
        dsn += ("&" if "?" in dsn else "?") + "sslmode=require"
    return dsn

SQL_PATCH = """
-- accounts 補欄位
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS expires_enc TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS expires_at  DATE;

-- app_sessions 補欄位
ALTER TABLE app_sessions ADD COLUMN IF NOT EXISTS role         TEXT;
ALTER TABLE app_sessions ADD COLUMN IF NOT EXISTS module       TEXT;
ALTER TABLE app_sessions ADD COLUMN IF NOT EXISTS user_agent   TEXT;
ALTER TABLE app_sessions ADD COLUMN IF NOT EXISTS ended_reason TEXT;

-- app_settings 也補（保險）
CREATE TABLE IF NOT EXISTS app_settings (
  key   TEXT PRIMARY KEY,
  value JSONB NOT NULL
);
"""

def ensure_all_tables():
    dsn = _get_dsn()
    conn = psycopg2.connect(dsn)
    conn.autocommit = True
    with conn, conn.cursor() as cur:
        cur.execute(SQL_CREATE_ALL)
        cur.execute(SQL_PATCH)   # ✅ 補洞
    conn.close()

# ✅ 兼容舊名稱：舊程式如果還呼叫 ensure_audit_login_table()，就當成 ensure_all_tables().
def ensure_audit_login_table():
    ensure_all_tables()

# ✅ 可選：如果你想保留 ensure_sessions_tables(conn) 這個名字，就做「補洞」而不是重建另一份 schema
def ensure_sessions_tables(conn):
    """
    只做補洞（ALTER TABLE ADD COLUMN IF NOT EXISTS），避免跟 SQL_CREATE_ALL 互打。
    """
    with conn.cursor() as cur:
        # 補 app_settings
        cur.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key   TEXT PRIMARY KEY,
            value JSONB NOT NULL
        );
        """)

        # 補 app_sessions 欄位（就算已存在也不會炸）
        cur.execute("ALTER TABLE app_sessions ADD COLUMN IF NOT EXISTS role TEXT;")
        cur.execute("ALTER TABLE app_sessions ADD COLUMN IF NOT EXISTS module TEXT;")
        cur.execute("ALTER TABLE app_sessions ADD COLUMN IF NOT EXISTS user_agent TEXT;")
        cur.execute("ALTER TABLE app_sessions ADD COLUMN IF NOT EXISTS ended_reason TEXT;")

        conn.commit()
