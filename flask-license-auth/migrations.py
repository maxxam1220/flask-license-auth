# migrations.py
import os, psycopg2
from psycopg2.extras import register_default_jsonb

SQL_CREATE_AUDIT_LOGIN = """
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
"""

def ensure_audit_login_table():
    dsn = os.environ["AUDIT_DB_DSN"]   # 你後端原本就有設（連 Internal DB URL）
    # e.g. postgresql://user:pass@<internal-host>:5432/license_db_0830?sslmode=require
    conn = psycopg2.connect(dsn)
    conn.autocommit = True
    with conn, conn.cursor() as cur:
        cur.execute(SQL_CREATE_AUDIT_LOGIN)
    conn.close()
