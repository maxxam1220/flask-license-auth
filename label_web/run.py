import os
import argparse
import configparser
from pathlib import Path
from waitress import serve
from server import create_app

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--existing-database", action="store_true", help="Use the PostgreSQL connection from the parent label system config.ini")
    args = parser.parse_args()
    host = os.environ.get("LABELCHECK_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5083"))
    if host not in {"127.0.0.1", "localhost", "::1"} and len(os.environ.get("LABELCHECK_PASSWORD", "")) < 12:
        raise SystemExit("遠端使用請先設定至少 12 字元的 LABELCHECK_PASSWORD。")
    config = {}
    if args.existing_database:
        settings = configparser.ConfigParser(interpolation=None)
        settings.read(Path(__file__).resolve().parent.parent / "config.ini", encoding="utf-8-sig")
        url = settings.get("postgres", "database_url", fallback="")
        if not url.startswith(("postgresql://", "postgres://")):
            raise SystemExit("找不到原標籤系統的 PostgreSQL 設定。")
        config["DATABASE_URL"] = url
    if os.environ.get("RENDER") and (not os.environ.get("LABELCHECK_DATA_DIR") or not os.environ.get("LABELCHECK_DATABASE_URL")):
        raise SystemExit("Render 啟動前必須設定持久照片目錄及既有 PostgreSQL 連線。")
    application = create_app(config)
    print(f"Label check: http://{host}:{port}", flush=True)
    serve(application, host=host, port=port, threads=6, max_request_body_size=16 * 1024 * 1024)
