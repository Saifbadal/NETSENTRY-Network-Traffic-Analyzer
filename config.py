import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.environ.get("NTA_SECRET_KEY", "change-this-development-key-before-deployment")
    DATABASE = str(BASE_DIR / "instance" / "nta.sqlite3")
    UPLOAD_FOLDER = str(BASE_DIR / "uploads")
    REPORT_FOLDER = str(BASE_DIR / "reports")
    MODEL_FOLDER = str(BASE_DIR / "ml_models")
    MAX_CONTENT_LENGTH = 32 * 1024 * 1024  # 32 MB PCAP upload limit
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
