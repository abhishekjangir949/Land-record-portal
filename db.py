import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "land_portal.db"


def normalize_phone(phone: str) -> str:
    digits = "".join(ch for ch in (phone or "") if ch.isdigit())
    if len(digits) > 10 and digits.startswith("91"):
        digits = digits[-10:]
    return digits


def get_db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, col_type: str):
    existing_cols = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in existing_cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        phone TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'officer',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS password_otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        identifier TEXT NOT NULL,
        user_email TEXT NOT NULL,
        otp_code TEXT NOT NULL,
        expires_at REAL NOT NULL,
        verified INTEGER NOT NULL DEFAULT 0,
        used INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS land_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        original_filename TEXT NOT NULL,
        stored_filename TEXT NOT NULL,
        file_type TEXT NOT NULL,
        sha256_hash TEXT NOT NULL,
        ocr_confidence REAL NOT NULL DEFAULT 0,
        raw_ocr_text TEXT DEFAULT '',
        owner_name TEXT DEFAULT '',
        father_name TEXT DEFAULT '',
        survey_number TEXT DEFAULT '',
        khasra_number TEXT DEFAULT '',
        account_number TEXT DEFAULT '',
        village_name TEXT DEFAULT '',
        tehsil TEXT DEFAULT '',
        district TEXT DEFAULT '',
        land_area TEXT DEFAULT '',
        land_type TEXT DEFAULT '',
        ownership_details TEXT DEFAULT '',
        mutation_details TEXT DEFAULT '',
        registration_details TEXT DEFAULT '',
        uncertain_fields TEXT DEFAULT '',
        health_score INTEGER NOT NULL DEFAULT 0,
        duplicate_of_id INTEGER,
        conflict_with_id INTEGER,
        status TEXT NOT NULL DEFAULT 'Needs Review',
        submitted_by TEXT DEFAULT '',
        submitted_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Safe schema migration for existing SQLite DBs
    migrations = [
        ("users", "role", "TEXT NOT NULL DEFAULT 'officer'"),
        ("land_records", "survey_number", "TEXT DEFAULT ''"),
        ("land_records", "ownership_details", "TEXT DEFAULT ''"),
        ("land_records", "mutation_details", "TEXT DEFAULT ''"),
        ("land_records", "registration_details", "TEXT DEFAULT ''"),
        ("land_records", "uncertain_fields", "TEXT DEFAULT ''"),
        ("land_records", "conflict_with_id", "INTEGER"),
        ("land_records", "submitted_by", "TEXT DEFAULT ''"),
        ("land_records", "submitted_at", "TIMESTAMP"),
    ]
    for tbl, col, ctype in migrations:
        _ensure_column(conn, tbl, col, ctype)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT,
        action TEXT NOT NULL,
        details TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    demo_email = "officer@landportal.local"
    demo_phone = "9876543210"
    exists = cur.execute(
        "SELECT id FROM users WHERE email = ? OR phone = ?", (demo_email, demo_phone)
    ).fetchone()
    if not exists:
        cur.execute(
            """INSERT INTO users (full_name, email, phone, password_hash, role)
               VALUES (?, ?, ?, ?, ?)""",
            (
                "Land Record Officer",
                demo_email,
                demo_phone,
                generate_password_hash("Land@1234"),
                "officer",
            ),
        )

    conn.commit()
    conn.close()