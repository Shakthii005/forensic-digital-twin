"""
database.py — SQLite persistence layer
Tables: users, organizations, sessions, device_data, logs, alerts, twin_state, devices
"""

import sqlite3
import threading
import hashlib
import os
from datetime import datetime, timezone
DB_PATH = "logs.db"
#from config import DB_PATH

_lock = threading.Lock()


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with _lock:
        conn = get_conn()
        c = conn.cursor()

        # ── Auth tables ───────────────────────────────────────────────────────
        c.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    UNIQUE NOT NULL,
                plan        TEXT    DEFAULT 'free',
                created_at  TEXT    NOT NULL
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id       INTEGER NOT NULL REFERENCES organizations(id),
                username     TEXT    UNIQUE NOT NULL,
                email        TEXT    UNIQUE NOT NULL,
                password_hash TEXT   NOT NULL,
                role         TEXT    NOT NULL DEFAULT 'analyst',
                full_name    TEXT,
                is_active    INTEGER DEFAULT 1,
                created_at   TEXT    NOT NULL,
                last_login   TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token       TEXT    PRIMARY KEY,
                user_id     INTEGER NOT NULL REFERENCES users(id),
                created_at  TEXT    NOT NULL,
                expires_at  TEXT    NOT NULL,
                ip_address  TEXT
            )
        """)

        # ── Devices ───────────────────────────────────────────────────────────
        c.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id       INTEGER NOT NULL REFERENCES organizations(id),
                device_id    TEXT    NOT NULL,
                name         TEXT,
                location     TEXT,
                source       TEXT    DEFAULT 'simulator',
                mqtt_topic   TEXT,
                is_active    INTEGER DEFAULT 1,
                registered_at TEXT   NOT NULL,
                UNIQUE(org_id, device_id)
            )
        """)

        # ── Telemetry ─────────────────────────────────────────────────────────
        c.execute("""
            CREATE TABLE IF NOT EXISTS device_data (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id       INTEGER NOT NULL,
                device_id    TEXT    NOT NULL,
                temp         REAL    NOT NULL,
                humidity     REAL    NOT NULL,
                device_state TEXT    NOT NULL,
                timestamp    TEXT    NOT NULL,
                nonce        TEXT    NOT NULL,
                hash         TEXT    NOT NULL,
                signature    TEXT,
                is_attack    INTEGER DEFAULT 0,
                source       TEXT    DEFAULT 'simulator'
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id      INTEGER NOT NULL,
                device_id   TEXT    NOT NULL,
                event_type  TEXT    NOT NULL,
                description TEXT    NOT NULL,
                hash_chain  TEXT    NOT NULL,
                timestamp   TEXT    NOT NULL
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id      INTEGER NOT NULL,
                device_id   TEXT    NOT NULL,
                attack_type TEXT    NOT NULL,
                severity    TEXT    NOT NULL,
                detail      TEXT,
                timestamp   TEXT    NOT NULL
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS twin_state (
                org_id       INTEGER NOT NULL,
                device_id    TEXT    NOT NULL,
                temp         REAL,
                humidity     REAL,
                device_state TEXT,
                last_hash    TEXT,
                last_nonce   TEXT,
                updated_at   TEXT,
                PRIMARY KEY (org_id, device_id)
            )
        """)

        conn.commit()

        # Seed default org + admin if empty
        c.execute("SELECT COUNT(*) FROM organizations")
        if c.fetchone()[0] == 0:
            _seed_defaults(c)
            conn.commit()

        conn.close()


def _seed_defaults(c):
    now = datetime.now(timezone.utc).isoformat()
    c.execute("INSERT INTO organizations (name, plan, created_at) VALUES (?,?,?)",
              ("Default Organization", "free", now))
    org_id = c.lastrowid
    pw_hash = _hash_password("admin123")
    c.execute("""
        INSERT INTO users (org_id, username, email, password_hash, role, full_name, created_at)
        VALUES (?,?,?,?,?,?,?)
    """, (org_id, "admin", "admin@fdtp.local", pw_hash, "admin", "Administrator", now))
    # After seeding defaults, add this:
def clean_duplicate_devices(org_id: int):
    with _lock:
        conn = get_conn()
        conn.execute("""
            DELETE FROM devices 
            WHERE org_id=? AND source='simulator'
            AND device_id IN (
                SELECT device_id FROM devices 
                WHERE org_id=? AND source='mqtt'
            )
        """, (org_id, org_id))
        conn.commit()
        conn.close()

def _hash_password(password: str) -> str:
    import hashlib, os
    salt = os.urandom(32)
    key  = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 310000)
    return salt.hex() + ":" + key.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, key_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        key  = bytes.fromhex(key_hex)
        new_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 310000)
        return new_key == key
    except Exception:
        return False


# ── AUTH ──────────────────────────────────────────────────────────────────────

def get_user_by_username(username: str):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND is_active=1", (username,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id: int):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def create_session(user_id: int, ip: str = None) -> str:
    import secrets
    from datetime import timedelta
    from config import SESSION_TIMEOUT
    with _lock:
        token      = secrets.token_urlsafe(32)
        now        = datetime.now(timezone.utc)
        expires_at = (now + timedelta(seconds=SESSION_TIMEOUT)).isoformat()
        conn = get_conn()
        conn.execute("INSERT INTO sessions (token, user_id, created_at, expires_at, ip_address) VALUES (?,?,?,?,?)",
                     (token, user_id, now.isoformat(), expires_at, ip))
        conn.execute("UPDATE users SET last_login=? WHERE id=?", (now.isoformat(), user_id))
        conn.commit()
        conn.close()
        return token


def get_session(token: str):
    conn = get_conn()
    c = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    c.execute("SELECT * FROM sessions WHERE token=? AND expires_at > ?", (token, now))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def delete_session(token: str):
    with _lock:
        conn = get_conn()
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()
        conn.close()


def register_user(org_id: int, username: str, email: str, password: str,
                  role: str = "analyst", full_name: str = "") -> dict:
    with _lock:
        now  = datetime.now(timezone.utc).isoformat()
        pw_h = _hash_password(password)
        try:
            conn = get_conn()
            conn.execute("""
                INSERT INTO users (org_id, username, email, password_hash, role, full_name, created_at)
                VALUES (?,?,?,?,?,?,?)
            """, (org_id, username, email, pw_h, role, full_name, now))
            conn.commit()
            conn.close()
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}


def get_all_users(org_id: int):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id,username,email,role,full_name,is_active,created_at,last_login FROM users WHERE org_id=?", (org_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def toggle_user(user_id: int, active: bool):
    with _lock:
        conn = get_conn()
        conn.execute("UPDATE users SET is_active=? WHERE id=?", (1 if active else 0, user_id))
        conn.commit()
        conn.close()


# ── DEVICES ───────────────────────────────────────────────────────────────────

def register_device(org_id: int, device_id: str, name: str, location: str,
                    source: str = "simulator", mqtt_topic: str = None):
    with _lock:
        now = datetime.now(timezone.utc).isoformat()
        try:
            conn = get_conn()
            conn.execute("""
                INSERT OR IGNORE INTO devices
                (org_id, device_id, name, location, source, mqtt_topic, registered_at)
                VALUES (?,?,?,?,?,?,?)
            """, (org_id, device_id, name, location, source, mqtt_topic, now))
            conn.commit()
            conn.close()
        except Exception:
            pass


def get_devices(org_id: int):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM devices WHERE org_id=? AND is_active=1", (org_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


# ── TELEMETRY ─────────────────────────────────────────────────────────────────

def insert_device_data(row: dict) -> int:
    with _lock:
        conn = get_conn()
        c = conn.cursor()
        c.execute("""
            INSERT INTO device_data
                (org_id, device_id, temp, humidity, device_state, timestamp, nonce, hash, signature, is_attack, source)
            VALUES
                (:org_id, :device_id, :temp, :humidity, :device_state, :timestamp, :nonce, :hash, :signature, :is_attack, :source)
        """, row)
        conn.commit()
        rid = c.lastrowid
        conn.close()
        return rid


def fetch_device_data(org_id: int, device_id: str = None, limit: int = 300):
    conn = get_conn()
    c = conn.cursor()
    if device_id:
        c.execute("SELECT * FROM device_data WHERE org_id=? AND device_id=? ORDER BY id DESC LIMIT ?",
                  (org_id, device_id, limit))
    else:
        c.execute("SELECT * FROM device_data WHERE org_id=? ORDER BY id DESC LIMIT ?", (org_id, limit))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def insert_log(row: dict):
    with _lock:
        conn = get_conn()
        conn.execute("""
            INSERT INTO logs (org_id, device_id, event_type, description, hash_chain, timestamp)
            VALUES (:org_id, :device_id, :event_type, :description, :hash_chain, :timestamp)
        """, row)
        conn.commit()
        conn.close()


def fetch_logs(org_id: int, limit: int = 300):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM logs WHERE org_id=? ORDER BY id DESC LIMIT ?", (org_id, limit))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def insert_alert(row: dict):
    with _lock:
        conn = get_conn()
        conn.execute("""
            INSERT INTO alerts (org_id, device_id, attack_type, severity, detail, timestamp)
            VALUES (:org_id, :device_id, :attack_type, :severity, :detail, :timestamp)
        """, row)
        conn.commit()
        conn.close()


def fetch_alerts(org_id: int, limit: int = 300):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM alerts WHERE org_id=? ORDER BY id DESC LIMIT ?", (org_id, limit))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def upsert_twin(org_id: int, device_id: str, state: dict):
    with _lock:
        conn = get_conn()
        conn.execute("""
            INSERT INTO twin_state (org_id, device_id, temp, humidity, device_state, last_hash, last_nonce, updated_at)
            VALUES (:org_id, :device_id, :temp, :humidity, :device_state, :last_hash, :last_nonce, :updated_at)
            ON CONFLICT(org_id, device_id) DO UPDATE SET
                temp=excluded.temp, humidity=excluded.humidity,
                device_state=excluded.device_state, last_hash=excluded.last_hash,
                last_nonce=excluded.last_nonce, updated_at=excluded.updated_at
        """, {"org_id": org_id, "device_id": device_id, **state})
        conn.commit()
        conn.close()


def fetch_all_twins(org_id: int):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM twin_state WHERE org_id=?", (org_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows
