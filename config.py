"""
config.py — Central configuration for Forensic Digital Twin SaaS Platform
Edit these values to configure your deployment.
"""

import os

# ── Application ───────────────────────────────────────────────────────────────
APP_NAME        = "Forensic Digital Twin Platform"
APP_VERSION     = "2.0.0"
APP_TAGLINE     = "Real-Time IoT Security & Forensic Intelligence"

# ── Database ──────────────────────────────────────────────────────────────────
DB_PATH = os.environ.get("FDTP_DB_PATH", "/tmp/fdtp.db")

# ── Auth ──────────────────────────────────────────────────────────────────────
SECRET_KEY      = os.environ.get("FDTP_SECRET", "fdtp-secret-change-in-production")
SESSION_TIMEOUT = 3600   # seconds (1 hour)
BCRYPT_ROUNDS   = 12

# ── MQTT ──────────────────────────────────────────────────────────────────────
MQTT_BROKER     = os.environ.get("FDTP_MQTT_BROKER", "broker.hivemq.com")
MQTT_PORT       = int(os.environ.get("FDTP_MQTT_PORT", "1883"))
MQTT_USERNAME   = os.environ.get("FDTP_MQTT_USER", "")
MQTT_PASSWORD   = os.environ.get("FDTP_MQTT_PASS", "")
MQTT_TOPIC_BASE = "fdtp/devices"          # devices publish to fdtp/devices/{device_id}
MQTT_TLS        = os.environ.get("FDTP_MQTT_TLS", "false").lower() == "true"

# ── Simulator ─────────────────────────────────────────────────────────────────
SIM_INTERVAL    = 2.0    # seconds between simulated packets
SIM_DEVICES     = {
    "IoT_1": {"base_temp": 28.0, "base_humidity": 55.0, "location": "Server Room A"},
    "IoT_2": {"base_temp": 22.0, "base_humidity": 45.0, "location": "Lab B"},
    "IoT_3": {"base_temp": 35.0, "base_humidity": 70.0, "location": "Outdoor Unit"},
}

# ── Forensic thresholds ───────────────────────────────────────────────────────
NONCE_WINDOW_SEC       = 120
ZSCORE_THRESHOLD       = 3.0
RATE_OF_CHANGE_LIMIT   = 8.0
ANOMALY_WINDOW         = 20
LSTM_ANOMALY_MULT      = 2.8
FINGERPRINT_MIN_SAMPLES= 30
FINGERPRINT_Z_THRESH   = 3.5

# ── User roles ────────────────────────────────────────────────────────────────
ROLE_ADMIN   = "admin"
ROLE_ANALYST = "analyst"
ROLE_VIEWER  = "viewer"

ROLE_PERMISSIONS = {
    ROLE_ADMIN:   ["view", "simulate_attacks", "manage_users", "export_evidence", "manage_devices"],
    ROLE_ANALYST: ["view", "simulate_attacks", "export_evidence"],
    ROLE_VIEWER:  ["view"],
}

# ── Dashboard ─────────────────────────────────────────────────────────────────
REFRESH_INTERVAL = 3     # seconds
MAX_CHART_POINTS = 100
MAX_TABLE_ROWS   = 200
