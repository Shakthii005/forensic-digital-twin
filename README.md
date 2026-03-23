# 🛡️ Forensic Digital Twin Platform — SaaS Edition

**Real-Time IoT Security Monitoring | Multi-User | MQTT Support**

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run
streamlit run app.py

# 3. Open browser
# http://localhost:8501
```

### Default Login
| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `admin123` |

---

## 👥 User Roles

| Role | Permissions |
|------|------------|
| **Admin** | Everything — manage users, devices, simulate attacks, export evidence |
| **Analyst** | View dashboard, simulate attacks, export evidence |
| **Viewer** | View dashboard only — read-only access |

---

## 📡 Connecting Real IoT Devices (MQTT)

### Step 1 — Configure broker in config.py
```python
MQTT_BROKER = "your-broker-host"   # e.g. "192.168.1.100" or "broker.hivemq.com"
MQTT_PORT   = 1883
```

### Or use environment variables
```bash
export FDTP_MQTT_BROKER=192.168.1.100
export FDTP_MQTT_PORT=1883
export FDTP_MQTT_USER=youruser      # optional
export FDTP_MQTT_PASS=yourpassword  # optional
streamlit run app.py
```

### Step 2 — Device sends JSON to topic
**Topic:** `fdtp/devices/{device_id}`

**Payload:**
```json
{
  "device_id"  : "IoT_1",
  "temp"       : 28.3,
  "humidity"   : 54.1,
  "state"      : "ACTIVE",
  "timestamp"  : "2026-03-21T07:24:01+00:00",
  "nonce"      : "uuid4-string",
  "hash"       : "sha256-hex-or-simulated",
  "signature"  : "rsa-hex-or-simulated"
}
```

### Step 3 — Minimal Python device script
```python
import paho.mqtt.client as mqtt
import json, uuid, time
from datetime import datetime, timezone

client = mqtt.Client()
client.connect("your-broker", 1883)

while True:
    payload = {
        "device_id": "IoT_1",
        "temp": 28.3,
        "humidity": 54.1,
        "state": "ACTIVE",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nonce": str(uuid.uuid4()),
        "hash": "simulated",
        "signature": "simulated"
    }
    client.publish("fdtp/devices/IoT_1", json.dumps(payload))
    time.sleep(2)
```

### Free MQTT Brokers for Testing
- `broker.hivemq.com` (port 1883) — free public broker
- `test.mosquitto.org` (port 1883) — free public broker
- Install locally: `sudo apt install mosquitto`

---

## 🔧 Configuration Reference

Edit `config.py`:

```python
MQTT_BROKER          = "localhost"    # Broker hostname/IP
MQTT_PORT            = 1883           # Default MQTT port
NONCE_WINDOW_SEC     = 120            # Replay detection window
ZSCORE_THRESHOLD     = 3.0            # Anomaly sensitivity
RATE_OF_CHANGE_LIMIT = 8.0            # Max °C change per reading
LSTM_ANOMALY_MULT    = 2.8            # LSTM sensitivity
FINGERPRINT_Z_THRESH = 3.5            # Fingerprint sensitivity
REFRESH_INTERVAL     = 3              # Dashboard refresh (seconds)
```

---

## 🏗️ Architecture

```
forensic-dt-saas/
├── app.py              ← Main Streamlit app (6 pages + user management)
├── auth.py             ← Login, register, sessions, RBAC
├── config.py           ← Central configuration
├── database.py         ← SQLite (users, orgs, devices, telemetry)
├── mqtt_connector.py   ← Real device MQTT support
├── simulator.py        ← IoT simulator (fallback)
├── twin.py             ← Digital twin engine
├── forensic.py         ← 8-layer detection engine
├── threat_score.py     ← Composite 0-100 threat scoring
├── lstm_detector.py    ← Per-device LSTM AI (online learning)
├── fingerprint.py      ← Behavioral device fingerprinting
├── attacks.py          ← Attack simulation
├── evidence_export.py  ← SHA-256 sealed forensic PDF
└── requirements.txt
```

---

## 🔐 8 Detection Layers

| Layer | Method | Detects |
|-------|--------|---------|
| L1 | RSA-PSS Signature | Fake/forged packets |
| L2 | Nonce Replay Shield | Replay attacks |
| L3 | Blockchain Hash Chain | Data tampering |
| L4 | Z-Score Anomaly | Sudden spikes |
| L5 | Twin Divergence | Sensor spoofing |
| L6 | LSTM Behavioral AI | Gradual manipulation |
| L7 | Device Fingerprinting | Cloned devices |
| L8 | Forensic Log Chain | Log tampering |

---

## 🌐 Deploy Online (Streamlit Cloud)

1. Push to GitHub
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Connect your repo
4. Set secrets in Streamlit Cloud dashboard:
   - `FDTP_MQTT_BROKER`
   - `FDTP_MQTT_PORT`
   - `FDTP_SECRET`

---

## 📄 Patent Claims

This platform supports 5 novel patent claims:
1. Composite weighted forensic scoring for IoT packet verification
2. Device-specific LSTM online learning for digital twin anomaly detection
3. Behavioral fingerprint-based IoT device identity verification
4. Automated tamper-evident forensic evidence package generation
5. Multi-layer cryptographic IoT digital twin integrity verification
