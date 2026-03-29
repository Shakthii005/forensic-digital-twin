"""
mqtt_connector.py — Real IoT Device Support via MQTT
Connects to an MQTT broker to receive real sensor data.
Automatically falls back to simulation if broker is unavailable.

Real device payload format (JSON):
{
  "device_id": "IoT_1",
  "temp": 28.3,
  "humidity": 54.1,
  "state": "ACTIVE",
  "timestamp": "2026-03-21T07:24:01+00:00",
  "nonce": "uuid-string",
  "hash": "sha256-hex",
  "signature": "rsa-hex"
}
"""

import json
import threading
import hashlib
import uuid
import time
from datetime import datetime, timezone
from typing import Callable, Optional
from config import (MQTT_BROKER, MQTT_PORT, MQTT_USERNAME, MQTT_PASSWORD,
                    MQTT_TOPIC_BASE, MQTT_TLS, SIM_DEVICES)


# ── Connection status ─────────────────────────────────────────────────────────

class MQTTStatus:
    DISCONNECTED = "disconnected"
    CONNECTING   = "connecting"
    CONNECTED    = "connected"
    ERROR        = "error"


class MQTTConnector:
    """
    Manages MQTT connection for real IoT devices.
    Falls back to simulation gracefully when broker unavailable.
    """

    def __init__(self, org_id: int, on_packet: Callable):
        self.org_id      = org_id
        self.on_packet   = on_packet
        self.status      = MQTTStatus.DISCONNECTED
        self.error_msg   = ""
        self._client     = None
        self._lock       = threading.Lock()
        self._subscribed_topics = set()

    # ── Connect ───────────────────────────────────────────────────────────────

    def connect(self) -> bool:
        """
        Attempt MQTT broker connection.
        Returns True if connected, False if unavailable (use simulation).
        """
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            self.status    = MQTTStatus.ERROR
            self.error_msg = "paho-mqtt not installed. Run: pip install paho-mqtt"
            return False

        self.status = MQTTStatus.CONNECTING

        client = mqtt.Client(client_id=f"fdtp-{self.org_id}-{uuid.uuid4().hex[:8]}")
        transport="websockets" 

        if MQTT_USERNAME:
            client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)

        if MQTT_TLS:
            client.tls_set()
        client.ws_set_options(path="/mqtt")
        client.on_connect    = self._on_connect
        client.on_disconnect = self._on_disconnect
        client.on_message    = self._on_message

        try:
            client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
            client.loop_start()
            self._client = client

            # Wait up to 5 seconds for connection
            for _ in range(50):
                if self.status == MQTTStatus.CONNECTED:
                    return True
                time.sleep(0.1)

            self.status    = MQTTStatus.ERROR
            self.error_msg = f"Timeout connecting to {MQTT_BROKER}:{MQTT_PORT}"
            client.loop_stop()
            return False

        except Exception as e:
            self.status    = MQTTStatus.ERROR
            self.error_msg = str(e)
            return False

    def disconnect(self):
        if self._client:
            self._client.loop_stop()
            self._client.disconnect()
        self.status = MQTTStatus.DISCONNECTED

    # ── Subscribe to device topics ────────────────────────────────────────────

    def subscribe_device(self, device_id: str):
        """Subscribe to a specific device's MQTT topic."""
        topic = f"{MQTT_TOPIC_BASE}/{device_id}"
        if self._client and self.status == MQTTStatus.CONNECTED:
            self._client.subscribe(topic, qos=1)
            self._subscribed_topics.add(topic)

    def subscribe_all(self):
        """Subscribe to all devices wildcard."""
        topic = f"{MQTT_TOPIC_BASE}/+"
        if self._client and self.status == MQTTStatus.CONNECTED:
            self._client.subscribe(topic, qos=1)

    # ── MQTT callbacks ────────────────────────────────────────────────────────

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.status    = MQTTStatus.CONNECTED
            self.error_msg = ""
            self.subscribe_all()
        else:
            codes = {1:"Wrong protocol", 2:"Client ID rejected", 3:"Broker unavailable",
                     4:"Bad credentials", 5:"Not authorized"}
            self.status    = MQTTStatus.ERROR
            self.error_msg = codes.get(rc, f"Connection refused (code {rc})")

    def _on_disconnect(self, client, userdata, rc):
        self.status = MQTTStatus.DISCONNECTED
        if rc != 0:
            self.error_msg = "Unexpected disconnection"

    def _on_message(self, client, userdata, msg):
        """Process arriving MQTT message with full validation."""
        try:
            payload = json.loads(msg.payload.decode("utf-8"))

            # Validate required fields
            required = {"device_id","temp","humidity","timestamp","nonce","hash","signature"}
            if not required.issubset(payload.keys()):
                return

            # ESP32/DHT22 sensor range validation
            temp = payload.get("temp")
            humidity = payload.get("humidity")
            
            # DHT22: temp -40°C to 80°C, humidity 0-100%
            if not isinstance(temp, (int, float)) or not (-40 <= temp <= 80):
                return  # Invalid temperature range
            if not isinstance(humidity, (int, float)) or not (0 <= humidity <= 100):
                return  # Invalid humidity range

            # Validate timestamp format
            try:
                datetime.fromisoformat(payload["timestamp"].replace('Z', '+00:00'))
            except Exception:
                return

            # Validate nonce is non-empty string
            if not isinstance(payload.get("nonce"), str) or len(payload["nonce"]) < 8:
                return

            # Add source tag
            payload["source"] = "mqtt"
            payload["state"]  = payload.get("state", "ACTIVE")

            if self.on_packet:
                self.on_packet(payload)

        except json.JSONDecodeError:
            # Silently ignore malformed JSON
            pass
        except Exception:
            # Ignore any other processing errors
            pass


# ── MQTT Device Registration Helper ──────────────────────────────────────────

def get_mqtt_setup_instructions(device_id: str) -> str:
    """Returns setup instructions for connecting a real device."""
    topic = f"{MQTT_TOPIC_BASE}/{device_id}"
    return f"""
# Real Device MQTT Setup — {device_id}

## 1. Install MQTT library on your device
pip install paho-mqtt  # Python
# or use Arduino/ESP32 PubSubClient library

## 2. Broker connection
Broker Host : {MQTT_BROKER}
Port        : {MQTT_PORT}
Topic       : {topic}

## 3. Payload format (JSON)
{{
  "device_id"  : "{device_id}",
  "temp"       : 28.3,
  "humidity"   : 54.1,
  "state"      : "ACTIVE",
  "timestamp"  : "2026-03-21T07:24:01+00:00",
  "nonce"      : "<uuid4>",
  "hash"       : "<sha256-hex>",
  "signature"  : "<rsa-pss-hex>"
}}

## 4. Minimal Python example (no signing)
import paho.mqtt.client as mqtt, json, uuid
from datetime import datetime, timezone

client = mqtt.Client()
client.connect("{MQTT_BROKER}", {MQTT_PORT})

payload = {{
    "device_id": "{device_id}",
    "temp": 28.3, "humidity": 54.1, "state": "ACTIVE",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "nonce": str(uuid.uuid4()),
    "hash": "simulated", "signature": "simulated"
}}
client.publish("{topic}", json.dumps(payload))
"""


def validate_esp32_payload(payload: dict) -> tuple:
    """
    Validate an ESP32/DHT22 sensor payload.
    Returns (is_valid: bool, error_msg: str)
    """
    # Check temp range (DHT22: -40 to 80°C)
    temp = payload.get("temp")
    if not isinstance(temp, (int, float)):
        return False, "temp must be numeric"
    if not (-40 <= temp <= 80):
        return False, f"temp {temp}°C outside DHT22 range [-40, 80]"

    # Check humidity range (DHT22: 0-100%)
    humidity = payload.get("humidity")
    if not isinstance(humidity, (int, float)):
        return False, "humidity must be numeric"
    if not (0 <= humidity <= 100):
        return False, f"humidity {humidity}% outside DHT22 range [0, 100]"

    # Check timestamp
    timestamp = payload.get("timestamp")
    if not isinstance(timestamp, str):
        return False, "timestamp must be ISO-8601 string"
    try:
        datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    except Exception:
        return False, f"timestamp '{timestamp}' not ISO-8601 format"

    # Check device_id
    device_id = payload.get("device_id")
    if not isinstance(device_id, str) or len(device_id) < 1:
        return False, "device_id must be non-empty string"

    return True, "OK"


# ── Hybrid manager ────────────────────────────────────────────────────────────

class DeviceManager:
    """
    Manages both real (MQTT) and simulated devices.
    Automatically uses simulation for devices without MQTT connection.
    Supports ESP32 + DHT22 real sensor telemetry via MQTT.
    """

    def __init__(self, org_id: int, on_packet: Callable):
        self.org_id      = org_id
        self.on_packet   = on_packet
        self.mqtt        = MQTTConnector(org_id, on_packet)
        self.using_mqtt  = False
        self._tried_mqtt = False

    def start(self) -> dict:
        """
        Attempt MQTT connection.
        Returns status dict with connection info.
        """
        self._tried_mqtt = True
        connected = self.mqtt.connect()

        if connected:
            self.using_mqtt = True
            return {
                "mode":    "mqtt",
                "status":  "connected",
                "broker":  f"{MQTT_BROKER}:{MQTT_PORT}",
                "message": f"Connected to MQTT broker at {MQTT_BROKER}:{MQTT_PORT}. Listening for real device data.",
            }
        else:
            self.using_mqtt = False
            return {
                "mode":    "simulation",
                "status":  "simulation",
                "error":   self.mqtt.error_msg,
                "message": "MQTT broker not available. Running in simulation mode.",
            }

    def get_status(self) -> dict:
        if not self._tried_mqtt:
            return {"mode": "not_started"}
        if self.using_mqtt:
            return {"mode": "mqtt", "status": self.mqtt.status, "broker": f"{MQTT_BROKER}:{MQTT_PORT}"}
        return {"mode": "simulation", "status": "running", "error": self.mqtt.error_msg}

    def stop(self):
        if self.using_mqtt:
            self.mqtt.disconnect()
