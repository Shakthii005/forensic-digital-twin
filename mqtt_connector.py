"""
mqtt_connector.py — Real IoT Device Support via MQTT
Connects to broker.hivemq.com:1883 (standard MQTT, no TLS)
ESP32 also connects to same broker on port 1883
Both communicate through HiveMQ as the shared broker
"""

import json
import threading
import uuid
import time
from datetime import datetime, timezone
from typing import Callable, Optional
from config import (MQTT_BROKER, MQTT_PORT, MQTT_USERNAME, MQTT_PASSWORD,
                    MQTT_TOPIC_BASE, SIM_DEVICES)


class MQTTStatus:
    DISCONNECTED = "disconnected"
    CONNECTING   = "connecting"
    CONNECTED    = "connected"
    ERROR        = "error"


class MQTTConnector:
    def __init__(self, org_id: int, on_packet: Callable):
        self.org_id    = org_id
        self.on_packet = on_packet
        self.status    = MQTTStatus.DISCONNECTED
        self.error_msg = ""
        self._client   = None

    def connect(self) -> bool:
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            self.status    = MQTTStatus.ERROR
            self.error_msg = "paho-mqtt not installed"
            return False

        self.status = MQTTStatus.CONNECTING

        # Standard MQTT client — no WebSocket, no TLS
        # Port 1883 works both locally and matches ESP32
        client = mqtt.Client(
            client_id=f"fdtp-{self.org_id}-{uuid.uuid4().hex[:8]}"
        )

        if MQTT_USERNAME:
            client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)

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

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.status    = MQTTStatus.CONNECTED
            self.error_msg = ""
            # Subscribe to all device topics
            topic = f"{MQTT_TOPIC_BASE}/+"
            client.subscribe(topic, qos=0)
            print(f"[MQTT] Connected to {MQTT_BROKER}:{MQTT_PORT}, subscribed to {topic}")
        else:
            codes = {1:"Wrong protocol", 2:"Client ID rejected",
                     3:"Broker unavailable", 4:"Bad credentials", 5:"Not authorized"}
            self.status    = MQTTStatus.ERROR
            self.error_msg = codes.get(rc, f"Connection refused (code {rc})")

    def _on_disconnect(self, client, userdata, rc):
        self.status = MQTTStatus.DISCONNECTED
        if rc != 0:
            self.error_msg = "Unexpected disconnection"

    def _on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            required = {"device_id", "temp", "humidity", "timestamp", "nonce", "hash", "signature"}
            if not required.issubset(payload.keys()):
                print(f"[MQTT] Missing fields in payload: {payload.keys()}")
                return
            payload["source"] = "mqtt"
            payload["state"]  = payload.get("state", "ACTIVE")
            print(f"[MQTT] Received from {payload['device_id']}: {payload['temp']}°C")
            if self.on_packet:
                self.on_packet(payload)
        except Exception as e:
            print(f"[MQTT] Message parse error: {e}")


class DeviceManager:
    def __init__(self, org_id: int, on_packet: Callable):
        self.org_id      = org_id
        self.on_packet   = on_packet
        self.mqtt        = MQTTConnector(org_id, on_packet)
        self.using_mqtt  = False
        self._tried_mqtt = False

    def start(self) -> dict:
        self._tried_mqtt = True
        connected = self.mqtt.connect()

        if connected:
            self.using_mqtt = True
            return {
                "mode":    "mqtt",
                "status":  "connected",
                "broker":  f"{MQTT_BROKER}:{MQTT_PORT}",
                "message": f"Connected to MQTT broker at {MQTT_BROKER}:{MQTT_PORT}",
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
            return {"mode": "mqtt", "status": self.mqtt.status,
                    "broker": f"{MQTT_BROKER}:{MQTT_PORT}"}
        return {"mode": "simulation", "status": "running", "error": self.mqtt.error_msg}

    def stop(self):
        if self.using_mqtt:
            self.mqtt.disconnect()


def get_mqtt_setup_instructions(device_id: str) -> str:
    topic = f"{MQTT_TOPIC_BASE}/{device_id}"
    return f"""
# Real Device MQTT Setup — {device_id}

## Broker connection
Broker Host : {MQTT_BROKER}
Port        : {MQTT_PORT}
Topic       : {topic}

## Payload format (JSON)
{{
  "device_id"  : "{device_id}",
  "temp"       : 28.3,
  "humidity"   : 54.1,
  "state"      : "ACTIVE",
  "timestamp"  : "2026-03-29T10:24:01+00:00",
  "nonce"      : "<uuid4>",
  "hash"       : "simulated",
  "signature"  : "simulated"
}}

## ESP32 Arduino settings
const char* MQTT_HOST  = "{MQTT_BROKER}";
const int   MQTT_PORT  = {MQTT_PORT};
const char* MQTT_TOPIC = "{topic}";
"""
