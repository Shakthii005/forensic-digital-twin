import json
import paho.mqtt.client as mqtt
from forensic import ForensicEngine
from config import MQTT_BROKER, MQTT_PORT, MQTT_USERNAME, MQTT_PASSWORD, MQTT_TLS, MQTT_TOPIC_BASE

mqtt_status = {
    "connected": False,
    "last_message": None,
    "error": None,
}

def start_mqtt(forensic_engine, org_id: int = 1):
    """Start MQTT client with support for both TLS and non-TLS brokers."""

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print(f"✓ MQTT Connected to {MQTT_BROKER}:{MQTT_PORT}")
            mqtt_status["connected"] = True
            client.subscribe(f"{MQTT_TOPIC_BASE}/#", qos=1)
        else:
            error_msgs = {
                1: "Wrong protocol version",
                2: "Client ID rejected",
                3: "Broker unavailable",
                4: "Bad credentials",
                5: "Not authorized",
            }
            mqtt_status["connected"] = False
            mqtt_status["error"] = error_msgs.get(rc, f"Connection refused (code {rc})")
            print(f"✗ MQTT Connection failed: {mqtt_status['error']}")

    def on_disconnect(client, userdata, rc):
        if rc != 0:
            mqtt_status["connected"] = False
            print(f"✗ Unexpected MQTT disconnection (code {rc})")
        else:
            print("MQTT Disconnected gracefully")

    def on_message(client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode('utf-8'))
            
            # Add org_id if not present
            if "org_id" not in payload:
                payload["org_id"] = org_id
            
            # Log reception
            device_id = payload.get("device_id", "unknown")
            temp = payload.get("temp", "?")
            humidity = payload.get("humidity", "?")
            print(f"📨 [{device_id}] Temp={temp}°C Humidity={humidity}% Nonce={payload.get('nonce', '?')[:12]}...")
            
            mqtt_status["last_message"] = payload
            
            # Process with forensic engine
            forensic_engine.process(payload)
            
        except json.JSONDecodeError as e:
            mqtt_status["error"] = f"JSON decode error: {e}"
            print(f"✗ MQTT JSON Error: {e}")
        except Exception as e:
            mqtt_status["error"] = str(e)
            print(f"✗ MQTT Error: {e}")

    # Create MQTT client
    client = mqtt.Client(client_id=f"fdtp-server-{org_id}")
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message

    # Set credentials if provided
    if MQTT_USERNAME and MQTT_PASSWORD:
        client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)

    # Set TLS if broker requires it (port 8883)
    if MQTT_TLS and MQTT_PORT == 8883:
        client.tls_set()
        client.tls_insecure = False

    # Connect to broker
    try:
        print(f"Connecting to MQTT broker {MQTT_BROKER}:{MQTT_PORT}...")
        client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
        client.loop_start()
        return client
    except Exception as e:
        mqtt_status["error"] = str(e)
        print(f"✗ Failed to connect to MQTT: {e}")
        return None
