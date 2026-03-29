import json
import paho.mqtt.client as mqtt
from forensic import ForensicEngine

def start_mqtt(forensic_engine):

    def on_connect(client, userdata, flags, rc):
        print("MQTT Connected")
        client.subscribe("fdtp/devices/#")

    def on_message(client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode())
            print("Received:", payload)
            forensic_engine.process(payload)
        except Exception as e:
            print("MQTT Error:", e)

    client = mqtt.Client()
    client.connect("broker.hivemq.com", 8883, 60)

    client.on_connect = on_connect
    client.on_message = on_message

    client.loop_start()
