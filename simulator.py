"""
simulator.py — IoT Device Simulator
Generates realistic sensor telemetry for multiple devices.
Each packet is signed with RSA, includes a nonce, and a rolling hash chain.
"""

import hashlib
import json
import time
import uuid
import threading
import random
from datetime import datetime, timezone
from typing import Callable, Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

import database as db


# ── Key generation ────────────────────────────────────────────────────────────

def generate_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key  = private_key.public_key()
    return private_key, public_key


def sign_payload(private_key, payload_bytes: bytes) -> str:
    sig = private_key.sign(
        payload_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return sig.hex()


def verify_signature(public_key, payload_bytes: bytes, sig_hex: str) -> bool:
    try:
        public_key.verify(
            bytes.fromhex(sig_hex),
            payload_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ── Device profiles ───────────────────────────────────────────────────────────

DEVICE_PROFILES = {
    "IoT_1": {"base_temp": 28.0, "base_humidity": 55.0, "location": "Server Room A"},
    "IoT_2": {"base_temp": 22.0, "base_humidity": 45.0, "location": "Lab B"},
    "IoT_3": {"base_temp": 35.0, "base_humidity": 70.0, "location": "Outdoor Unit"},
}


class DeviceSimulator:
    def __init__(self, device_id: str, profile: dict, interval: float = 2.0,
                 on_packet: Callable = None):
        self.device_id   = device_id
        self.profile     = profile
        self.interval    = interval
        self.on_packet   = on_packet          # callback(packet_dict)
        self._stop       = threading.Event()

        # Crypto
        self.private_key, self.public_key = generate_keypair()

        # State
        self._prev_hash   = hashlib.sha256(device_id.encode()).hexdigest()
        self._temp        = profile["base_temp"]
        self._humidity    = profile["base_humidity"]
        self._state       = "ACTIVE"
        self._attack_mode = None   # None | "tamper" | "replay" | "fake"
        self._replay_buf  = None   # stores a packet for replay injection

    # ── Attack injection ──────────────────────────────────────────────────────

    def inject_attack(self, mode: str):
        self._attack_mode = mode

    # ── Packet construction ───────────────────────────────────────────────────

    def _build_packet(self, tamper: bool = False, fake: bool = False) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        nonce = str(uuid.uuid4())

        temp     = round(self._temp + random.gauss(0, 0.3), 2)
        humidity = round(self._humidity + random.gauss(0, 0.5), 2)
        state    = self._state

        if fake:
            # Completely fabricated values
            temp     = round(random.uniform(10, 90), 2)
            humidity = round(random.uniform(10, 95), 2)

        payload_dict = {
            "device_id": self.device_id,
            "temp":       temp,
            "humidity":   humidity,
            "state":      state,
            "timestamp":  now,
            "nonce":      nonce,
        }

        # Canonical JSON for hashing/signing
        canon = json.dumps(payload_dict, sort_keys=True).encode()

        # Rolling hash chain: H(prev_hash ‖ current_payload)
        data_hash = hashlib.sha256(
            (self._prev_hash + canon.decode()).encode()
        ).hexdigest()

        if tamper:
            # Corrupt the hash to simulate tampering
            data_hash = "TAMPERED_" + data_hash[9:]

        # RSA signature (on canonical JSON, NOT tampered hash)
        signature = sign_payload(self.private_key, canon)

        packet = {
            **payload_dict,
            "hash":      data_hash,
            "signature": signature,
            "prev_hash": self._prev_hash,
        }

        # Only advance chain on legitimate packets
        if not tamper and not fake:
            self._prev_hash = data_hash

        return packet

    # ── Drift simulation ──────────────────────────────────────────────────────

    def _drift(self):
        """Slowly drift temperature/humidity to simulate real sensor behaviour."""
        self._temp     += random.gauss(0, 0.05)
        self._humidity += random.gauss(0, 0.1)
        self._temp     = max(15, min(60, self._temp))
        self._humidity = max(20, min(95, self._humidity))

    # ── Main loop ─────────────────────────────────────────────────────────────

    def _run(self):
        while not self._stop.is_set():
            self._drift()

            attack = self._attack_mode
            self._attack_mode = None  # consume once

            if attack == "tamper":
                pkt = self._build_packet(tamper=True)
                pkt["_injected_attack"] = "tamper"
            elif attack == "replay" and self._replay_buf:
                pkt = dict(self._replay_buf)
                pkt["_injected_attack"] = "replay"
            elif attack == "fake":
                pkt = self._build_packet(fake=True)
                pkt["_injected_attack"] = "fake"
            else:
                pkt = self._build_packet()
                # Store last good packet for future replay injection
                self._replay_buf = dict(pkt)

            if self.on_packet:
                self.on_packet(pkt)

            time.sleep(self.interval)

    def start(self):
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def stop(self):
        self._stop.set()


# ── Fleet manager ─────────────────────────────────────────────────────────────

class SimulatorFleet:
    """Manages all device simulators and routes packets to the forensic engine."""

    def __init__(self, on_packet: Callable = None, org_id: int = 1):
        self.devices: Dict[str, DeviceSimulator] = {}
        self.on_packet = on_packet
        self.org_id    = org_id

    def launch(self):
        for dev_id, profile in DEVICE_PROFILES.items():
            sim = DeviceSimulator(
                device_id=dev_id,
                profile=profile,
                on_packet=self.on_packet,
            )
            self.devices[dev_id] = sim
            sim.start()

    def inject(self, device_id: str, attack: str):
        if device_id in self.devices:
            self.devices[device_id].inject_attack(attack)

    def get_public_key(self, device_id: str):
        if device_id in self.devices:
            return self.devices[device_id].public_key
        return None
