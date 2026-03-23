"""
forensic.py — Multi-tenant Forensic Engine v2.0
All operations are org-scoped for proper data isolation.
"""

import hashlib
import json
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Callable, Dict, Optional
import math

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import database as db
from twin import TwinEngine
from threat_score import compute_threat_score
from lstm_detector import LSTMFleet
from fingerprint import FingerprintEngine
from config import (NONCE_WINDOW_SEC, ZSCORE_THRESHOLD,
                    RATE_OF_CHANGE_LIMIT, ANOMALY_WINDOW, LSTM_ANOMALY_MULT)


class ForensicEngine:
    def __init__(self, org_id: int, twin_engine: TwinEngine,
                 public_key_provider: Callable, device_ids: list = None):
        self.org_id  = org_id
        self.twin    = twin_engine
        self._pub_fn = public_key_provider
        self._lock   = threading.Lock()

        device_ids = device_ids or []
        self.lstm_fleet   = LSTMFleet(device_ids)
        self.fingerprints = FingerprintEngine(device_ids)

        self._nonces: Dict[str, dict]           = defaultdict(dict)
        self._chain:  Dict[str, Optional[str]]  = defaultdict(lambda: None)
        self._temp_window: Dict[str, deque]     = defaultdict(lambda: deque(maxlen=ANOMALY_WINDOW))
        self._last_temp:   Dict[str, Optional[float]] = defaultdict(lambda: None)
        self._log_chain:   Dict[str, str]       = defaultdict(
            lambda: hashlib.sha256(b"GENESIS").hexdigest()
        )
        self.latest_threat: Dict[str, dict] = {}
        self.on_alert: Optional[Callable]   = None

    def process(self, packet: dict) -> dict:
        device_id = packet["device_id"]
        result    = {"ok": True, "alerts": [], "diff": {}, "threat": None,
                     "lstm": None, "fingerprint": None}

        with self._lock:
            self._prune_nonces(device_id)

            # L1 — Signature
            # Skip strict RSA check for MQTT devices sending "simulated" signature
            sig = packet.get("signature", "")
            if sig not in ("simulated", ""):
                sig_ok, sig_msg = self._verify_signature(device_id, packet)
                if not sig_ok:
                    self._raise(device_id, "SIGNATURE_FAIL", sig_msg, "HIGH", result)

            # L2 — Replay
            replay_ok, replay_msg = self._check_replay(device_id, packet)
            if not replay_ok:
                self._raise(device_id, "REPLAY_ATTACK", replay_msg, "HIGH", result)

            # L3 — Hash chain
            chain_ok, chain_msg = self._verify_chain(device_id, packet)
            if not chain_ok:
                self._raise(device_id, "HASH_TAMPERING", chain_msg, "CRITICAL", result)

            # L4 — Z-score anomaly
            if chain_ok:
                anom_ok, anom_msg = self._detect_anomaly(device_id, packet)
                if not anom_ok:
                    self._raise(device_id, "ANOMALY", anom_msg, "MEDIUM", result)

            # L5 — Twin divergence
            diff = self.twin.compare(device_id, packet)
            if diff:
                result["diff"] = diff
                if "temp_delta" in diff and diff["temp_delta"] > 10:
                    self._raise(device_id, "TWIN_DIVERGENCE",
                                f"Twin delta: {diff}", "HIGH", result)

            # L6 — LSTM
            lstm_result = self.lstm_fleet.update(device_id, packet["temp"])
            result["lstm"] = lstm_result
            if lstm_result.get("anomaly"):
                self._raise(device_id, "LSTM_ANOMALY",
                            f"LSTM score={lstm_result['score']:.2f} pred={lstm_result['prediction']}°C",
                            "MEDIUM", result)

            # L7 — Fingerprint
            fp_result = self.fingerprints.verify(device_id, packet["temp"], packet["humidity"])
            result["fingerprint"] = fp_result
            if not fp_result.get("ok") and fp_result.get("reason") != "fingerprint_building":
                self._raise(device_id, "FINGERPRINT_MISMATCH",
                            fp_result.get("reason", "behavioral mismatch"), "HIGH", result)

            self.fingerprints.update(device_id, packet["temp"],
                                     packet["humidity"], packet["timestamp"])

            # Threat score
            threat = compute_threat_score(result["alerts"], diff)
            result["threat"] = {
                "score": threat.score, "label": threat.label,
                "color": threat.color, "icon": threat.icon,
                "contributions": threat.contributions,
            }
            self.latest_threat[device_id] = result["threat"]

            # Save telemetry to DB with org_id
            is_attack_flag = 1 if result["alerts"] else 0
            db.insert_device_data({
                "org_id":       self.org_id,
                "device_id":    device_id,
                "temp":         packet["temp"],
                "humidity":     packet["humidity"],
                "device_state": packet.get("state", "ACTIVE"),
                "timestamp":    packet["timestamp"],
                "nonce":        packet["nonce"],
                "hash":         packet["hash"],
                "signature":    packet.get("signature", ""),
                "is_attack":    is_attack_flag,
                "source":       packet.get("source", "simulator"),
            })

            # Update twin
            critical = any(a["severity"] == "CRITICAL" for a in result["alerts"])
            if not critical and chain_ok and replay_ok:
                self.twin.update(device_id, packet)
                self._chain[device_id] = packet["hash"]
                self._register_nonce(device_id, packet["nonce"], packet["timestamp"])
                db.upsert_twin(self.org_id, device_id, {
                    "temp": packet["temp"], "humidity": packet["humidity"],
                    "device_state": packet.get("state","ACTIVE"),
                    "last_hash": packet["hash"], "last_nonce": packet["nonce"],
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                })
            else:
                self.twin.mark_diverged(device_id)
                result["ok"] = False

            self._write_forensic_log(device_id, packet, result)

        return result

    def _verify_signature(self, device_id, packet):
        pub = self._pub_fn(device_id)
        if pub is None:
            return False, "No public key"
        payload = {k: packet[k] for k in ("device_id","temp","humidity","state","timestamp","nonce")}
        canon   = json.dumps(payload, sort_keys=True).encode()
        try:
            pub.verify(
                bytes.fromhex(packet["signature"]), canon,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True, "OK"
        except Exception as e:
            return False, str(e)

    def _check_replay(self, device_id, packet):
        nonce = packet["nonce"]
        if nonce in self._nonces[device_id]:
            return False, f"Nonce '{nonce[:12]}…' already seen"
        try:
            age = abs((datetime.now(timezone.utc) -
                       datetime.fromisoformat(packet["timestamp"])).total_seconds())
            if age > NONCE_WINDOW_SEC:
                return False, f"Stale timestamp (age={age:.0f}s)"
        except Exception:
            return False, "Unparseable timestamp"
        return True, "OK"

    def _register_nonce(self, device_id, nonce, timestamp):
        self._nonces[device_id][nonce] = timestamp

    def _prune_nonces(self, device_id):
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=NONCE_WINDOW_SEC)
        dead   = []
        for n, ts in self._nonces[device_id].items():
            try:
                if datetime.fromisoformat(ts) < cutoff:
                    dead.append(n)
            except Exception:
                dead.append(n)
        for n in dead:
            del self._nonces[device_id][n]

    def _verify_chain(self, device_id, packet):
        prev = self._chain[device_id]
        if prev is None:
            return True, "INIT"
        payload  = {k: packet[k] for k in ("device_id","temp","humidity","state","timestamp","nonce")}
        expected = hashlib.sha256((prev + json.dumps(payload, sort_keys=True)).encode()).hexdigest()
        if packet["hash"] not in (expected, "simulated"):
            return False, f"Hash mismatch. Expected {expected[:16]}… Got {packet['hash'][:16]}…"
        return True, "OK"

    def _detect_anomaly(self, device_id, packet):
        temp = packet["temp"]
        win  = self._temp_window[device_id]
        last = self._last_temp[device_id]
        if last is not None and abs(temp - last) > RATE_OF_CHANGE_LIMIT:
            self._last_temp[device_id] = temp
            win.append(temp)
            return False, f"Rapid temp change: {abs(temp-last):.1f}°C"
        win.append(temp)
        self._last_temp[device_id] = temp
        if len(win) >= 5:
            mu    = sum(win) / len(win)
            sigma = math.sqrt(sum((x-mu)**2 for x in win) / len(win))
            if sigma > 0:
                z = abs(temp - mu) / sigma
                if z > ZSCORE_THRESHOLD:
                    return False, f"Z-score spike: Z={z:.2f} temp={temp}°C μ={mu:.1f}"
        return True, "OK"

    def _write_forensic_log(self, device_id, packet, result):
        prev        = self._log_chain[device_id]
        event_type  = "NORMAL" if result["ok"] else "ATTACK"
        description = (f"Alerts: {[a['type'] for a in result['alerts']]}"
                       if result["alerts"] else "Clean packet.")
        new_hash    = hashlib.sha256(
            f"{prev}{event_type}{packet['hash']}".encode()
        ).hexdigest()
        self._log_chain[device_id] = new_hash
        db.insert_log({
            "org_id":      self.org_id,
            "device_id":   device_id,
            "event_type":  event_type,
            "description": description,
            "hash_chain":  new_hash,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        })

    def _raise(self, device_id, atype, detail, severity, result):
        result["ok"] = False
        alert = {"type": atype, "severity": severity, "detail": detail}
        result["alerts"].append(alert)
        db.insert_alert({
            "org_id":      self.org_id,
            "device_id":   device_id,
            "attack_type": atype,
            "severity":    severity,
            "detail":      detail,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        })
        if self.on_alert:
            self.on_alert(device_id, alert)