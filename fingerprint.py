"""
fingerprint.py — Behavioral Device Fingerprinting
Patent Claim: "Behavioral fingerprint-based identity verification for IoT digital twins —
a method of detecting device spoofing by comparing runtime behavioral signatures
against learned per-device statistical profiles."

Each device builds a fingerprint from:
  - Temperature operating range (min, max, mean, std)
  - Humidity operating range
  - Inter-packet timing consistency
  - Value transition patterns (delta distribution)

An incoming packet is scored against the fingerprint.
High deviation = possible spoofed / cloned device.
"""

import math
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Dict, Optional


FINGERPRINT_MIN_SAMPLES = 30   # need this many readings before fingerprint is reliable
DEVIATION_THRESHOLD     = 3.5  # std deviations before flagging


class DeviceFingerprint:
    """Rolling behavioral fingerprint for one device."""

    def __init__(self, device_id: str):
        self.device_id = device_id
        self._lock     = threading.Lock()

        self._temps     = deque(maxlen=200)
        self._humids    = deque(maxlen=200)
        self._deltas    = deque(maxlen=200)   # consecutive temp differences
        self._intervals = deque(maxlen=200)   # ms between packets
        self._last_temp : Optional[float] = None
        self._last_time : Optional[datetime] = None
        self._n         = 0

    # ── Welford stats ─────────────────────────────────────────────────────────

    @staticmethod
    def _stats(vals):
        if not vals:
            return 0.0, 1.0
        n  = len(vals)
        mu = sum(vals) / n
        if n < 2:
            return mu, 1.0
        var = sum((x - mu) ** 2 for x in vals) / (n - 1)
        return mu, max(math.sqrt(var), 0.01)

    # ── Update ────────────────────────────────────────────────────────────────

    def update(self, temp: float, humidity: float, timestamp: str) -> dict:
        with self._lock:
            self._n += 1
            self._temps.append(temp)
            self._humids.append(humidity)

            # Delta
            if self._last_temp is not None:
                self._deltas.append(abs(temp - self._last_temp))
            self._last_temp = temp

            # Interval
            try:
                t = datetime.fromisoformat(timestamp)
                if self._last_time is not None:
                    ms = abs((t - self._last_time).total_seconds() * 1000)
                    self._intervals.append(ms)
                self._last_time = t
            except Exception:
                pass

            return self.snapshot()

    def snapshot(self) -> dict:
        mu_t, s_t = self._stats(list(self._temps))
        mu_h, s_h = self._stats(list(self._humids))
        mu_d, s_d = self._stats(list(self._deltas))
        mu_i, s_i = self._stats(list(self._intervals))
        return {
            "device_id":    self.device_id,
            "samples":      self._n,
            "temp_mean":    round(mu_t, 2),
            "temp_std":     round(s_t, 2),
            "temp_min":     round(min(self._temps), 2) if self._temps else 0,
            "temp_max":     round(max(self._temps), 2) if self._temps else 0,
            "humid_mean":   round(mu_h, 2),
            "humid_std":    round(s_h, 2),
            "delta_mean":   round(mu_d, 2),
            "delta_std":    round(s_d, 2),
            "interval_mean_ms": round(mu_i, 1),
            "interval_std_ms":  round(s_i, 1),
            "reliable":     self._n >= FINGERPRINT_MIN_SAMPLES,
        }

    # ── Verify incoming packet ────────────────────────────────────────────────

    def verify(self, temp: float, humidity: float) -> dict:
        """
        Checks whether temp/humidity fall within the learned behavioral envelope.
        Returns {"ok": bool, "reason": str, "deviation": float}
        """
        with self._lock:
            if self._n < FINGERPRINT_MIN_SAMPLES:
                return {"ok": True, "reason": "fingerprint_building", "deviation": 0.0}

            mu_t, s_t = self._stats(list(self._temps))
            mu_h, s_h = self._stats(list(self._humids))

            z_t = abs(temp     - mu_t) / s_t
            z_h = abs(humidity - mu_h) / s_h

            max_z = max(z_t, z_h)

            if max_z > DEVIATION_THRESHOLD:
                return {
                    "ok":        False,
                    "reason":    f"Behavioral mismatch: Z={max_z:.2f} (temp Z={z_t:.2f}, humid Z={z_h:.2f})",
                    "deviation": round(max_z, 3),
                }
            return {"ok": True, "reason": "within_envelope", "deviation": round(max_z, 3)}


class FingerprintEngine:
    """Fleet-level fingerprint manager."""

    def __init__(self, device_ids: list):
        self._fps: Dict[str, DeviceFingerprint] = {
            did: DeviceFingerprint(did) for did in device_ids
        }

    def update(self, device_id: str, temp: float, humidity: float, timestamp: str) -> dict:
        fp = self._fps.get(device_id)
        if fp:
            return fp.update(temp, humidity, timestamp)
        return {}

    def verify(self, device_id: str, temp: float, humidity: float) -> dict:
        fp = self._fps.get(device_id)
        if fp:
            return fp.verify(temp, humidity)
        return {"ok": True, "reason": "unknown_device", "deviation": 0.0}

    def all_snapshots(self) -> list:
        return [fp.snapshot() for fp in self._fps.values()]
