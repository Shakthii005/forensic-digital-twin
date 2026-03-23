"""
twin.py — Digital Twin Engine
In-memory only. DB persistence is handled by ForensicEngine with org_id.
"""

from datetime import datetime, timezone
from typing import Dict, Optional
import threading


class DeviceTwin:
    def __init__(self, device_id: str):
        self.device_id   = device_id
        self._lock       = threading.Lock()
        self.temp: Optional[float]     = None
        self.humidity: Optional[float] = None
        self.state: Optional[str]      = None
        self.last_hash: Optional[str]  = None
        self.last_nonce: Optional[str] = None
        self.updated_at: Optional[str] = None
        self.diverged    = False

    def update(self, packet: dict):
        with self._lock:
            self.temp       = packet["temp"]
            self.humidity   = packet["humidity"]
            self.state      = packet.get("state", "UNKNOWN")
            self.last_hash  = packet["hash"]
            self.last_nonce = packet["nonce"]
            self.updated_at = datetime.now(timezone.utc).isoformat()
            self.diverged   = False

    def mark_diverged(self):
        with self._lock:
            self.diverged = True

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "device_id":  self.device_id,
                "temp":       self.temp,
                "humidity":   self.humidity,
                "state":      self.state,
                "last_hash":  self.last_hash,
                "last_nonce": self.last_nonce,
                "updated_at": self.updated_at,
                "diverged":   self.diverged,
            }


class TwinEngine:
    def __init__(self, device_ids: list):
        self._twins: Dict[str, DeviceTwin] = {
            did: DeviceTwin(did) for did in device_ids
        }

    def get(self, device_id: str) -> Optional[DeviceTwin]:
        return self._twins.get(device_id)

    def update(self, device_id: str, packet: dict):
        twin = self._twins.get(device_id)
        if twin:
            twin.update(packet)

    def mark_diverged(self, device_id: str):
        twin = self._twins.get(device_id)
        if twin:
            twin.mark_diverged()

    def all_snapshots(self) -> list:
        return [t.snapshot() for t in self._twins.values()]

    def compare(self, device_id: str, incoming: dict) -> dict:
        twin = self._twins.get(device_id)
        if not twin or twin.temp is None:
            return {}
        snap = twin.snapshot()
        diff = {}
        temp_delta = abs((incoming.get("temp") or 0) - (snap["temp"] or 0))
        if temp_delta > 5.0:
            diff["temp_delta"] = round(temp_delta, 2)
        hum_delta = abs((incoming.get("humidity") or 0) - (snap["humidity"] or 0))
        if hum_delta > 10.0:
            diff["humidity_delta"] = round(hum_delta, 2)
        if incoming.get("state") != snap["state"]:
            diff["state_change"] = f"{snap['state']} → {incoming.get('state')}"
        return diff