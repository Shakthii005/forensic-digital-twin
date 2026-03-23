"""
attacks.py — Attack Simulator
Exposes clean functions to inject specific attack scenarios.
Called from the Streamlit UI attack panel.
"""

from simulator import SimulatorFleet


def simulate_replay(fleet: SimulatorFleet, device_id: str):
    """
    Injects a replay attack: re-sends a previously captured valid packet.
    The nonce will already be in the used-nonce set → Forensic Engine detects it.
    """
    fleet.inject(device_id, "replay")
    return f"[ATTACK] Replay attack injected on {device_id}"


def simulate_tampering(fleet: SimulatorFleet, device_id: str):
    """
    Injects a tampered packet: valid data but corrupted hash.
    Forensic Engine hash-chain check will catch the mismatch.
    """
    fleet.inject(device_id, "tamper")
    return f"[ATTACK] Tampering attack injected on {device_id}"


def simulate_fake_device(fleet: SimulatorFleet, device_id: str):
    """
    Injects a packet with completely fabricated sensor values.
    Anomaly detection + Z-score will flag the outlier.
    """
    fleet.inject(device_id, "fake")
    return f"[ATTACK] Fake-device packet injected on {device_id}"
