"""
threat_score.py — Composite Forensic Threat Scoring Engine
Patent Claim: "A composite weighted forensic scoring method for IoT packet verification
combining cryptographic, behavioral, and statistical signals into a unified threat index."

Score 0–100:
  0–20   → SAFE (green)
  21–45  → LOW  (yellow)
  46–70  → MEDIUM (orange)
  71–89  → HIGH (red)
  90–100 → CRITICAL (blinking red)
"""

from dataclasses import dataclass, field
from typing import List, Dict


# ── Weights (must sum to 100) ─────────────────────────────────────────────────
WEIGHTS = {
    "signature_fail":    30,   # Layer 1 — RSA failure is most severe
    "replay_attack":     25,   # Layer 2 — replay is a definitive attack
    "hash_tampering":    25,   # Layer 3 — chain break = tampering
    "anomaly":           10,   # Layer 4 — could be sensor glitch
    "twin_divergence":    7,   # Layer 5 — divergence is a soft signal
    "stale_timestamp":    3,   # partial replay signal
}

SEVERITY_LABELS = {
    (0,  20):  ("SAFE",     "#00ff88", "🟢"),
    (21, 45):  ("LOW",      "#ffd700", "🟡"),
    (46, 70):  ("MEDIUM",   "#ff8c00", "🟠"),
    (71, 89):  ("HIGH",     "#ff3333", "🔴"),
    (90, 101): ("CRITICAL", "#ff0000", "💀"),
}


@dataclass
class ThreatResult:
    score:        int
    label:        str
    color:        str
    icon:         str
    contributions: Dict[str, int] = field(default_factory=dict)
    alerts:       List[str]       = field(default_factory=list)


def compute_threat_score(forensic_alerts: list, diff: dict = None) -> ThreatResult:
    """
    forensic_alerts : list of alert dicts from ForensicEngine (each has 'type', 'severity')
    diff            : twin divergence dict
    Returns ThreatResult with score 0–100
    """
    score         = 0
    contributions = {}
    alert_names   = []

    alert_types = {a["type"].upper() for a in forensic_alerts}

    # Map alert types to weight keys
    mapping = {
        "SIGNATURE_FAIL":  "signature_fail",
        "REPLAY_ATTACK":   "replay_attack",
        "HASH_TAMPERING":  "hash_tampering",
        "ANOMALY":         "anomaly",
        "TWIN_DIVERGENCE": "twin_divergence",
    }

    for alert_type, weight_key in mapping.items():
        if alert_type in alert_types:
            w = WEIGHTS[weight_key]
            score += w
            contributions[weight_key] = w
            alert_names.append(alert_type)

    # Partial score for twin divergence even without alert
    if diff and "temp_delta" in diff:
        partial = min(int(diff["temp_delta"] / 15 * WEIGHTS["twin_divergence"]), WEIGHTS["twin_divergence"])
        if "twin_divergence" not in contributions:
            score += partial
            contributions["twin_divergence"] = partial

    score = min(score, 100)

    # Determine label
    label, color, icon = "SAFE", "#00ff88", "🟢"
    for (lo, hi), (lbl, clr, icn) in SEVERITY_LABELS.items():
        if lo <= score < hi:
            label, color, icon = lbl, clr, icn
            break

    return ThreatResult(
        score=score,
        label=label,
        color=color,
        icon=icon,
        contributions=contributions,
        alerts=alert_names,
    )


def score_to_gauge_html(score: int, color: str) -> str:
    """Returns an SVG gauge for embedding in Streamlit via components."""
    pct  = score / 100
    r    = 54
    circ = 2 * 3.14159 * r
    dash = pct * circ
    return f"""
    <svg viewBox="0 0 120 120" xmlns="http://www.w3.org/2000/svg" width="140" height="140">
      <circle cx="60" cy="60" r="{r}" fill="none" stroke="#1a0a0a" stroke-width="12"/>
      <circle cx="60" cy="60" r="{r}" fill="none" stroke="{color}" stroke-width="12"
        stroke-dasharray="{dash:.1f} {circ:.1f}"
        stroke-dashoffset="{circ*0.25:.1f}"
        stroke-linecap="round"
        style="filter: drop-shadow(0 0 6px {color})"/>
      <text x="60" y="56" text-anchor="middle" font-size="22" font-weight="bold"
        fill="{color}" font-family="monospace">{score}</text>
      <text x="60" y="74" text-anchor="middle" font-size="9"
        fill="#888" font-family="monospace">THREAT</text>
    </svg>
    """
