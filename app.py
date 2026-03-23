"""
app.py — Forensic Digital Twin Platform v2.0 SaaS
Run: streamlit run app.py
"""

import time
import os
from datetime import datetime, timezone, timedelta

# IST = UTC+5:30
IST = timezone(timedelta(hours=5, minutes=30))

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

import database as db
from auth import show_auth_page, get_current_user, logout, can
from simulator import SimulatorFleet, DEVICE_PROFILES
from twin import TwinEngine
from forensic import ForensicEngine
from mqtt_connector import DeviceManager, get_mqtt_setup_instructions
import attacks
from config import (APP_NAME, APP_VERSION, SIM_DEVICES, MQTT_BROKER,
                    MQTT_PORT, REFRESH_INTERVAL)

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title=f"FDTP — {APP_NAME}",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Init DB ───────────────────────────────────────────────────────────────────
db.init_db()

# ── Auth gate ─────────────────────────────────────────────────────────────────
user = get_current_user()
if not user:
    show_auth_page()
    st.stop()

org_id = user["org_id"]

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
html,body,[class*="css"]{font-family:'Inter',sans-serif!important;background:#030712!important;color:#f9fafb!important;}
.stApp{background:#030712!important;}
[data-testid="stSidebar"]{display:none!important;}
[data-testid="collapsedControl"]{display:none!important;}
#MainMenu,header[data-testid="stHeader"],footer{display:none!important;}
.block-container{padding-top:0!important;padding-left:2rem!important;padding-right:2rem!important;max-width:100%!important;}
[data-testid="stMetric"]{display:none!important;}
.stButton>button{background:#111827!important;color:#d1d5db!important;border:1px solid #1f2937!important;border-radius:8px!important;font-family:'Inter',sans-serif!important;font-size:13px!important;font-weight:500!important;}
.stButton>button:hover{background:#1f2937!important;border-color:#6366f1!important;color:#a5b4fc!important;}
.stSuccess{background:rgba(34,197,94,0.08)!important;border:1px solid rgba(34,197,94,0.2)!important;border-left:3px solid #22c55e!important;color:#86efac!important;border-radius:8px!important;}
.stError{background:rgba(239,68,68,0.08)!important;border:1px solid rgba(239,68,68,0.2)!important;border-left:3px solid #ef4444!important;color:#fca5a5!important;border-radius:8px!important;}
.stWarning{background:rgba(234,179,8,0.08)!important;border:1px solid rgba(234,179,8,0.2)!important;border-left:3px solid #eab308!important;color:#fde047!important;border-radius:8px!important;}
.stInfo{background:rgba(99,102,241,0.08)!important;border:1px solid rgba(99,102,241,0.2)!important;border-left:3px solid #6366f1!important;color:#a5b4fc!important;border-radius:8px!important;}
code,pre,.stCode{font-family:'JetBrains Mono',monospace!important;background:#111827!important;border:1px solid #1f2937!important;color:#6366f1!important;border-radius:6px!important;font-size:11px!important;}
[data-baseweb="select"]>div{background:#111827!important;border-color:#1f2937!important;border-radius:8px!important;}
[data-testid="stTextInput"]>div>div{background:#111827!important;border-color:#1f2937!important;border-radius:8px!important;color:#f9fafb!important;}
hr{border-color:#111827!important;}
[data-testid="stExpander"]{background:#0f172a!important;border:1px solid #1f2937!important;border-radius:8px!important;}
::-webkit-scrollbar{width:4px;height:4px;}
::-webkit-scrollbar-track{background:#030712;}
::-webkit-scrollbar-thumb{background:#1f2937;border-radius:2px;}
.section-label{font-size:11px;font-weight:600;letter-spacing:2px;text-transform:uppercase;color:#374151;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #111827;}
</style>
""", unsafe_allow_html=True)

# ── SCIF table helper ─────────────────────────────────────────────────────────
def scif_table(headers, rows, col_colors=None, max_rows=100):
    col_colors = col_colors or {}
    th = "".join(
        f"<th style='padding:10px 16px;text-align:left;font-family:Inter,sans-serif;"
        f"font-size:11px;font-weight:600;letter-spacing:1.5px;color:#6b7280;"
        f"background:#111827;border-bottom:1px solid #1f2937;text-transform:uppercase;"
        f"white-space:nowrap;'>{h}</th>" for h in headers
    )
    tr = ""
    for ri, row in enumerate(rows[:max_rows]):
        bg = "#0f172a" if ri % 2 == 0 else "#111827"
        td = ""
        for ci, cell in enumerate(row):
            val   = str(cell) if cell is not None else "—"
            fn    = col_colors.get(ci)
            color = fn(val) if fn else "#9ca3af"
            td   += (f"<td style='padding:9px 16px;font-family:JetBrains Mono,monospace;"
                     f"font-size:11px;color:{color};border-bottom:1px solid #1f2937;"
                     f"white-space:nowrap;'>{val}</td>")
        tr += (f"<tr style='background:{bg};transition:background 0.15s;'"
               f" onmouseover=\"this.style.background='#1e293b'\""
               f" onmouseout=\"this.style.background='{bg}'\">{td}</tr>")
    st.markdown(
        f"<div style='overflow-x:auto;border:1px solid #1f2937;border-radius:8px;margin-bottom:20px;'>"
        f"<table style='width:100%;border-collapse:collapse;'>"
        f"<thead><tr>{th}</tr></thead><tbody>{tr}</tbody></table></div>",
        unsafe_allow_html=True
    )

def sev_color(v): return {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308","LOW":"#22c55e"}.get(v.upper(),"#6b7280")
def evt_color(v): return "#ef4444" if v.upper()=="ATTACK" else "#22c55e"
def acc(_):   return "#a5b4fc"
def dim(_):   return "#4b5563"
def bright(_):return "#d1d5db"
def hash_c(_):return "#374151"
def bool_c(v):return "#22c55e" if v.upper() in ("no","false","0","clean","🟢 clean") else "#ef4444"

def hero_card(col, label, value, sub, icon, border_color="#6366f1"):
    with col:
        st.markdown(
            f"<div style='background:#0f172a;border:1px solid #1f2937;"
            f"border-top:2px solid {border_color};border-radius:12px;"
            f"padding:20px 24px;position:relative;'>"
            f"<div style='position:absolute;top:16px;right:16px;font-size:24px;opacity:0.15;'>{icon}</div>"
            f"<div style='font-size:11px;font-weight:600;letter-spacing:1.5px;"
            f"text-transform:uppercase;color:#4b5563;margin-bottom:8px;'>{label}</div>"
            f"<div style='font-size:2.2rem;font-weight:700;color:#f9fafb;line-height:1;margin-bottom:4px;'>{value}</div>"
            f"<div style='font-size:12px;color:#4b5563;font-family:JetBrains Mono,monospace;'>{sub}</div>"
            f"</div>",
            unsafe_allow_html=True
        )

# ── Bootstrap (per-user session) ─────────────────────────────────────────────
@st.cache_resource
def bootstrap(uid: int, oid: int):
    device_ids   = list(SIM_DEVICES.keys())
    twin_engine  = TwinEngine(device_ids)
    fleet        = SimulatorFleet(org_id=oid)
    forensic_eng = ForensicEngine(
        org_id=oid,
        twin_engine=twin_engine,
        public_key_provider=fleet.get_public_key,
        device_ids=device_ids,
    )
    dev_mgr = DeviceManager(oid, lambda pkt: forensic_eng.process(pkt))
    fleet.on_packet = lambda pkt: forensic_eng.process({**pkt, "source": "simulator"})

    # Start MQTT (fallback to simulator)
    mqtt_status = dev_mgr.start()
    if mqtt_status["mode"] == "simulation":
        fleet.launch()

    # Register devices in DB
    for did, profile in SIM_DEVICES.items():
        db.register_device(oid, did, did, profile["location"], "simulator")

    return fleet, twin_engine, forensic_eng, dev_mgr, mqtt_status

fleet, twin_engine, forensic_engine, dev_manager, mqtt_info = bootstrap(user["id"], org_id)

# ── Live data ─────────────────────────────────────────────────────────────────
twins      = twin_engine.all_snapshots()
all_alerts = db.fetch_alerts(org_id, limit=500)
all_logs   = db.fetch_logs(org_id, limit=500)
all_data   = db.fetch_device_data(org_id, limit=500)
now_str    = datetime.now(IST).strftime("%H:%M:%S IST")

total_alerts   = len(all_alerts)
critical_count = len([a for a in all_alerts if a["severity"]=="CRITICAL"])
high_count     = len([a for a in all_alerts if a["severity"]=="HIGH"])
compromised    = sum(1 for t in twins if t["diverged"])

# ── TOP NAV ───────────────────────────────────────────────────────────────────
device_dots = ""
for t in twins:
    dot_color = "#ef4444" if t["diverged"] else "#22c55e"
    threat    = forensic_engine.latest_threat.get(t["device_id"], {})
    score     = threat.get("score", 0)
    device_dots += (
        f"<span style='font-size:12px;color:#6b7280;margin-right:12px;'>"
        f"<span style='display:inline-block;width:7px;height:7px;background:{dot_color};"
        f"border-radius:50%;box-shadow:0 0 6px {dot_color};margin-right:5px;'></span>"
        f"{t['device_id']} <span style='color:#374151;font-size:10px;"
        f"font-family:JetBrains Mono,monospace;'>[{score}]</span></span>"
    )

mode_badge = (
    f"<span style='font-size:11px;padding:3px 10px;border-radius:20px;"
    f"background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.2);color:#22c55e;'>"
    f"● MQTT LIVE</span>"
    if mqtt_info["mode"] == "mqtt" else
    f"<span style='font-size:11px;padding:3px 10px;border-radius:20px;"
    f"background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.2);color:#6366f1;'>"
    f"◈ SIMULATION</span>"
)

role_color = {"admin":"#ef4444","analyst":"#f59e0b","viewer":"#22c55e"}.get(user["role"],"#6b7280")

st.markdown(f"""
<div style='position:sticky;top:0;z-index:999;background:rgba(3,7,18,0.97);
     backdrop-filter:blur(12px);border-bottom:1px solid #1f2937;
     padding:0 2rem;display:flex;align-items:center;justify-content:space-between;
     height:56px;margin:-1rem -2rem 0;'>
  <div style='display:flex;align-items:center;gap:12px;'>
    <div style='width:32px;height:32px;background:linear-gradient(135deg,#6366f1,#8b5cf6);
         border-radius:8px;display:flex;align-items:center;justify-content:center;
         font-size:16px;box-shadow:0 0 12px rgba(99,102,241,0.4);'>🛡️</div>
    <div>
      <div style='font-size:14px;font-weight:700;color:#f9fafb;'>FDTP v{APP_VERSION}</div>
      <div style='font-size:9px;color:#4b5563;letter-spacing:2px;font-family:JetBrains Mono,monospace;'>
        FORENSIC DIGITAL TWIN PLATFORM</div>
    </div>
  </div>
  <div style='display:flex;align-items:center;gap:16px;'>
    {device_dots}
    {mode_badge}
    <span style='font-family:JetBrains Mono,monospace;font-size:11px;color:#4b5563;
          padding:4px 12px;border:1px solid #1f2937;border-radius:6px;'>⏱ {now_str}</span>
    <span style='font-size:12px;color:{role_color};background:rgba(0,0,0,0.3);
          padding:3px 10px;border-radius:6px;border:1px solid {role_color}33;'>
      {user["full_name"] or user["username"]} · {user["role"].upper()}</span>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Tabs ──────────────────────────────────────────────────────────────────────
tabs = ["⬛  Dashboard", "📡  Forensic Logs", "🚨  Alerts",
        "🧠  AI Analysis", "⚔️  Attack Panel", "📡  Device Manager",
        "📁  Evidence Export"]
if user["role"] == "admin":
    tabs.append("👥  User Management")

tab_objects = st.tabs(tabs)
(tab_dash, tab_logs, tab_alerts, tab_ai,
 tab_attack, tab_devices, tab_evidence, *extra_tabs) = tab_objects
tab_users = extra_tabs[0] if extra_tabs else None

# ═══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
with tab_dash:
    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-label'>System Overview</div>", unsafe_allow_html=True)

    c1,c2,c3,c4,c5,c6 = st.columns(6)
    hero_card(c1,"Assets Online",   len(twins),      "devices monitored",       "📡","#6366f1")
    hero_card(c2,"Total Alerts",    total_alerts,    "since session start",      "🚨","#ef4444" if total_alerts else "#22c55e")
    hero_card(c3,"Critical",        critical_count,  "highest severity",         "💀","#ef4444" if critical_count else "#6366f1")
    hero_card(c4,"High Severity",   high_count,      "requires attention",       "⚠️","#f97316" if high_count else "#6366f1")
    hero_card(c5,"Log Entries",     len(all_logs),   "forensic chain length",    "🔗","#6366f1")
    hero_card(c6,"Compromised",     compromised,     "twin divergence detected", "🔴","#ef4444" if compromised else "#22c55e")

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

    # MQTT status banner
    if mqtt_info["mode"] == "mqtt":
        st.success(f"✅ Connected to MQTT broker at {mqtt_info['broker']} — receiving live device data")
    else:
        st.info(f"◈ Running in simulation mode — {mqtt_info.get('error','MQTT broker not configured')} — Go to Device Manager to connect real sensors")

    # Recent alerts
    if all_alerts[:3]:
        st.markdown("<div class='section-label'>Recent Incidents</div>", unsafe_allow_html=True)
        for a in all_alerts[:3]:
            clr = sev_color(a["severity"])
            st.markdown(
                f"<div style='background:rgba(239,68,68,0.05);border:1px solid rgba(239,68,68,0.1);"
                f"border-left:3px solid {clr};border-radius:8px;padding:10px 16px;"
                f"margin-bottom:8px;display:flex;align-items:center;gap:10px;'>"
                f"<span style='font-size:16px;'>{'💀' if a['severity']=='CRITICAL' else '⚠️'}</span>"
                f"<div><span style='font-weight:600;color:{clr};'>{a['attack_type']}</span>"
                f" on <span style='color:#d1d5db;'>{a['device_id']}</span>"
                f"<span style='color:#4b5563;font-family:JetBrains Mono,monospace;font-size:10px;'>"
                f" — {a['timestamp'][:19]}</span></div>"
                f"<span style='margin-left:auto;padding:2px 8px;border-radius:4px;"
                f"background:rgba(0,0,0,0.3);font-size:10px;font-weight:600;color:{clr};'>"
                f"{a['severity']}</span></div>",
                unsafe_allow_html=True
            )

    # Device cards
    st.markdown("<div class='section-label'>Asset Telemetry</div>", unsafe_allow_html=True)
    dcols = st.columns(len(twins))
    for col, twin in zip(dcols, twins):
        with col:
            threat  = forensic_engine.latest_threat.get(twin["device_id"], {})
            score   = threat.get("score", 0)
            tcolor  = threat.get("color", "#22c55e")
            tlabel  = threat.get("label", "SAFE")
            temp_v  = f"{twin['temp']:.1f}°C"    if twin["temp"]     is not None else "—"
            hum_v   = f"{twin['humidity']:.1f}%"  if twin["humidity"] is not None else "—"
            hash_v  = twin["last_hash"][:20]+"…"  if twin["last_hash"] else "initialising…"
            card_bc = "#991b1b" if twin["diverged"] else "#166534"
            badge   = "⚠ COMPROMISED" if twin["diverged"] else "✓ SECURE"
            bdg_cls = "background:rgba(239,68,68,0.1);color:#ef4444;border:1px solid rgba(239,68,68,0.3);" if twin["diverged"] else "background:rgba(34,197,94,0.1);color:#22c55e;border:1px solid rgba(34,197,94,0.3);"
            loc     = SIM_DEVICES.get(twin["device_id"], {}).get("location", "")
            r=36;circ=226;fill=score/100*circ
            gauge = f"""<svg viewBox="0 0 90 90" width="80" height="80" xmlns="http://www.w3.org/2000/svg">
              <circle cx="45" cy="45" r="{r}" fill="none" stroke="#1f2937" stroke-width="7"/>
              <circle cx="45" cy="45" r="{r}" fill="none" stroke="{tcolor}" stroke-width="7"
                stroke-dasharray="{fill:.1f} {circ}" stroke-dashoffset="{circ*0.25:.1f}"
                stroke-linecap="round"/>
              <text x="45" y="42" text-anchor="middle" font-size="15" font-weight="700"
                fill="{tcolor}" font-family="Inter,sans-serif">{score}</text>
              <text x="45" y="55" text-anchor="middle" font-size="7" fill="#374151"
                font-family="JetBrains Mono,monospace">THREAT</text></svg>"""
            st.markdown(
                f"<div style='background:#0f172a;border:1px solid {card_bc}33;"
                f"border-top:2px solid {tcolor};border-radius:12px;padding:16px;'>"
                f"<div style='display:flex;justify-content:space-between;align-items:flex-start;'>"
                f"  <div><div style='font-size:13px;font-weight:700;color:#f9fafb;'>{twin['device_id']}</div>"
                f"  <div style='font-size:11px;color:#4b5563;font-family:JetBrains Mono,monospace;'>{loc}</div></div>"
                f"  <div style='text-align:center;'>{gauge}</div></div>"
                f"<div style='font-size:1.8rem;font-weight:700;color:#f9fafb;margin:6px 0;'>{temp_v}</div>"
                f"<div style='font-size:12px;color:#6b7280;margin-bottom:10px;'>💧 {hum_v}</div>"
                f"<div style='font-family:JetBrains Mono,monospace;font-size:9px;color:#1f2937;"
                f"word-break:break-all;margin-bottom:10px;'>{hash_v}</div>"
                f"<span style='display:inline-block;padding:3px 10px;border-radius:20px;"
                f"font-size:11px;font-weight:600;{bdg_cls}'>{badge}</span></div>",
                unsafe_allow_html=True
            )

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

    # Temp chart
    st.markdown("<div class='section-label'>Temperature Feed — Live</div>", unsafe_allow_html=True)
    if all_data:
        df = pd.DataFrame(all_data)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp")
        palette = {"IoT_1":"#6366f1","IoT_2":"#22c55e","IoT_3":"#f59e0b"}
        fig = go.Figure()
        for dev_id in df["device_id"].unique():
            sub  = df[df["device_id"]==dev_id].tail(80)
            norm = sub[sub["is_attack"]==0]
            atk  = sub[sub["is_attack"]==1]
            clr  = palette.get(dev_id,"#6b7280")
            fig.add_trace(go.Scatter(
                x=norm["timestamp"], y=norm["temp"], mode="lines", name=dev_id,
                line=dict(color=clr,width=2), fill="tozeroy",
                fillcolor=f"rgba({int(clr[1:3],16)},{int(clr[3:5],16)},{int(clr[5:7],16)},0.04)",
            ))
            if not atk.empty:
                fig.add_trace(go.Scatter(
                    x=atk["timestamp"], y=atk["temp"], mode="markers",
                    name=f"{dev_id} ⚠", marker=dict(color="#ef4444",size=10,symbol="x-open",
                    line=dict(color="#ef4444",width=2))
                ))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#0f172a",
            font=dict(color="#4b5563",family="Inter"),
            legend=dict(bgcolor="rgba(0,0,0,0)",font=dict(color="#9ca3af"),orientation="h",y=-0.15),
            margin=dict(l=0,r=0,t=10,b=30), height=280,
            xaxis=dict(gridcolor="#111827",color="#374151",showline=False),
            yaxis=dict(gridcolor="#111827",color="#374151",title="°C",showline=False),
            hovermode="x unified",
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Awaiting telemetry data…")

    st.markdown("<div class='section-label'>Digital Twin Sync Status</div>", unsafe_allow_html=True)
    scif_table(
        headers=["ASSET","TEMP °C","HUMIDITY %","STATE","LAST NONCE","UPDATED AT","DIVERGED"],
        rows=[[t["device_id"],
               f"{t['temp']:.2f}" if t["temp"] is not None else "None",
               f"{t['humidity']:.2f}" if t["humidity"] is not None else "None",
               t["state"] or "—",
               (t["last_nonce"] or "—")[:30],
               (t["updated_at"] or "—")[:19],
               "YES" if t["diverged"] else "NO"] for t in twins],
        col_colors={0:acc, 1:lambda v:"#f9fafb", 2:lambda v:"#6ee7b7",
                    3:bright, 4:hash_c, 5:dim,
                    6:lambda v:"#ef4444" if v=="YES" else "#22c55e"}
    )

# ═══════════════════════════════════════════════════════════════════════════════
# FORENSIC LOGS
# ═══════════════════════════════════════════════════════════════════════════════
with tab_logs:
    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-label'>Blockchain-Style Forensic Log Chain</div>", unsafe_allow_html=True)
    logs = db.fetch_logs(org_id, limit=200)
    if not logs:
        st.info("Log chain initialising…")
    else:
        df = pd.DataFrame(logs)
        chain_entries = logs[:6]
        chain_cols    = st.columns(len(chain_entries))
        for i, (col, entry) in enumerate(zip(chain_cols, chain_entries)):
            with col:
                is_atk = entry["event_type"]=="ATTACK"
                color  = "#ef4444" if is_atk else "#22c55e"
                bg     = "rgba(239,68,68,0.05)" if is_atk else "rgba(34,197,94,0.05)"
                border = "rgba(239,68,68,0.2)"  if is_atk else "rgba(34,197,94,0.2)"
                st.markdown(
                    f"<div style='background:{bg};border:1px solid {border};"
                    f"border-top:2px solid {color};border-radius:8px;padding:12px;text-align:center;'>"
                    f"<div style='font-size:10px;font-weight:600;color:{color};letter-spacing:1px;"
                    f"margin-bottom:4px;'>{'ATTACK' if is_atk else 'CLEAN'}</div>"
                    f"<div style='font-size:11px;color:#9ca3af;margin-bottom:4px;'>{entry['device_id']}</div>"
                    f"<div style='font-family:JetBrains Mono,monospace;font-size:8px;"
                    f"color:#374151;word-break:break-all;'>{entry['hash_chain'][:18]}…</div></div>",
                    unsafe_allow_html=True
                )
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        c1, c2 = st.columns([2,1])
        with c1:
            dev_filter  = st.multiselect("Filter Asset", list(SIM_DEVICES.keys()), default=list(SIM_DEVICES.keys()))
        with c2:
            type_filter = st.selectbox("Event", ["ALL","NORMAL","ATTACK"])
        filtered = [l for l in logs if l["device_id"] in dev_filter]
        if type_filter != "ALL":
            filtered = [l for l in filtered if l["event_type"]==type_filter]
        scif_table(
            headers=["DEVICE","EVENT","DESCRIPTION","HASH CHAIN","TIMESTAMP"],
            rows=[[l["device_id"],l["event_type"],l["description"][:60],
                   l["hash_chain"][:38]+"…",l["timestamp"][:19]] for l in filtered[:100]],
            col_colors={0:acc, 1:evt_color, 2:bright, 3:hash_c, 4:dim}
        )

# ═══════════════════════════════════════════════════════════════════════════════
# ALERTS
# ═══════════════════════════════════════════════════════════════════════════════
with tab_alerts:
    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    alert_list = db.fetch_alerts(org_id, limit=300)
    if not alert_list:
        st.success("✅ No threats detected — all systems nominal")
    else:
        df = pd.DataFrame(alert_list)
        c1,c2,c3,c4 = st.columns(4)
        hero_card(c1,"Total Incidents",len(df),"all time","🚨","#ef4444")
        hero_card(c2,"Critical",len(df[df["severity"]=="CRITICAL"]),"immediate action","💀","#ef4444")
        hero_card(c3,"High",len(df[df["severity"]=="HIGH"]),"investigate","⚠️","#f97316")
        hero_card(c4,"Attack Vectors",df["attack_type"].nunique(),"unique types","🎯","#6366f1")
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        fig2 = px.scatter(df, x="timestamp", y="attack_type", color="severity",
            color_discrete_map={"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308","LOW":"#22c55e"},
            symbol="device_id", hover_data=["detail","device_id"])
        fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#0f172a",
            font=dict(color="#4b5563",family="Inter"),
            margin=dict(l=0,r=0,t=10,b=0), height=260,
            legend=dict(bgcolor="rgba(0,0,0,0)"),
            xaxis=dict(gridcolor="#111827"), yaxis=dict(gridcolor="#111827"))
        st.plotly_chart(fig2, use_container_width=True)
        col_pie, col_bar = st.columns(2)
        with col_pie:
            pie = df["attack_type"].value_counts().reset_index()
            pie.columns = ["Type","Count"]
            fig3 = px.pie(pie, values="Count", names="Type", hole=0.55,
                color_discrete_sequence=["#6366f1","#ef4444","#f97316","#eab308","#22c55e"])
            fig3.update_layout(paper_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#9ca3af",family="Inter"),
                margin=dict(l=0,r=0,t=10,b=0), height=250)
            st.plotly_chart(fig3, use_container_width=True)
        with col_bar:
            bar = df["device_id"].value_counts().reset_index()
            bar.columns = ["Asset","Incidents"]
            fig4 = px.bar(bar, x="Asset", y="Incidents", color="Incidents",
                color_continuous_scale=["#1f2937","#6366f1","#ef4444"])
            fig4.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#0f172a",
                font=dict(color="#4b5563",family="Inter"),
                margin=dict(l=0,r=0,t=10,b=0), height=250,
                xaxis=dict(gridcolor="#111827"), yaxis=dict(gridcolor="#111827"),
                coloraxis_showscale=False)
            st.plotly_chart(fig4, use_container_width=True)
        scif_table(
            headers=["ASSET","ATTACK TYPE","SEVERITY","DETAIL","TIMESTAMP"],
            rows=[[a["device_id"],a["attack_type"],a["severity"],
                   (a["detail"] or "")[:60],a["timestamp"][:19]] for a in alert_list[:100]],
            col_colors={0:acc, 1:lambda v:"#f97316", 2:sev_color, 3:bright, 4:dim}
        )

# ═══════════════════════════════════════════════════════════════════════════════
# AI ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
with tab_ai:
    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-label'>LSTM Behavioral Models</div>", unsafe_allow_html=True)
    lstm_cols = st.columns(len(SIM_DEVICES))
    for col, (dev_id, _) in zip(lstm_cols, SIM_DEVICES.items()):
        with col:
            model  = forensic_engine.lstm_fleet.get_model(dev_id)
            step   = model._step if model else 0
            pct    = min(step/20*100, 100)
            color  = "#22c55e" if step >= 20 else "#f59e0b"
            status = "TRAINED" if step >= 20 else f"LEARNING {pct:.0f}%"
            st.markdown(
                f"<div style='background:#0f172a;border:1px solid #1f2937;"
                f"border-top:2px solid {color};border-radius:8px;padding:14px;text-align:center;'>"
                f"<div style='font-size:13px;font-weight:600;color:{color};'>{dev_id}</div>"
                f"<div style='font-family:JetBrains Mono,monospace;font-size:10px;color:#4b5563;margin:6px 0;'>"
                f"SAMPLES: {step}</div>"
                f"<div style='font-family:JetBrains Mono,monospace;font-size:11px;color:{color};'>{status}</div>"
                f"</div>", unsafe_allow_html=True
            )
    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-label'>Behavioral Fingerprints</div>", unsafe_allow_html=True)
    fp_snaps = forensic_engine.fingerprints.all_snapshots()
    if fp_snaps:
        scif_table(
            headers=["DEVICE","SAMPLES","TEMP MEAN","TEMP STD","TEMP MIN","TEMP MAX","HUM MEAN","DELTA MEAN","INTERVAL ms","RELIABLE"],
            rows=[[fp.get("device_id",""),fp.get("samples",0),fp.get("temp_mean",0),
                   fp.get("temp_std",0),fp.get("temp_min",0),fp.get("temp_max",0),
                   fp.get("humid_mean",0),fp.get("delta_mean",0),
                   fp.get("interval_mean_ms",0),"YES" if fp.get("reliable") else "NO"]
                  for fp in fp_snaps],
            col_colors={0:acc,1:bright,2:lambda v:"#f9fafb",3:dim,4:dim,5:dim,
                        6:lambda v:"#6ee7b7",7:bright,8:dim,
                        9:lambda v:"#22c55e" if v=="YES" else "#eab308"}
        )
    # Heatmap
    if all_alerts:
        st.markdown("<div class='section-label'>Threat Heatmap</div>", unsafe_allow_html=True)
        dfa = pd.DataFrame(all_alerts)
        dfa["timestamp"] = pd.to_datetime(dfa["timestamp"])
        dfa["minute"]    = dfa["timestamp"].dt.floor("1min").dt.strftime("%H:%M")
        dfa["sev_num"]   = dfa["severity"].map({"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}).fillna(1)
        pivot = dfa.groupby(["device_id","minute"])["sev_num"].max().reset_index()
        pivot = pivot.pivot(index="device_id",columns="minute",values="sev_num").fillna(0)
        fig_h = go.Figure(data=go.Heatmap(
            z=pivot.values, x=pivot.columns.tolist(), y=pivot.index.tolist(),
            colorscale=[[0,"#0f172a"],[0.33,"#312e81"],[0.66,"#9333ea"],[1,"#ef4444"]],
            showscale=True,
        ))
        fig_h.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#0f172a",
            font=dict(color="#4b5563",family="Inter"),
            margin=dict(l=0,r=0,t=10,b=0), height=200)
        st.plotly_chart(fig_h, use_container_width=True)

# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK PANEL
# ═══════════════════════════════════════════════════════════════════════════════
with tab_attack:
    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    if not can(user, "simulate_attacks"):
        st.error("⛔ You don't have permission to simulate attacks. Contact your admin.")
    else:
        st.warning("⚠️ Authorized penetration testing only. All injections are logged.")
        target = st.selectbox("Target Device", list(SIM_DEVICES.keys()))
        col_r, col_t, col_f = st.columns(3)
        def atk_card(col, title, desc, btn, fn, color):
            with col:
                st.markdown(
                    f"<div style='background:#0f172a;border:1px solid #1f2937;"
                    f"border-top:2px solid {color};border-radius:8px;padding:14px;margin-bottom:12px;'>"
                    f"<div style='font-size:12px;font-weight:600;color:{color};"
                    f"letter-spacing:1px;margin-bottom:8px;'>{title}</div>"
                    f"<div style='font-size:12px;color:#6b7280;line-height:1.6;'>{desc}</div>"
                    f"</div>", unsafe_allow_html=True
                )
                if st.button(btn, use_container_width=True):
                    st.error(fn(fleet, target))
        atk_card(col_r,"🔁 REPLAY ATTACK","Resends a captured valid packet. Nonce already registered → Layer 2 detects.","Inject Replay",attacks.simulate_replay,"#6366f1")
        atk_card(col_t,"✏️ TAMPERING ATTACK","Corrupts the packet hash. Hash-chain verification fails → CRITICAL.","Inject Tamper",attacks.simulate_tampering,"#ef4444")
        atk_card(col_f,"👾 FAKE DEVICE","Fabricated sensor values. LSTM + Z-score + fingerprint all trigger.","Inject Fake",attacks.simulate_fake_device,"#f59e0b")
        st.markdown("<div class='section-label'>Active Detection Layers</div>", unsafe_allow_html=True)
        scif_table(
            headers=["LAYER","METHOD","DETECTS","SEVERITY"],
            rows=[["L1","RSA-PSS Signature","Forged/fake device packets","HIGH"],
                  ["L2","Nonce Replay Shield","Replay attacks — 120s window","HIGH"],
                  ["L3","Blockchain Hash Chain","Any data tampering","CRITICAL"],
                  ["L4","Z-Score Anomaly","Sudden sensor spikes","MEDIUM"],
                  ["L5","Twin Divergence","Large delta vs verified state","HIGH"],
                  ["L6","LSTM Behavioral AI","Learned pattern deviations","MEDIUM"],
                  ["L7","Device Fingerprinting","Behavioral mismatch/spoofing","HIGH"],
                  ["L8","Forensic Log Chain","Retroactive log tampering","CRITICAL"]],
            col_colors={0:lambda v:"#a5b4fc",1:lambda v:"#d1d5db",2:lambda v:"#9ca3af",3:sev_color}
        )

# ═══════════════════════════════════════════════════════════════════════════════
# DEVICE MANAGER
# ═══════════════════════════════════════════════════════════════════════════════
with tab_devices:
    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-label'>Device Manager</div>", unsafe_allow_html=True)

    # Connection status card
    if mqtt_info["mode"] == "mqtt":
        st.success(f"✅ MQTT Connected — {mqtt_info['broker']}")
    else:
        st.markdown(
            f"<div style='background:#0f172a;border:1px solid #1f2937;border-radius:12px;padding:20px;margin-bottom:20px;'>"
            f"<div style='font-size:13px;font-weight:600;color:#f9fafb;margin-bottom:8px;'>📡 MQTT Connection Status</div>"
            f"<div style='display:flex;gap:12px;flex-wrap:wrap;'>"
            f"<span style='font-family:JetBrains Mono,monospace;font-size:11px;color:#4b5563;'>Broker: {MQTT_BROKER}:{MQTT_PORT}</span>"
            f"<span style='font-family:JetBrains Mono,monospace;font-size:11px;color:#ef4444;'>● {mqtt_info.get('error','Not connected')}</span>"
            f"</div>"
            f"<div style='margin-top:12px;font-size:12px;color:#6b7280;'>"
            f"To connect real devices, configure MQTT broker in config.py or set FDTP_MQTT_BROKER environment variable."
            f"</div></div>",
            unsafe_allow_html=True
        )

    # Registered devices table
    st.markdown("<div class='section-label'>Registered Devices</div>", unsafe_allow_html=True)
    devices = db.get_devices(org_id)
    if devices:
        scif_table(
            headers=["DEVICE ID","NAME","LOCATION","SOURCE","MQTT TOPIC","STATUS"],
            rows=[[d["device_id"],d["name"] or "—",d["location"] or "—",
                   d["source"],d["mqtt_topic"] or "—",
                   "ACTIVE" if d["is_active"] else "INACTIVE"] for d in devices],
            col_colors={0:acc,1:bright,2:dim,
                        3:lambda v:"#6366f1" if v=="simulator" else "#22c55e",
                        4:hash_c,
                        5:lambda v:"#22c55e" if v=="ACTIVE" else "#ef4444"}
        )

    # MQTT setup instructions
    st.markdown("<div class='section-label'>Connect a Real Device</div>", unsafe_allow_html=True)
    sel_dev = st.selectbox("Select device to get setup instructions", list(SIM_DEVICES.keys()))
    instructions = get_mqtt_setup_instructions(sel_dev)
    st.code(instructions, language="bash")

    # Add new device
    if can(user, "manage_devices"):
        st.markdown("<div class='section-label'>Register New Device</div>", unsafe_allow_html=True)
        with st.form("add_device_form"):
            col1, col2 = st.columns(2)
            with col1:
                new_dev_id  = st.text_input("Device ID",  placeholder="e.g. IoT_4")
                new_dev_name = st.text_input("Name",       placeholder="e.g. Warehouse Sensor")
            with col2:
                new_dev_loc  = st.text_input("Location",   placeholder="e.g. Warehouse A")
                new_dev_src  = st.selectbox("Source", ["simulator","mqtt"])
            new_dev_topic = st.text_input("MQTT Topic (if mqtt)", placeholder=f"fdtp/devices/IoT_4")
            if st.form_submit_button("Register Device"):
                if new_dev_id:
                    db.register_device(org_id, new_dev_id, new_dev_name,
                                       new_dev_loc, new_dev_src,
                                       new_dev_topic or None)
                    st.success(f"Device {new_dev_id} registered!")
                    st.rerun()
                else:
                    st.error("Device ID is required.")

# ═══════════════════════════════════════════════════════════════════════════════
# EVIDENCE EXPORT
# ═══════════════════════════════════════════════════════════════════════════════
with tab_evidence:
    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    if not can(user, "export_evidence"):
        st.error("⛔ You don't have permission to export evidence.")
    else:
        col_form, col_info = st.columns([1,1])
        with col_form:
            st.markdown("<div class='section-label'>Case Metadata</div>", unsafe_allow_html=True)
            case_id = st.text_input("Case ID",      value=f"CASE-{datetime.now(IST).strftime('%Y%m%d-%H%M')}")
            analyst = st.text_input("Analyst Name", value=user["full_name"] or user["username"])
            org_name= st.text_input("Organisation", value="Digital Forensics Unit")
            if st.button("🔒  Generate Evidence Package", use_container_width=True):
                with st.spinner("Compiling forensic evidence…"):
                    try:
                        from evidence_export import generate_evidence_pdf
                        out_path  = os.path.join(os.getcwd(), f"evidence_{case_id}.pdf")
                        file_hash = generate_evidence_pdf(out_path, case_id=case_id, analyst=analyst)
                        with open(out_path,"rb") as f:
                            pdf_bytes = f.read()
                        st.success("✅ Evidence package generated.")
                        st.code(f"SHA-256 INTEGRITY SEAL:\n{file_hash}", language=None)
                        st.download_button("⬇  Download Evidence PDF", pdf_bytes,
                                           file_name=f"forensic_evidence_{case_id}.pdf",
                                           mime="application/pdf", use_container_width=True)
                    except Exception as e:
                        st.error(f"Export failed: {e}")
        with col_info:
            st.markdown("<div class='section-label'>Package Contents</div>", unsafe_allow_html=True)
            scif_table(
                headers=["SECTION","CONTENTS"],
                rows=[["Cover Page","Case ID, analyst, classification, timestamp"],
                      ["Alert Log","All attack detections with severity + detail"],
                      ["Forensic Log Chain","Full blockchain-style event chain"],
                      ["Chain of Custody","Every packet: device → hash → timestamp"],
                      ["Integrity Seal","SHA-256 of entire PDF document"]],
                col_colors={0:acc, 1:bright}
            )

# ═══════════════════════════════════════════════════════════════════════════════
# USER MANAGEMENT (Admin only)
# ═══════════════════════════════════════════════════════════════════════════════
if tab_users and user["role"] == "admin":
    with tab_users:
        st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
        st.markdown("<div class='section-label'>User Management</div>", unsafe_allow_html=True)

        all_users = db.get_all_users(org_id)
        scif_table(
            headers=["ID","USERNAME","EMAIL","ROLE","FULL NAME","ACTIVE","CREATED","LAST LOGIN"],
            rows=[[u["id"],u["username"],u["email"],u["role"],
                   u["full_name"] or "—",
                   "YES" if u["is_active"] else "NO",
                   (u["created_at"] or "—")[:10],
                   (u["last_login"] or "Never")[:16]] for u in all_users],
            col_colors={
                0:dim, 1:acc, 2:bright,
                3:lambda v:{"admin":"#ef4444","analyst":"#f59e0b","viewer":"#22c55e"}.get(v,"#9ca3af"),
                4:bright, 5:lambda v:"#22c55e" if v=="YES" else "#ef4444",
                6:dim, 7:dim
            }
        )

        st.markdown("<div class='section-label'>Add New User</div>", unsafe_allow_html=True)
        with st.form("add_user_form"):
            col1, col2 = st.columns(2)
            with col1:
                n_fullname = st.text_input("Full Name")
                n_username = st.text_input("Username")
                n_email    = st.text_input("Email")
            with col2:
                n_role     = st.selectbox("Role", ["viewer","analyst","admin"])
                n_password = st.text_input("Password", type="password")
                n_confirm  = st.text_input("Confirm Password", type="password")
            if st.form_submit_button("Create User"):
                if not all([n_fullname, n_username, n_email, n_role, n_password]):
                    st.error("All fields required.")
                elif n_password != n_confirm:
                    st.error("Passwords do not match.")
                elif len(n_password) < 6:
                    st.error("Password must be at least 6 characters.")
                else:
                    result = db.register_user(org_id, n_username, n_email,
                                              n_password, n_role, n_fullname)
                    if result["ok"]:
                        st.success(f"User {n_username} created with role {n_role}.")
                        st.rerun()
                    else:
                        st.error(f"Failed: {result['error']}")

        st.markdown("<div class='section-label'>Deactivate / Reactivate User</div>", unsafe_allow_html=True)
        col_uid, col_action = st.columns([1,1])
        with col_uid:
            toggle_uid = st.number_input("User ID", min_value=1, step=1)
        with col_action:
            toggle_act = st.selectbox("Action", ["Deactivate","Reactivate"])
        if st.button("Apply"):
            if toggle_uid == user["id"]:
                st.error("You cannot deactivate yourself.")
            else:
                db.toggle_user(int(toggle_uid), toggle_act=="Reactivate")
                st.success(f"User {toggle_uid} {toggle_act.lower()}d.")
                st.rerun()

# ── Logout button ─────────────────────────────────────────────────────────────
st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)
col_spacer, col_logout = st.columns([8, 1])
with col_logout:
    if st.button("Sign Out"):
        logout()

# ── Auto refresh ──────────────────────────────────────────────────────────────
auto_r = st.sidebar.toggle("Auto-refresh", value=True)
if auto_r:
    time.sleep(REFRESH_INTERVAL)
    st.rerun()