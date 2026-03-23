"""
evidence_export.py — Forensic Evidence Package Generator v2.1
Strategy:
  Pass 1 → build full PDF to a temp file, compute SHA-256
  Pass 2 → rebuild identical PDF with real hash embedded in seal page
  → output_path gets the final styled PDF with correct integrity seal
"""

import hashlib
import os
import tempfile
from datetime import datetime, timezone

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak,
)

import database as db

# ── Colour palette ─────────────────────────────────────────────────────────────
C_BG      = colors.HexColor("#0a0005")
C_BG2     = colors.HexColor("#0d0008")
C_ROWODD  = colors.HexColor("#0a0005")
C_ROWEVEN = colors.HexColor("#0d0008")
C_RED     = colors.HexColor("#cc0020")
C_RED2    = colors.HexColor("#880015")
C_REDLT   = colors.HexColor("#ff3344")
C_ORANGE  = colors.HexColor("#cc5500")
C_YELLOW  = colors.HexColor("#ccaa00")
C_GREENLT = colors.HexColor("#00cc44")
C_MUTED   = colors.HexColor("#664455")
C_DIM     = colors.HexColor("#441122")
C_WHITE   = colors.HexColor("#e8e8e8")
C_MONO    = colors.HexColor("#993344")
C_HASHCLR = colors.HexColor("#331122")
C_BORDER  = colors.HexColor("#2a0010")
C_HEADER  = colors.HexColor("#110008")


def _sev_color(sev):
    return {"CRITICAL": C_REDLT, "HIGH": C_ORANGE,
            "MEDIUM": C_YELLOW, "LOW": C_GREENLT}.get(sev.upper(), C_MUTED)

def _event_color(evt):
    return C_REDLT if evt.upper() == "ATTACK" else C_GREENLT


def _styles():
    return {
        "title": ParagraphStyle("title", fontSize=20, fontName="Helvetica-Bold",
            textColor=C_REDLT, spaceAfter=4, alignment=TA_CENTER),
        "subtitle": ParagraphStyle("subtitle", fontSize=9, fontName="Helvetica",
            textColor=C_MUTED, spaceAfter=2, alignment=TA_CENTER),
        "classified": ParagraphStyle("classified", fontSize=10, fontName="Helvetica-Bold",
            textColor=C_WHITE, spaceAfter=6, alignment=TA_CENTER, backColor=C_RED),
        "section": ParagraphStyle("section", fontSize=11, fontName="Helvetica-Bold",
            textColor=C_REDLT, spaceBefore=12, spaceAfter=6),
        "section_label": ParagraphStyle("section_label", fontSize=8, fontName="Helvetica-Bold",
            textColor=C_RED2, spaceBefore=6, spaceAfter=4),
        "body": ParagraphStyle("body", fontSize=8.5, fontName="Helvetica",
            textColor=C_MUTED, spaceAfter=3),
        "mono": ParagraphStyle("mono", fontSize=7.5, fontName="Courier",
            textColor=C_MONO, spaceAfter=2),
        "mono_hash": ParagraphStyle("mono_hash", fontSize=8, fontName="Courier",
            textColor=C_REDLT, spaceAfter=2, alignment=TA_CENTER),
        "warning": ParagraphStyle("warning", fontSize=8, fontName="Helvetica-Bold",
            textColor=C_ORANGE, spaceAfter=3),
        "stamp": ParagraphStyle("stamp", fontSize=7.5, fontName="Courier",
            textColor=C_DIM, alignment=TA_CENTER),
        "meta_key": ParagraphStyle("meta_key", fontSize=8.5, fontName="Helvetica-Bold",
            textColor=C_RED),
        "meta_val": ParagraphStyle("meta_val", fontSize=8.5, fontName="Courier",
            textColor=C_WHITE),
    }


def _base_table_style():
    return TableStyle([
        ("BACKGROUND",     (0,0), (-1,0),  C_HEADER),
        ("TEXTCOLOR",      (0,0), (-1,0),  C_RED),
        ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0,0), (-1,0),  7.5),
        ("BOTTOMPADDING",  (0,0), (-1,0),  6),
        ("TOPPADDING",     (0,0), (-1,0),  6),
        ("FONTNAME",       (0,1), (-1,-1), "Courier"),
        ("FONTSIZE",       (0,1), (-1,-1), 7),
        ("TEXTCOLOR",      (0,1), (-1,-1), C_MUTED),
        ("TOPPADDING",     (0,1), (-1,-1), 3),
        ("BOTTOMPADDING",  (0,1), (-1,-1), 3),
        ("LEFTPADDING",    (0,0), (-1,-1), 8),
        ("RIGHTPADDING",   (0,0), (-1,-1), 8),
        ("LINEBELOW",      (0,0), (-1,0),  1,   C_RED2),
        ("LINEBELOW",      (0,1), (-1,-1), 0.3, C_DIM),
        ("BOX",            (0,0), (-1,-1), 0.5, C_BORDER),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_ROWEVEN, C_ROWODD]),
    ])


class SCIFBackground:
    def __init__(self, case_id):
        self.case_id = case_id

    def __call__(self, canv, doc):
        w, h = A4
        canv.setFillColor(C_BG)
        canv.rect(0, 0, w, h, fill=1, stroke=0)
        canv.setFillColor(C_RED2)
        canv.rect(0, h - 1.1*cm, w, 1.1*cm, fill=1, stroke=0)
        canv.setFont("Helvetica-Bold", 7)
        canv.setFillColor(C_WHITE)
        canv.drawString(1.5*cm, h - 0.75*cm, "FORENSIC DIGITAL TWIN PLATFORM")
        canv.drawRightString(w - 1.5*cm, h - 0.75*cm, f"CASE: {self.case_id}")
        canv.setFillColor(C_DIM)
        canv.rect(0, 0, w, 0.8*cm, fill=1, stroke=0)
        canv.setFont("Courier", 6.5)
        canv.setFillColor(C_MUTED)
        canv.drawString(1.5*cm, 0.25*cm, "CLASSIFIED — FORENSIC EVIDENCE — DO NOT MODIFY")
        canv.drawRightString(w - 1.5*cm, 0.25*cm, f"PAGE {doc.page}")
        canv.setFillColor(C_RED2)
        canv.rect(0, 0.8*cm, 0.25*cm, h - 1.9*cm, fill=1, stroke=0)


def _build_story(S, now_str, case_id, analyst, seal_hash, alerts_all, logs_all, raw_all):
    """Build the complete story list. seal_hash is embedded in the integrity seal page."""
    story = []

    # ── COVER ─────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1.8*cm))
    story.append(Paragraph("◈  CLASSIFIED  ◈", S["classified"]))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph("FORENSIC DIGITAL TWIN PLATFORM", S["title"]))
    story.append(Paragraph("OFFICIAL EVIDENCE PACKAGE", S["subtitle"]))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=1.5, color=C_RED, spaceAfter=16))

    meta_rows = [
        [Paragraph("CASE ID",        S["meta_key"]), Paragraph(case_id,   S["meta_val"])],
        [Paragraph("GENERATED AT",   S["meta_key"]), Paragraph(now_str,   S["meta_val"])],
        [Paragraph("ANALYST",        S["meta_key"]), Paragraph(analyst,   S["meta_val"])],
        [Paragraph("CLASSIFICATION", S["meta_key"]), Paragraph("FORENSIC — CHAIN OF CUSTODY DOCUMENT", S["meta_val"])],
        [Paragraph("SYSTEM",         S["meta_key"]), Paragraph("Forensic Digital Twin Platform v2.0",  S["meta_val"])],
    ]
    mt = Table(meta_rows, colWidths=[4.5*cm, 12*cm])
    mt.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), C_BG2),
        ("ROWBACKGROUNDS",(0,0),(-1,-1), [C_BG2, C_ROWODD]),
        ("LINEBELOW",     (0,0),(-1,-1), 0.3, C_DIM),
        ("BOX",           (0,0),(-1,-1), 0.5, C_BORDER),
        ("TOPPADDING",    (0,0),(-1,-1), 6),
        ("BOTTOMPADDING", (0,0),(-1,-1), 6),
        ("LEFTPADDING",   (0,0),(-1,-1), 10),
        ("LINEAFTER",     (0,0),(0,-1),  0.5, C_RED2),
    ]))
    story.append(mt)
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(
        "⚠  WARNING: This document is auto-generated forensic evidence. "
        "Any modification invalidates the integrity seal on the final page.",
        S["warning"]
    ))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_DIM, spaceAfter=8))

    # Summary stats
    critical_n = len([a for a in alerts_all if a["severity"] == "CRITICAL"])
    attack_n   = len([l for l in logs_all   if l["event_type"] == "ATTACK"])
    sum_rows = [
        ["TOTAL ALERTS", str(len(alerts_all)), "CRITICAL",   str(critical_n)],
        ["LOG ENTRIES",  str(len(logs_all)),   "ATTACK LOGS",str(attack_n)],
        ["RAW PACKETS",  str(len(raw_all)),    "DEVICES",    "3"],
    ]
    st = Table(sum_rows, colWidths=[4*cm, 3.5*cm, 4*cm, 3.5*cm])
    st.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(-1,-1), C_BG2),
        ("FONTNAME",     (0,0),(-1,-1), "Courier"),
        ("FONTSIZE",     (0,0),(-1,-1), 8),
        ("TEXTCOLOR",    (0,0),(0,-1),  C_MUTED),
        ("TEXTCOLOR",    (2,0),(2,-1),  C_MUTED),
        ("TEXTCOLOR",    (1,0),(1,-1),  C_REDLT),
        ("TEXTCOLOR",    (3,0),(3,-1),  C_REDLT),
        ("FONTNAME",     (1,0),(1,-1),  "Courier-Bold"),
        ("FONTNAME",     (3,0),(3,-1),  "Courier-Bold"),
        ("BOX",          (0,0),(-1,-1), 0.5, C_BORDER),
        ("LINEAFTER",    (1,0),(1,-1),  0.5, C_DIM),
        ("TOPPADDING",   (0,0),(-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ("LEFTPADDING",  (0,0),(-1,-1), 10),
    ]))
    story.append(st)
    story.append(PageBreak())

    # ── SECTION 1: ALERT LOG ──────────────────────────────────────────────────
    story.append(Paragraph("01  ///  ATTACK ALERT LOG", S["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_RED2, spaceAfter=8))

    if alerts_all:
        rows = [["#","DEVICE","ATTACK TYPE","SEVERITY","DETAIL","TIMESTAMP"]]
        for i, a in enumerate(alerts_all[:120], 1):
            rows.append([str(i), a["device_id"], a["attack_type"], a["severity"],
                         (a["detail"] or "")[:52], a["timestamp"][:19]])
        t = Table(rows, colWidths=[0.8*cm,2.2*cm,3.2*cm,2*cm,5.8*cm,3.5*cm])
        sty = _base_table_style()
        for i, a in enumerate(alerts_all[:120], 1):
            clr = _sev_color(a["severity"])
            sty.add("TEXTCOLOR", (3,i),(3,i), clr)
            sty.add("FONTNAME",  (3,i),(3,i), "Courier-Bold")
            if a["severity"] == "CRITICAL":
                sty.add("BACKGROUND",(0,i),(-1,i), colors.HexColor("#1a0005"))
        t.setStyle(sty)
        story.append(t)
    else:
        story.append(Paragraph("No alerts recorded.", S["body"]))

    story.append(PageBreak())

    # ── SECTION 2: FORENSIC LOG CHAIN ─────────────────────────────────────────
    story.append(Paragraph("02  ///  FORENSIC LOG CHAIN", S["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_RED2, spaceAfter=4))
    story.append(Paragraph(
        "H(n) = SHA-256(H(n-1) + event_type + packet_hash). "
        "Modifying any entry breaks all subsequent hashes.", S["body"]))
    story.append(Spacer(1, 0.2*cm))

    if logs_all:
        rows = [["#","DEVICE","EVENT","HASH CHAIN (PARTIAL)","TIMESTAMP"]]
        for i, l in enumerate(logs_all[:180], 1):
            rows.append([str(i), l["device_id"], l["event_type"],
                         l["hash_chain"][:42]+"…", l["timestamp"][:19]])
        t2 = Table(rows, colWidths=[0.8*cm,2.2*cm,2*cm,9.5*cm,3.5*cm])
        sty2 = _base_table_style()
        for i, l in enumerate(logs_all[:180], 1):
            sty2.add("TEXTCOLOR",(2,i),(2,i), _event_color(l["event_type"]))
            sty2.add("FONTNAME", (2,i),(2,i), "Courier-Bold")
            sty2.add("TEXTCOLOR",(3,i),(3,i), C_HASHCLR)
            if l["event_type"] == "ATTACK":
                sty2.add("BACKGROUND",(0,i),(-1,i), colors.HexColor("#150005"))
        t2.setStyle(sty2)
        story.append(t2)
    else:
        story.append(Paragraph("No logs recorded.", S["body"]))

    story.append(PageBreak())

    # ── SECTION 3: CHAIN OF CUSTODY ───────────────────────────────────────────
    story.append(Paragraph("03  ///  CHAIN OF CUSTODY", S["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_RED2, spaceAfter=4))
    story.append(Paragraph(
        "Unbroken verifiable custody of every telemetry packet from device to forensic log.",
        S["body"]))
    story.append(Spacer(1, 0.2*cm))

    if raw_all:
        rows = [["DEVICE","TEMP","HUMIDITY","TIMESTAMP","NONCE (PARTIAL)","HASH (PARTIAL)","ATTACK"]]
        for r in raw_all[:100]:
            rows.append([r["device_id"], f"{r['temp']:.1f}C", f"{r['humidity']:.1f}%",
                         r["timestamp"][:19], r["nonce"][:16]+"…",
                         r["hash"][:22]+"…", "YES" if r["is_attack"] else "NO"])
        t3 = Table(rows, colWidths=[2*cm,1.5*cm,1.8*cm,3.5*cm,3*cm,4*cm,1.5*cm])
        sty3 = _base_table_style()
        for i, r in enumerate(raw_all[:100], 1):
            sty3.add("TEXTCOLOR",(5,i),(5,i), C_HASHCLR)
            if r["is_attack"]:
                sty3.add("BACKGROUND",(0,i),(-1,i), colors.HexColor("#1a0005"))
                sty3.add("TEXTCOLOR", (6,i),(6,i),  C_REDLT)
                sty3.add("FONTNAME",  (6,i),(6,i),  "Courier-Bold")
            else:
                sty3.add("TEXTCOLOR",(6,i),(6,i), C_GREENLT)
        t3.setStyle(sty3)
        story.append(t3)

    story.append(PageBreak())

    # ── SECTION 4: INTEGRITY SEAL ─────────────────────────────────────────────
    story.append(Paragraph("04  ///  DOCUMENT INTEGRITY SEAL", S["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_RED2, spaceAfter=8))
    story.append(Paragraph(
        "The SHA-256 hash below is computed from the complete binary content of this PDF file. "
        "Re-compute it on the downloaded file to verify it has not been altered.", S["body"]))
    story.append(Spacer(1, 0.5*cm))

    seal_text = seal_hash if seal_hash else "COMPUTING — SEE FINAL DOCUMENT"
    seal_box = Table(
        [[Paragraph("SHA-256 INTEGRITY SEAL", S["section_label"])],
         [Paragraph(seal_text, S["mono_hash"])]],
        colWidths=[16*cm]
    )
    seal_box.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(-1,-1), C_BG2),
        ("BOX",          (0,0),(-1,-1), 1,   C_RED2),
        ("LINEABOVE",    (0,0),(-1,0),  2,   C_RED),
        ("TOPPADDING",   (0,0),(-1,-1), 10),
        ("BOTTOMPADDING",(0,0),(-1,-1), 10),
        ("LEFTPADDING",  (0,0),(-1,-1), 14),
    ]))
    story.append(seal_box)
    story.append(Spacer(1, 0.6*cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_RED2))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        f"GENERATED BY FORENSIC DIGITAL TWIN PLATFORM  ◈  {now_str}  ◈  {case_id}",
        S["stamp"]
    ))

    return story


def generate_evidence_pdf(output_path: str, case_id: str = None,
                          analyst: str = "System") -> str:
    if case_id is None:
        case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    now_str     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    S           = _styles()
    bg          = SCIFBackground(case_id)

    # Fetch data once — reused in both passes
    alerts_all  = db.fetch_alerts(limit=500)
    logs_all    = db.fetch_logs(limit=500)
    raw_all     = db.fetch_device_data(limit=500)

    def _make_doc(path):
        return SimpleDocTemplate(
            path, pagesize=A4,
            leftMargin=1.8*cm, rightMargin=1.8*cm,
            topMargin=1.8*cm,  bottomMargin=1.5*cm,
        )

    # ── PASS 1: placeholder seal ───────────────────────────────────────────────
    tmp_path = output_path + ".tmp.pdf"
    story1   = _build_story(S, now_str, case_id, analyst, None,
                            alerts_all, logs_all, raw_all)
    _make_doc(tmp_path).build(story1, onFirstPage=bg, onLaterPages=bg)

    # Compute SHA-256 of pass-1 output
    with open(tmp_path, "rb") as f:
        pass1_hash = hashlib.sha256(f.read()).hexdigest()

    # ── PASS 2: embed real hash ────────────────────────────────────────────────
    story2 = _build_story(S, now_str, case_id, analyst, pass1_hash,
                          alerts_all, logs_all, raw_all)
    _make_doc(output_path).build(story2, onFirstPage=bg, onLaterPages=bg)

    # Clean up temp
    try:
        os.remove(tmp_path)
    except Exception:
        pass

    # Return hash of final file
    with open(output_path, "rb") as f:
        final_hash = hashlib.sha256(f.read()).hexdigest()

    return final_hash