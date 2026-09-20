from __future__ import annotations
import io
import json
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors


def build_json(result):
    return json.dumps(result, indent=2, default=str)


def build_pdf(result):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("SecureMailScope — Cryptographic Security Posture Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Capture: {result.get('filename', 'unknown')}", styles["Normal"]),
        Paragraph(f"Posture score: {result.get('score', 'N/A')}/100", styles["Normal"]),
        Paragraph(f"Risk level: {result.get('risk_level', 'N/A')}", styles["Normal"]),
        Spacer(1, 12),
    ]

    rows = [["Session", "Protocol", "STARTTLS", "TLS", "Handshake", "Certificates"]]
    for session in result.get("sessions", []):
        rows.append([
            session.get("id"),
            session.get("protocol"),
            "Yes" if session.get("starttls") else "No",
            "Yes" if session.get("tls_seen") else "No",
            str(session.get("tls_handshake_count", 0)),
            str(len(session.get("certificates", []))),
        ])
    table = Table(rows, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17324d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.extend([table, Spacer(1, 14), Paragraph("Findings", styles["Heading2"])])

    for item in result.get("findings", []):
        story.append(Paragraph(
            f"<b>{item.get('severity', '').upper()} — {item.get('title', '')}</b><br/>{item.get('evidence', '')}<br/><i>Remediation: {item.get('remediation', '')}</i>",
            styles["BodyText"],
        ))
        story.append(Spacer(1, 8))

    story.append(Paragraph("Evidence limitations", styles["Heading2"]))
    for item in result.get("limitations", []):
        story.append(Paragraph(f"• {item}", styles["BodyText"]))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
