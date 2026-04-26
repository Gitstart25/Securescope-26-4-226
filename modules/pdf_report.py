import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart


# ---------------- REMOVE DUPLICATES ----------------
def get_unique_vulnerabilities(true_positives):
    seen = set()
    unique_alerts = []

    for alert in true_positives:
        identifier = (
            alert.get("alert", "").lower().strip(),
            alert.get("url", "").split("?")[0],
            alert.get("param", "").lower().strip()
        )

        if identifier not in seen:
            seen.add(identifier)
            unique_alerts.append(alert)

    return unique_alerts


# ---------------- MERGE VULNERABILITIES ----------------
def merge_vulnerabilities(alerts, max_items=5):
    merged = {}

    for alert in alerts:
        key = (
            alert.get("alert", "Unknown"),
            alert.get("risk", "NA")
        )

        if key not in merged:
            merged[key] = {
                "alert": alert.get("alert", "Unknown"),
                "risk": alert.get("risk", "NA"),
                "cwe": alert.get("cweid", "NA"),
                "urls": set(),
                "params": set(),
                "count": 0
            }

        merged[key]["urls"].add(alert.get("url", "NA"))
        merged[key]["params"].add(alert.get("param", "NA"))
        merged[key]["count"] += 1

    # Limit entries (IMPORTANT for page control)
    for key in merged:
        merged[key]["urls"] = list(merged[key]["urls"])[:max_items]
        merged[key]["params"] = list(merged[key]["params"])[:max_items]

    return list(merged.values())


# ---------------- RISK COLOR ----------------
def get_risk_color(risk):
    risk = str(risk).lower()

    if "high" in risk:
        return colors.red
    elif "medium" in risk:
        return colors.orange
    elif "low" in risk:
        return colors.green
    else:
        return colors.black


# ---------------- CHART ----------------
def create_risk_chart(alerts):
    risk_count = {"High": 0, "Medium": 0, "Low": 0}

    for alert in alerts:
        risk = str(alert.get("risk", "")).capitalize()
        if risk in risk_count:
            risk_count[risk] += 1

    drawing = Drawing(400, 200)
    chart = VerticalBarChart()

    chart.x = 50
    chart.y = 50
    chart.height = 125
    chart.width = 300

    chart.data = [list(risk_count.values())]
    chart.categoryAxis.categoryNames = list(risk_count.keys())

    drawing.add(chart)
    return drawing


# ---------------- MAIN FUNCTION ----------------
def generate_pdf_report(target_url, true_positives):
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"reports/SecureScope_Report_{timestamp}.pdf"

    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    # ---------------- HEADER ----------------
    elements.append(Paragraph("<b>SecureScope Vulnerability Report</b>", styles["Title"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph(f"<b>Target:</b> {target_url}", styles["Normal"]))
    elements.append(
        Paragraph(
            f"<b>Generated:</b> {datetime.now().strftime('%d %b %Y %H:%M:%S')}",
            styles["Normal"]
        )
    )
    elements.append(Spacer(1, 20))

    # ---------------- STEP 1: REMOVE DUPLICATES ----------------
    unique_alerts = get_unique_vulnerabilities(true_positives)

    # ---------------- STEP 2: MERGE ----------------
    merged_alerts = merge_vulnerabilities(unique_alerts, max_items=5)

    # ---------------- SUMMARY ----------------
    elements.append(Paragraph("<b>Summary</b>", styles["Heading2"]))
    elements.append(
        Paragraph(
            f"Total Unique Vulnerability Types: <b>{len(merged_alerts)}</b>",
            styles["Normal"]
        )
    )
    elements.append(Spacer(1, 20))

    # ---------------- NO FINDINGS ----------------
    if not merged_alerts:
        elements.append(
            Paragraph(
                "No confirmed true positive vulnerabilities were identified.",
                styles["Normal"]
            )
        )
        doc.build(elements)
        return output_path

    # ---------------- CHART ----------------
    elements.append(create_risk_chart(unique_alerts))
    elements.append(Spacer(1, 20))

    # ---------------- COMPACT VULNERABILITY TABLES ----------------
    for idx, vuln in enumerate(merged_alerts, 1):

        risk_color = get_risk_color(vuln["risk"])

        elements.append(
            Paragraph(
                f"<b>{idx}. {vuln['alert']} ({vuln['risk']})</b>",
                styles["Heading3"]
            )
        )
        elements.append(Spacer(1, 6))

        urls_str = "<br/>".join(vuln["urls"])
        params_str = ", ".join(vuln["params"])

        table_data = [
            ["Risk", vuln["risk"]],
            ["CWE", str(vuln["cwe"])],
            ["Affected URLs", urls_str],
            ["Parameters", params_str],
            ["Occurrences", str(vuln["count"])]
        ]

        table = Table(table_data, colWidths=[140, 360])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("TEXTCOLOR", (1, 0), (1, 0), risk_color),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 20))

    # ---------------- BUILD ----------------
    doc.build(elements)
    return output_path