import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart


# =================================================
# REMOVE DUPLICATES
# =================================================
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


# =================================================
# MERGE SAME TYPE VULNERABILITIES
# =================================================
def merge_vulnerabilities(alerts, max_items=5):
    merged = {}

    for alert in alerts:
        key = (
            alert.get("alert", "Unknown"),
            alert.get("risk", "Low")
        )

        if key not in merged:
            merged[key] = {
                "alert": alert.get("alert", "Unknown"),
                "risk": alert.get("risk", "Low"),
                "cwe": alert.get("cweid", "NA"),
                "urls": set(),
                "params": set(),
                "count": 0
            }

        merged[key]["urls"].add(alert.get("url", "NA"))
        merged[key]["params"].add(alert.get("param", "NA"))
        merged[key]["count"] += 1

    for key in merged:
        merged[key]["urls"] = list(merged[key]["urls"])
        merged[key]["params"] = list(merged[key]["params"])[:max_items]

    return list(merged.values())


# =================================================
# CLEAN URL FORMAT
# =================================================
def format_urls(urls, max_show=3):
    cleaned_urls = []

    for url in urls[:max_show]:
        try:
            parts = url.split("/")[3:]
            short_url = "/" + "/".join(parts)

            if short_url == "/":
                short_url = url

            cleaned_urls.append(f"• {short_url}")

        except Exception:
            cleaned_urls.append(f"• {url}")

    remaining = len(urls) - max_show

    if remaining > 0:
        cleaned_urls.append(f"(+ {remaining} more URLs)")

    return "<br/>".join(cleaned_urls)


# =================================================
# RISK COLOR
# =================================================
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


# =================================================
# IMPROVED SECURITY SCORE
# =================================================
def calculate_security_score(alerts):
    """
    Improved realistic scoring system

    High Risk   → -7
    Medium Risk → -4
    Low Risk    → -2

    Minimum score fixed at 25
    """

    if not alerts:
        return 100

    high_count = 0
    medium_count = 0
    low_count = 0

    for alert in alerts:
        risk = str(alert.get("risk", "")).lower()

        if "high" in risk:
            high_count += 1
        elif "medium" in risk:
            medium_count += 1
        elif "low" in risk:
            low_count += 1

    deduction = (
        (high_count * 7) +
        (medium_count * 4) +
        (low_count * 2)
    )

    score = 100 - deduction

    if score < 25:
        score = 25

    if score > 100:
        score = 100

    return score


# =================================================
# TOP PRIORITY FIXES
# =================================================
def get_top_priority_fixes(merged_alerts):
    priority_list = []

    for vuln in merged_alerts:
        risk = str(vuln["risk"]).lower()

        if "high" in risk or "medium" in risk:
            priority_list.append(vuln["alert"])

    return priority_list[:5]


# =================================================
# FIX RECOMMENDATIONS
# =================================================
def get_fix_recommendation(vuln_name):
    fixes = {
        "Content Security Policy (CSP) Header Not Set":
            "Add Content-Security-Policy headers to prevent unsafe script execution.",

        "Missing Anti-clickjacking Header":
            "Add X-Frame-Options header as DENY or SAMEORIGIN.",

        "Absence of Anti-CSRF Tokens":
            "Implement CSRF tokens for sensitive forms and requests.",

        "Cookie Without Secure Flag":
            "Enable Secure flag to allow cookies only over HTTPS.",

        "Cookie No HttpOnly Flag":
            "Enable HttpOnly flag to prevent JavaScript access to cookies.",

        "Cookie without SameSite Attribute":
            "Use SameSite=Strict or SameSite=Lax for session security.",

        "Strict-Transport-Security Header Not Set":
            "Enable HSTS header to enforce HTTPS communication.",

        "Hidden File Found":
            "Block access to hidden files like .git, .svn and config files."
    }

    return fixes.get(
        vuln_name,
        "Review server configuration and apply security best practices."
    )


# =================================================
# RISK DISTRIBUTION CHART
# =================================================
def create_risk_chart(alerts):
    risk_count = {
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for alert in alerts:
        risk = str(alert.get("risk", "")).capitalize()

        if risk in risk_count:
            risk_count[risk] += 1

    drawing = Drawing(400, 220)

    chart = VerticalBarChart()
    chart.x = 50
    chart.y = 50
    chart.height = 130
    chart.width = 300

    chart.data = [list(risk_count.values())]
    chart.categoryAxis.categoryNames = list(risk_count.keys())

    drawing.add(chart)
    return drawing


# =================================================
# MAIN PDF REPORT
# =================================================
def generate_pdf_report(target_url, true_positives):
    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"reports/SecureScope_Report_{timestamp}.pdf"

    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    # =================================================
    # HEADER
    # =================================================
    elements.append(
        Paragraph(
            "<b>SecureScope Vulnerability Analysis & Remediation Report</b>",
            styles["Title"]
        )
    )

    elements.append(Spacer(1, 12))

    elements.append(
        Paragraph(
            f"<b>Target URL:</b> {target_url}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Generated On:</b> {datetime.now().strftime('%d %b %Y %H:%M:%S')}",
            styles["Normal"]
        )
    )

    elements.append(Spacer(1, 20))

    # =================================================
    # CLEAN + MERGE
    # =================================================
    unique_alerts = get_unique_vulnerabilities(true_positives)
    merged_alerts = merge_vulnerabilities(unique_alerts)

    if not merged_alerts:
        elements.append(
            Paragraph(
                "No confirmed true positive vulnerabilities were found.",
                styles["Normal"]
            )
        )
        doc.build(elements)
        return output_path

    # =================================================
    # EXECUTIVE SUMMARY
    # =================================================
    security_score = calculate_security_score(unique_alerts)

    elements.append(
        Paragraph("<b>Executive Summary</b>", styles["Heading2"])
    )

    elements.append(
        Paragraph(
            f"Total Unique Vulnerability Types: <b>{len(merged_alerts)}</b>",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"Security Score: <b>{security_score} / 100</b>",
            styles["Normal"]
        )
    )

    elements.append(Spacer(1, 10))

    # =================================================
    # TOP PRIORITY FIXES
    # =================================================
    elements.append(
        Paragraph("<b>Top Priority Fixes</b>", styles["Heading3"])
    )

    top_fixes = get_top_priority_fixes(merged_alerts)

    for fix in top_fixes:
        elements.append(
            Paragraph(f"• {fix}", styles["Normal"])
        )

    elements.append(Spacer(1, 20))

    # =================================================
    # CHART
    # =================================================
    elements.append(
        Paragraph("<b>Risk Distribution</b>", styles["Heading3"])
    )

    elements.append(create_risk_chart(unique_alerts))
    elements.append(Spacer(1, 20))

    # =================================================
    # DETAILED ANALYSIS
    # =================================================
    elements.append(
        Paragraph("<b>Detailed Vulnerability Analysis</b>", styles["Heading2"])
    )

    for idx, vuln in enumerate(merged_alerts, 1):
        risk_color = get_risk_color(vuln["risk"])

        elements.append(
            Paragraph(
                f"<b>{idx}. {vuln['alert']} ({vuln['risk']})</b>",
                styles["Heading3"]
            )
        )

        elements.append(Spacer(1, 6))

        urls_str = format_urls(vuln["urls"])
        params_str = ", ".join(vuln["params"])

        table_data = [
            ["Severity", vuln["risk"]],
            ["CWE ID", str(vuln["cwe"])],
            ["Affected Endpoints", f"{len(vuln['urls'])} URLs"],
            ["Top URLs", urls_str],
            ["Parameters", params_str],
            ["Occurrences", str(vuln["count"])],
            ["Recommended Fix", get_fix_recommendation(vuln["alert"])]
        ]

        table = Table(table_data, colWidths=[150, 350])

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("TEXTCOLOR", (1, 0), (1, 0), risk_color),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 20))

    # =================================================
    # DEVELOPER ACTION CHECKLIST
    # =================================================
    elements.append(
        Paragraph("<b>Developer Action Checklist</b>", styles["Heading2"])
    )

    checklist = [
        "Add Content Security Policy (CSP)",
        "Enable Secure + HttpOnly Cookies",
        "Implement Anti-CSRF Protection",
        "Enable HSTS Header",
        "Add X-Frame-Options Header",
        "Remove Public Hidden Files Access"
    ]

    for item in checklist:
        elements.append(
            Paragraph(f"☐ {item}", styles["Normal"])
        )

    # =================================================
    # BUILD PDF
    # =================================================
    doc.build(elements)

    return output_path