from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
from datetime import datetime

# ---------------- MODULE IMPORTS ----------------
from modules.zap_scanner import run_zap_scan
from modules.zap_cwe_cve_mapper import map_zap_alerts
from modules.model_predictor import predict_true_positives
from modules.pdf_report import generate_pdf_report
# ------------------------------------------------

app = Flask(__name__)
CORS(app)

# ------------------------------------------------
# GLOBAL VARIABLE (IMPORTANT)
# ------------------------------------------------
latest_report_path = None

# ------------------------------------------------
# CREATE REPORTS DIRECTORY
# ------------------------------------------------
REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)


# ------------------------------------------------
# HEALTH CHECK
# ------------------------------------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "SecureScope Backend Running"})


# ------------------------------------------------
# MAIN SCAN ENDPOINT
# ------------------------------------------------
@app.route("/scan", methods=["POST"])
def scan():
    global latest_report_path

    try:
        data = request.get_json()
        if not data or "url" not in data:
            return jsonify({"error": "URL is required"}), 400

        target_url = data["url"]

        print(f"\n[+] Starting scan for: {target_url}")

        # ------------------------------------------------
        # 1️⃣ RUN ZAP SCAN
        # ------------------------------------------------
        zap_alerts = run_zap_scan(target_url)

        if not zap_alerts:
            return jsonify({"message": "No alerts found"}), 200

        print(f"[✔] ZAP Alerts Found: {len(zap_alerts)}")

        # ------------------------------------------------
        # 2️⃣ MAP CWE + CVE
        # ------------------------------------------------
        mapped_alerts = map_zap_alerts(zap_alerts)
        print(f"[✔] Alerts Mapped: {len(mapped_alerts)}")

        # ------------------------------------------------
        # 3️⃣ ML FILTER
        # ------------------------------------------------
        true_positives = predict_true_positives(mapped_alerts)
        print(f"[✔] True Positives Identified: {len(true_positives)}")

        # ------------------------------------------------
        # 4️⃣ GENERATE PDF
        # ------------------------------------------------
        pdf_path = generate_pdf_report(
            target_url=target_url,
            true_positives=true_positives
        )

        # 🔥 SAVE PATH FOR DOWNLOAD API
        latest_report_path = pdf_path

        print(f"[📄] PDF Report Generated: {pdf_path}")

        # ------------------------------------------------
        # 5️⃣ RESPONSE
        # ------------------------------------------------
        return jsonify({
            "target": target_url,
            "total_alerts": len(zap_alerts),
            "mapped_alerts": len(mapped_alerts),
            "true_positives": len(true_positives),
            "results": true_positives
        })

    except Exception as e:
        print(f"[❌] Error: {str(e)}")
        return jsonify({
            "error": "Scan failed",
            "details": str(e)
        }), 500


# ------------------------------------------------
# 🔥 DOWNLOAD REPORT API (IMPORTANT)
# ------------------------------------------------
@app.route("/download-report", methods=["GET"])
def download_report():
    global latest_report_path

    if not latest_report_path or not os.path.exists(latest_report_path):
        return jsonify({"error": "Report not found"}), 404

    return send_file(
        latest_report_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="SecureScope_Report.pdf"
    )


# ------------------------------------------------
# RUN SERVER
# ------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)