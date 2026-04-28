from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import sqlite3
import json

from modules.zap_scanner import run_zap_scan
from modules.zap_cwe_cve_mapper import map_zap_alerts
from modules.model_predictor import predict_true_positives
from modules.pdf_report import generate_pdf_report

from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
CORS(app)

latest_report_path = None

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

DB_NAME = "secure_scope.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        url TEXT,
        vulnerabilities TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()


def save_scan(user_id, url, vulnerabilities):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO scans (user_id, url, vulnerabilities)
    VALUES (?, ?, ?)
    """, (
        user_id,
        url,
        json.dumps(vulnerabilities)
    ))

    conn.commit()
    conn.close()


def remove_duplicate_alerts(alerts):
    seen = set()
    unique_alerts = []

    for alert in alerts:
        identifier = (
            str(alert.get("alert", "")).lower().strip(),
            str(alert.get("url", "")).split("?")[0],
            str(alert.get("param", "")).lower().strip()
        )

        if identifier not in seen:
            seen.add(identifier)
            unique_alerts.append(alert)

    return unique_alerts


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "SecureScope Backend Running"
    })


@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json()

        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        if not username or not email or not password:
            return jsonify({
                "message": "All fields are required"
            }), 400

        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO users (username, email, password)
        VALUES (?, ?, ?)
        """, (
            username,
            email,
            hashed_password
        ))

        conn.commit()
        conn.close()

        return jsonify({
            "message": "Signup successful"
        })

    except sqlite3.IntegrityError:
        return jsonify({
            "message": "User already exists"
        }), 400

    except Exception as e:
        return jsonify({
            "message": "Signup failed",
            "error": str(e)
        }), 500


@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()

        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({
                "message": "Email and password required"
            }), 400

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
        SELECT id, username, password
        FROM users
        WHERE email = ?
        """, (email,))

        user = cursor.fetchone()
        conn.close()

        if user:
            user_id = user[0]
            username = user[1]
            stored_password = user[2]

            if check_password_hash(stored_password, password):
                return jsonify({
                    "message": "Login successful",
                    "user_id": user_id,
                    "username": username
                })

        return jsonify({
            "message": "Invalid credentials"
        }), 401

    except Exception as e:
        return jsonify({
            "message": "Login failed",
            "error": str(e)
        }), 500


@app.route("/scan", methods=["POST"])
def scan():
    global latest_report_path

    try:
        data = request.get_json()

        if not data or "url" not in data:
            return jsonify({
                "error": "URL is required"
            }), 400

        target_url = data["url"]
        user_id = data.get("user_id")

        print(f"\n[+] Starting scan for: {target_url}")

        zap_alerts = run_zap_scan(target_url)

        if not zap_alerts:
            return jsonify({
                "message": "No alerts found"
            }), 200

        print(f"[✔] ZAP Alerts Found: {len(zap_alerts)}")

        mapped_alerts = map_zap_alerts(zap_alerts)
        print(f"[✔] Alerts Mapped: {len(mapped_alerts)}")

        true_positives = predict_true_positives(mapped_alerts)
        print(f"[✔] Raw True Positives: {len(true_positives)}")

        true_positives = remove_duplicate_alerts(true_positives)
        print(f"[✔] Unique True Positives: {len(true_positives)}")

        if user_id:
            save_scan(
                user_id=user_id,
                url=target_url,
                vulnerabilities=true_positives
            )
            print("[✔] Scan history saved")

        pdf_path = generate_pdf_report(
            target_url=target_url,
            true_positives=true_positives
        )

        latest_report_path = pdf_path

        print(f"[📄] PDF Report Generated: {pdf_path}")

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


@app.route("/scan-history/<int:user_id>", methods=["GET"])
def get_scan_history(user_id):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
        SELECT id, url, vulnerabilities, timestamp
        FROM scans
        WHERE user_id = ?
        ORDER BY timestamp DESC
        """, (user_id,))

        rows = cursor.fetchall()
        conn.close()

        history = []

        for row in rows:
            history.append({
                "scan_id": row[0],
                "url": row[1],
                "vulnerabilities": json.loads(row[2]),
                "timestamp": row[3]
            })

        return jsonify(history)

    except Exception as e:
        return jsonify({
            "error": "Failed to fetch history",
            "details": str(e)
        }), 500


@app.route("/download-report", methods=["GET"])
def download_report():
    global latest_report_path

    if not latest_report_path or not os.path.exists(latest_report_path):
        return jsonify({
            "error": "Report not found"
        }), 404

    return send_file(
        latest_report_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="SecureScope_Report.pdf"
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)