from flask import Flask, request, jsonify
from sklearn.ensemble import IsolationForest
import pandas as pd
import numpy as np
import os
import sqlite3
from datetime import datetime

app = Flask(__name__)
API_KEY = os.getenv("FINSEC_API_KEY", "supersecret")
WEBHOOK_URL = os.getenv("FINSEC_WEBHOOK_URL", "https://webhook.site/test")

def log_request(data, result):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "risk_score": result["risk_score"],
        "severity": result["severity"],
        "status": result["status"],
        "recommendation": result["recommendation"]
    }
    df_log = pd.DataFrame([log_entry])
    df_log.to_csv("api_logs.csv", mode='a', index=False, header=not Path("api_logs.csv").exists())
    conn = sqlite3.connect("api.db")
    df_log.to_sql("logs", conn, if_exists="append", index=False)
    conn.close()

def send_webhook_alert(result):
    import requests
    try:
        alert = {
            "text": f"🚨 High Risk Alert from FinSec API\nRisk Score: {result['risk_score']}\nSeverity: {result['severity']}\nRecommendation: {result['recommendation']}"
        }
        requests.post(WEBHOOK_URL, json=alert, timeout=5)
    except Exception as e:
        print(f"Webhook failed: {e}")

def detect_fraud(data):
    df = pd.DataFrame([data])
    df_numeric = df.select_dtypes(include=[np.number])
    model = IsolationForest(contamination=0.05)
    preds = model.fit_predict(df_numeric)
    scores = model.decision_function(df_numeric) * -100
    risk_score = round(float(scores[0]), 2)
    status = "Suspicious" if preds[0] == -1 else "Normal"
    severity = "Low"
    if risk_score > 60:
        severity = "High"
    elif risk_score > 30:
        severity = "Medium"

    result = {
        "status": status,
        "risk_score": risk_score,
        "severity": severity,
        "recommendation": "Review immediately" if severity == "High" else "Monitor"
    }

    log_request(data, result)
    if severity == "High":
        send_webhook_alert(result)

    return result

@app.route("/detect", methods=["POST"])
def detect():
    auth = request.headers.get("Authorization")
    if auth != f"Bearer {API_KEY}":
        return jsonify({"error": "Unauthorized"}), 401

    if not request.is_json:
        return jsonify({"error": "Invalid JSON"}), 400

    data = request.get_json()
    try:
        result = detect_fraud(data)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "FinSec API is running."})

@app.route("/privacy", methods=["GET"])
def privacy():
    return jsonify({"policy": "FinSec does not store personal data unless explicitly required and consented to."})

@app.route("/terms", methods=["GET"])
def terms():
    return jsonify({"terms": "FinSec is a cybersecurity analysis platform. Use of the API implies agreement to standard usage terms."})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
