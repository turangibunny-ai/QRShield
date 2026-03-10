from flask import Flask, render_template, request, jsonify
import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

API_KEY = os.environ.get("VT_API_KEY")

scan_cache = {}

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check():
    data = request.get_json()
    url = data.get("url") if data else None

    if not url:
        return jsonify({"status": "error", "message": "No URL provided"})

    if url in scan_cache:
        return jsonify(scan_cache[url])

    if not API_KEY:
        return jsonify({"status": "error", "message": "API key not configured"})

    headers = {"x-apikey": API_KEY}

    try:
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )
        submit.raise_for_status()
    except requests.exceptions.RequestException as e:
        return jsonify({"status": "error", "message": f"VirusTotal connection failed: {str(e)}"})

    try:
        analysis_id = submit.json()["data"]["id"]
    except (KeyError, ValueError):
        return jsonify({"status": "error", "message": "Unexpected response from VirusTotal"})

    time.sleep(4)

    try:
        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )
        report.raise_for_status()
        result = report.json()
    except requests.exceptions.RequestException as e:
        return jsonify({"status": "error", "message": f"Failed to retrieve report: {str(e)}"})

    try:
        attributes = result["data"]["attributes"]
        stats = attributes["stats"]
        results = attributes["results"]
    except KeyError:
        return jsonify({"status": "error", "message": "Malformed response from VirusTotal"})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)

    total = malicious + suspicious + harmless
    danger_score = int((malicious / max(total, 1)) * 100)

    reasons = []
    for engine, engine_data in results.items():
        if engine_data.get("category") == "malicious":
            reason_text = engine_data.get("result")
            if reason_text and reason_text not in reasons:
                reasons.append(reason_text)
        if len(reasons) == 3:
            break

    if not reasons:
        reasons.append("No major threat detected")

    if malicious > 0:
        status = "Dangerous"
    elif suspicious > 0:
        status = "Suspicious"
    else:
        status = "Safe"

    response = {
        "status": status,
        "danger_score": danger_score,
        "reason": ", ".join(reasons)
    }

    scan_cache[url] = response
    return jsonify(response)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)