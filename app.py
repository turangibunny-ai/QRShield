from flask import Flask, render_template, request, jsonify
import requests 
import time
import os
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

# API key from environment variable
API_KEY = os.environ.get("VT_API_KEY")

# simple cache memory
scan_cache = {}

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check():
    data = request.json
    url = data.get("url")

    if not url:
        return jsonify({"status": "error", "message": "No URL provided"})

    # check cache first
    if url in scan_cache:
        return jsonify(scan_cache[url])

    headers = {"x-apikey": API_KEY}

    # submit URL
    submit = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    if submit.status_code != 200:
        return jsonify({"status": "error", "message": "VirusTotal connection failed"})

    analysis_id = submit.json()["data"]["id"]

    time.sleep(4)

    report = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers
    )

    result = report.json()

    stats = result["data"]["attributes"]["stats"]
    results = result["data"]["attributes"]["results"]

    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    harmless = stats["harmless"]

    total = malicious + suspicious + harmless

    danger_score = int((malicious / max(total, 1)) * 100)

    reason = "None"

    for engine in results:
        if results[engine]["category"] == "malicious":
            reason = results[engine]["result"]
            break

    if malicious > 0:
        status = "Dangerous"
    elif suspicious > 0:
        status = "Suspicious"
    else:
        status = "Safe"

    response = {
        "status": status,
        "danger_score": danger_score,
        "reason": reason
    }

    scan_cache[url] = response

    return jsonify(response)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)