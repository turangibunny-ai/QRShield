
from flask import Flask, render_template, request, jsonify
import requests
import time
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Get API keys from .env file
VT_API = os.environ.get("VT_API_KEY")
GSB_API = os.environ.get("GSB_API_KEY")

# Simple in-memory cache to avoid scanning same URL repeatedly
scan_cache = {}


@app.route("/")
def home():
    return render_template("index.html")


# ---------------- GOOGLE SAFE BROWSING CHECK ----------------
def check_google_safe_browsing(url):

    # Google Safe Browsing API endpoint
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API}"

    # Request body sent to Google API
    payload = {
        "client": {
            "clientId": "qrshield",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    # Send request to Google Safe Browsing
    response = requests.post(endpoint, json=payload)

    data = response.json()

    # If "matches" exists → Google detected threat
    if "matches" in data:
        return True

    # Otherwise URL is not flagged by Google
    return False


# ---------------- VIRUSTOTAL CHECK ----------------
def check_virustotal(url):

    headers = {"x-apikey": VT_API}

    # Submit URL to VirusTotal for scanning
    submit = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    # Get analysis ID for the scan
    analysis_id = submit.json()["data"]["id"]

    # Wait a few seconds for VirusTotal to generate report
    time.sleep(4)

    # Fetch scan report
    report = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers
    )

    result = report.json()

    stats = result["data"]["attributes"]["stats"]

    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    harmless = stats["harmless"]

    total = malicious + suspicious + harmless

    # Calculate risk score based on malicious detections
    risk_score = int((malicious / max(total,1)) * 100)

    return malicious, suspicious, risk_score


# ---------------- MAIN SCAN ROUTE ----------------
@app.route("/check", methods=["POST"])
def check():

    data = request.json
    url = data.get("url")

    # Validate URL input
    if not url:
        return jsonify({"status": "error", "message": "No URL provided"})


    # Check cache first
    if url in scan_cache:
        return jsonify(scan_cache[url])


    # Step 1: Check URL using Google Safe Browsing
    google_flag = check_google_safe_browsing(url)


    # Step 2: Scan URL using VirusTotal
    malicious, suspicious, risk_score = check_virustotal(url)


    # ---------------- FINAL ANALYSIS ----------------

    # Dangerous if Google flagged OR VirusTotal detected malware
    if google_flag or malicious > 0:

        status = "Dangerous"

        # Ensure risk score is high if threat detected
        risk_score = max(risk_score, 80)

        reason = "Detected as phishing or malware"

        response = {
            "status": status,
            "risk_score": risk_score,
            "reason": reason
        }

    # Suspicious if some engines marked suspicious
    elif suspicious > 0:

        status = "Suspicious"

        response = {
            "status": status,
            "risk_score": risk_score,
            "reason": "Suspicious activity detected"
        }

    # Safe if no threats detected
    else:

        status = "Safe"

        response = {
            "status": status,
            "risk_score": risk_score
        }


    # Store result in cache
    scan_cache[url] = response

    return jsonify(response)


if __name__ == "__main__":

    # Get port from environment (useful for hosting platforms)
    port = int(os.environ.get("PORT", 5000))

    # Run Flask server
    app.run(host="0.0.0.0", port=port)