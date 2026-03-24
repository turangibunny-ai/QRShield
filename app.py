from flask import Flask, render_template, request, jsonify
import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

VT_API = os.environ.get("VT_API_KEY")
GSB_API = os.environ.get("GSB_API_KEY")

scan_cache = {}


@app.route("/")
def home():
    return render_template("index.html")


# ---------------- URL STATUS CHECK ----------------
def check_url_status(url):
    try:
        r = requests.get(url, timeout=5)
        return r.status_code
    except:
        return None


# ---------------- HEURISTIC CHECK ----------------
def heuristic_check(url):
    suspicious_keywords = [
        "login", "verify", "secure", "account",
        "update", "bank", "paypal", "icloud"
    ]

    for word in suspicious_keywords:
        if word in url.lower():
            return True
    return False


# ---------------- GOOGLE SAFE BROWSING ----------------
def check_google_safe_browsing(url):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API}"

    payload = {
        "client": {
            "clientId": "qrshield",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    response = requests.post(endpoint, json=payload)
    data = response.json()

    return "matches" in data


# ---------------- VIRUSTOTAL ----------------
def check_virustotal(url):
    headers = {"x-apikey": VT_API}

    # Submit URL
    submit = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    analysis_id = submit.json()["data"]["id"]

    # Wait until analysis completed
    for _ in range(5):
        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )
        result = report.json()

        if result["data"]["attributes"]["status"] == "completed":
            break
        time.sleep(2)

    stats = result["data"]["attributes"]["stats"]

    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    harmless = stats["harmless"]

    total = malicious + suspicious + harmless
    risk_score = int((malicious / max(total, 1)) * 100)

    return malicious, suspicious, risk_score


# ---------------- MAIN ROUTE ----------------
@app.route("/check", methods=["POST"])
def check():
    data = request.json
    url = data.get("url")

    if not url:
        return jsonify({"status": "error", "message": "No URL provided"})

    if url in scan_cache:
        return jsonify(scan_cache[url])

    # Checks
    status_code = check_url_status(url)
    heuristic_flag = heuristic_check(url)
    google_flag = check_google_safe_browsing(url)
    malicious, suspicious, risk_score = check_virustotal(url)

    # ---------------- FINAL LOGIC ----------------

    if google_flag or malicious > 0:
        response = {
            "status": "Dangerous",
            "risk_score": max(risk_score, 80),
            "reason": "Detected as phishing or malware"
        }

    elif suspicious > 0 or heuristic_flag:
        response = {
            "status": "Suspicious",
            "risk_score": max(risk_score, 50),
            "reason": "Suspicious URL pattern or behavior"
        }

    elif status_code is None:
        response = {
            "status": "Suspicious",
            "risk_score": 50,
            "reason": "Website not reachable"
        }

    else:
        response = {
            "status": "Safe",
            "risk_score": risk_score
        }

    scan_cache[url] = response
    return jsonify(response)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)