from flask import Flask, render_template, request, jsonify
import requests
import time
import os
from dotenv import load_dotenv
from urllib.parse import urlparse

load_dotenv()

app = Flask(__name__)

VT_API = os.getenv("VT_API_KEY")
GSB_API = os.getenv("GSB_API_KEY")

scan_cache = {}
CACHE_TTL = 300  # 5 minutes cache


# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("index.html")


# ---------------- URL VALIDATION ----------------
def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


# ---------------- URL STATUS ----------------
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
        "update", "bank", "paypal", "icloud",
        "signin", "confirm", "password"
    ]

    score = 0
    for word in suspicious_keywords:
        if word in url.lower():
            score += 10

    return min(score, 50)  # max 50 from heuristic


# ---------------- GOOGLE SAFE BROWSING ----------------
def check_google_safe_browsing(url):
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API}"

        payload = {
            "client": {"clientId": "qrshield", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        response = requests.post(endpoint, json=payload, timeout=5)
        data = response.json()

        return "matches" in data
    except:
        return False


# ---------------- VIRUSTOTAL ----------------
def check_virustotal(url):
    try:
        headers = {"x-apikey": VT_API}

        # Submit URL
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )

        analysis_id = submit.json()["data"]["id"]

        # Wait for result
        for _ in range(6):
            report = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=10
            )
            result = report.json()

            if result["data"]["attributes"]["status"] == "completed":
                break
            time.sleep(2)

        stats = result["data"]["attributes"]["stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        total = malicious + suspicious + harmless + undetected

        risk_score = int((malicious / max(total, 1)) * 100)

        return malicious, suspicious, risk_score

    except:
        return 0, 0, 0


# ---------------- CACHE ----------------
def get_cached(url):
    data = scan_cache.get(url)
    if data and (time.time() - data["time"] < CACHE_TTL):
        return data["result"]
    return None


def set_cache(url, result):
    scan_cache[url] = {
        "result": result,
        "time": time.time()
    }


# ---------------- MAIN CHECK ----------------
@app.route("/check", methods=["POST"])
def check():
    data = request.json
    url = data.get("url", "").strip()

    if not url or not is_valid_url(url):
        return jsonify({
            "status": "error",
            "message": "Invalid URL"
        })

    # Cache check
    cached = get_cached(url)
    if cached:
        return jsonify(cached)

    # Run checks
    status_code = check_url_status(url)
    heuristic_score = heuristic_check(url)
    google_flag = check_google_safe_browsing(url)
    malicious, suspicious, vt_score = check_virustotal(url)

    # ---------------- FINAL RISK SCORE ----------------
    risk_score = vt_score + heuristic_score

    if google_flag:
        risk_score = max(risk_score, 90)

    if status_code is None:
        risk_score = max(risk_score, 50)

    risk_score = min(risk_score, 100)

    # ---------------- FINAL STATUS ----------------
    if google_flag or malicious > 0:
        status = "Dangerous"
        reason = "Detected as phishing/malware"

    elif suspicious > 0 or heuristic_score > 20:
        status = "Suspicious"
        reason = "Suspicious patterns detected"

    elif status_code is None:
        status = "Suspicious"
        reason = "Website unreachable"

    else:
        status = "Safe"
        reason = "No threats detected"

    response = {
        "status": status,
        "risk_score": risk_score,
        "reason": reason,
        "details": {
            "virustotal_malicious": malicious,
            "virustotal_suspicious": suspicious,
            "heuristic_score": heuristic_score,
            "google_safe": google_flag,
            "status_code": status_code
        }
    }

    set_cache(url, response)
    return jsonify(response)


# ---------------- RUN ----------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)