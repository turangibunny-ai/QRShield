from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import requests
import time
import os
from dotenv import load_dotenv
from urllib.parse import urlparse

load_dotenv()

app = Flask(__name__)
CORS(app)  # Frontend same origin or different port అయినా పని చేస్తుంది

VT_API = os.getenv("VT_API_KEY")
GSB_API = os.getenv("GSB_API_KEY")

scan_cache = {}
CACHE_TTL = 300


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
        "login","verify","secure","account",
        "update","bank","paypal","icloud",
        "signin","confirm","password"
    ]

    score = 0
    reasons = []

    for word in suspicious_keywords:
        if word in url.lower():
            score += 8
            reasons.append(f'Suspicious keyword detected: "{word}"')

    parsed = urlparse(url)
    domain = parsed.netloc

    if "-" in domain:
        score += 6
        reasons.append("Hyphen used in domain")

    if len(domain) > 30:
        score += 8
        reasons.append("Very long domain name")

    if not url.startswith("https"):
        score += 10
        reasons.append("Website not using HTTPS")

    return min(score, 40), reasons


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

        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )

        analysis_id = submit.json()["data"]["id"]

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

        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless",   0)
        undetected = stats.get("undetected", 0)

        total    = malicious + suspicious + harmless + undetected
        vt_score = int((malicious / max(total, 1)) * 100)

        return malicious, suspicious, vt_score

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
        "time":   time.time()
    }


# ================================================================
#  /check-url  — Frontend expects this endpoint
#  Request  : POST  { "url": "https://example.com" }
#  Response : {
#      "status"         : "Safe" | "Dangerous" | "Malicious",
#      "malicious_count": <int>,   ← frontend uses this field
#      "scan_score"     : <0-100>,
#      "url_details"    : <domain>,
#      "reasons"        : [...],
#      "advice"         : "...",
#      "engine_data"    : { ... }
#  }
# ================================================================
@app.route("/check-url", methods=["POST"])
def check_url():

    data = request.get_json(silent=True) or {}
    url  = data.get("url", "").strip()

    # ── validation ──────────────────────────────────────────────
    if not url or not is_valid_url(url):
        return jsonify({
            "status":          "error",
            "malicious_count": 0,
            "message":         "Invalid URL"
        }), 400

    # ── cache hit ───────────────────────────────────────────────
    cached = get_cached(url)
    if cached:
        return jsonify(cached)

    # ── run checks ──────────────────────────────────────────────
    parsed     = urlparse(url)
    domain     = parsed.netloc

    status_code                    = check_url_status(url)
    heuristic_score, h_reasons     = heuristic_check(url)
    google_flag                    = check_google_safe_browsing(url)
    malicious, suspicious, vt_score = check_virustotal(url)

    # ── aggregate score ─────────────────────────────────────────
    risk_score = 0
    reasons    = []

    if malicious > 0:
        risk_score += 70
        reasons.append(f"Flagged by {malicious} VirusTotal engines")

    if suspicious > 0:
        risk_score += 30
        reasons.append(f"{suspicious} engines marked URL suspicious")

    if h_reasons:
        risk_score += heuristic_score
        reasons.extend(h_reasons)

    if google_flag:
        risk_score = max(risk_score, 90)
        reasons.append("Google Safe Browsing flagged this URL")

    if status_code is None:
        risk_score = max(risk_score, 50)
        reasons.append("Website unreachable")

    risk_score = min(risk_score, 100)

    if not reasons:
        reasons.append("No suspicious indicators detected")

    # ── verdict ─────────────────────────────────────────────────
    if risk_score >= 80:
        status = "Malicious"
        advice = "Do NOT open this link"
    elif risk_score >= 50:
        status = "Dangerous"
        advice = "Proceed with extreme caution"
    else:
        status = "Safe"
        advice = "URL appears safe"

    # ── response — includes all fields frontend needs ────────────
    response = {
        # ★ Fields the frontend contract requires
        "status":          status,
        "malicious_count": malicious,

        # Extra fields (frontend mapBackendToResult reads these too)
        "scan_score":      risk_score,
        "url_details":     domain,
        "reasons":         reasons,
        "advice":          advice,

        "engine_data": {
            "virustotal_malicious":  malicious,
            "virustotal_suspicious": suspicious,
            "heuristic_score":       heuristic_score,
            "google_safe":           google_flag,
            "status_code":           status_code
        }
    }

    set_cache(url, response)
    return jsonify(response)


# ── keep old /check alive so nothing else breaks ────────────────
@app.route("/check", methods=["POST"])
def check():
    return check_url()


# ================================================================
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
