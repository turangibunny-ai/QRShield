from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import requests
import time
import os
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

VT_API = os.getenv("VT_API_KEY", "")
GSB_API = os.getenv("GSB_API_KEY", "")

scan_cache = {}
CACHE_TTL = 300


@app.route("/")
def home():
    return render_template("index.html")


# ---------------- URL VALIDATION ----------------
def normalize_url(url):
    """Auto-add https:// if scheme is missing."""
    url = url.strip()
    if not url:
        return None
    # Add scheme if missing
    if not url.startswith(("http://", "https://", "ftp://",
                            "javascript:", "data:", "vbscript:")):
        url = "https://" + url
    return url


def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme in ("http", "https", "ftp"), result.netloc])
    except Exception:
        return False


# ---------------- URL STATUS ----------------
def check_url_status(url):
    try:
        r = requests.get(url, timeout=5, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 QRShield/1.0"})
        return r.status_code
    except Exception:
        return None


# ---------------- HEURISTIC CHECK ----------------
def heuristic_check(url):
    suspicious_keywords = [
        "login", "verify", "secure", "account",
        "update", "bank", "paypal", "icloud",
        "signin", "confirm", "password", "wallet",
        "recover", "unlock", "suspended", "limited",
        "click", "redirect", "credential", "auth",
    ]

    score = 0
    reasons = []

    url_lower = url.lower()
    for word in suspicious_keywords:
        if word in url_lower:
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

    # Check for IP address URL
    import re
    if re.match(r"https?://(\d{1,3}\.){3}\d{1,3}", url):
        score += 20
        reasons.append("Raw IP address used instead of domain")

    # Check for excessive subdomains
    parts = domain.split(".")
    if len(parts) > 4:
        score += 10
        reasons.append(f"Excessive subdomains ({len(parts)-2} levels)")

    # Punycode / homograph
    if "xn--" in domain:
        score += 15
        reasons.append("Punycode domain detected (possible homograph attack)")

    return min(score, 40), reasons


# ---------------- GOOGLE SAFE BROWSING ----------------
def check_google_safe_browsing(url):
    if not GSB_API:
        return False
    try:
        endpoint = (
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
            f"?key={GSB_API}"
        )
        payload = {
            "client": {"clientId": "qrshield", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        response = requests.post(endpoint, json=payload, timeout=5)
        if response.status_code != 200:
            return False
        data = response.json()
        return "matches" in data
    except Exception:
        return False


# ---------------- VIRUSTOTAL ----------------
def check_virustotal(url):
    if not VT_API:
        return 0, 0, 0
    try:
        headers = {"x-apikey": VT_API}
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10,
        )
        if submit.status_code not in (200, 201):
            return 0, 0, 0

        analysis_id = submit.json()["data"]["id"]

        for _ in range(6):
            report = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=10,
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
        vt_score = int((malicious / max(total, 1)) * 100)

        return malicious, suspicious, vt_score
    except Exception:
        return 0, 0, 0


# ---------------- CACHE ----------------
def get_cached(url):
    data = scan_cache.get(url)
    if data and (time.time() - data["time"] < CACHE_TTL):
        return data["result"]
    return None


def set_cache(url, result):
    scan_cache[url] = {"result": result, "time": time.time()}


# ---------------- URL SCAN ----------------
@app.route("/check-url", methods=["POST"])
def check_url():
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "").strip()

    if not raw_url:
        return jsonify({
            "status": "error",
            "malicious_count": 0,
            "message": "No URL provided",
        }), 400

    # ── Normalize: add scheme if missing ──────────────────────────
    url = normalize_url(raw_url)

    if not url or not is_valid_url(url):
        return jsonify({
            "status": "error",
            "malicious_count": 0,
            "message": f"Invalid URL: '{raw_url}' — could not parse as a valid web address",
        }), 400

    # ── Cache check ───────────────────────────────────────────────
    cached = get_cached(url)
    if cached:
        return jsonify(cached)

    parsed = urlparse(url)
    domain = parsed.netloc

    # ── Run all checks ────────────────────────────────────────────
    status_code = check_url_status(url)
    heuristic_score, h_reasons = heuristic_check(url)
    google_flag = check_google_safe_browsing(url)
    malicious, suspicious, vt_score = check_virustotal(url)

    # ── Risk scoring ──────────────────────────────────────────────
    risk_score = 0
    reasons = []

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
        reasons.append("Website unreachable or timed out")

    risk_score = min(risk_score, 100)

    if not reasons:
        reasons.append("No suspicious indicators detected")

    # ── Final verdict ─────────────────────────────────────────────
    if risk_score >= 80:
        status = "Malicious"
        advice = "Do NOT open this link. This URL is flagged as dangerous."
    elif risk_score >= 50:
        status = "Dangerous"
        advice = "Proceed with extreme caution. Do not enter any credentials."
    elif risk_score >= 25:
        status = "Suspicious"
        advice = "This URL shows suspicious patterns. Verify before proceeding."
    else:
        status = "Safe"
        advice = "URL appears safe based on all checks."

    response = {
        "status": status,
        "malicious_count": malicious,
        "scan_score": risk_score,
        "url_details": domain,
        "reasons": reasons,
        "advice": advice,
        "engine_data": {
            "virustotal_malicious": malicious,
            "virustotal_suspicious": suspicious,
            "heuristic_score": heuristic_score,
            "google_safe": google_flag,
            "status_code": status_code,
        },
    }

    set_cache(url, response)
    return jsonify(response)


# Keep /check as alias
@app.route("/check", methods=["POST"])
def check():
    return check_url()


# ── Health check endpoint (used by frontend ping) ─────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "5.0"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
