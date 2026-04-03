from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import time
import os
import re
from urllib.parse import urlparse
from datetime import datetime
import tldextract
from rapidfuzz import fuzz
import logging

# ==================== APP INITIALIZATION ====================
app = Flask(__name__)
CORS(app)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# ==================== CONFIGURATION ====================
VT_API = os.getenv("VT_API_KEY", "")
GSB_API = os.getenv("GSB_API_KEY", "")

VT_RATE_LIMIT = 4
vt_request_timestamps = []

CACHE_TTL = 300
scan_cache = {}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==================== PHISHING PATTERNS ====================
PHISHING_KEYWORDS = {
    'high': ['login', 'verify', 'secure', 'account', 'update', 'banking', 'paypal', 'icloud', 'signin', 'confirm', 'password', 'wallet'],
    'medium': ['click', 'redirect', 'recover', 'unlock', 'restore', 'validate', 'payment'],
    'low': ['offer', 'promotion', 'discount', 'free', 'win', 'prize']
}

BRAND_DOMAINS = {
    'paypal.com', 'apple.com', 'google.com', 'microsoft.com', 'amazon.com',
    'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'netflix.com',
    'github.com', 'stackoverflow.com', 'reddit.com', 'youtube.com', 'whatsapp.com'
}

# ==================== UTILITIES ====================
def can_call_virustotal():
    global vt_request_timestamps
    current_time = time.time()
    vt_request_timestamps = [ts for ts in vt_request_timestamps if current_time - ts < 60]
    return len(vt_request_timestamps) < VT_RATE_LIMIT

def record_vt_call():
    global vt_request_timestamps
    vt_request_timestamps.append(time.time())

def normalize_url(url):
    url = url.strip()
    if not url:
        return None
    if not re.match(r'^[a-zA-Z]+://', url):
        url = 'https://' + url
    return url

def is_valid_url(url):
    try:
        result = urlparse(url)
        return result.scheme in ('http', 'https') and result.netloc
    except:
        return False

def check_url_status(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True,
                                headers={"User-Agent": "QRShield/2.0 Security Scanner"})
        return response.status_code
    except:
        return None

# ==================== HEURISTIC ANALYSIS ====================
def check_brand_similarity(domain):
    extracted = tldextract.extract(domain)
    domain_name = extracted.domain.lower() if extracted.domain else ""

    best_match = None
    highest_similarity = 0

    for brand in BRAND_DOMAINS:
        brand_extracted = tldextract.extract(brand)
        brand_name = brand_extracted.domain.lower()

        if domain_name == brand_name and extracted.subdomain:
            return {'similar': True, 'brand': brand, 'score': 25, 'type': 'subdomain_abuse'}

        similarity = fuzz.ratio(domain_name, brand_name) / 100.0

        if similarity > 0.75 and similarity > highest_similarity:
            highest_similarity = similarity
            best_match = brand

    if best_match and highest_similarity > 0.8:
        return {
            'similar': True,
            'brand': best_match,
            'score': min(int(highest_similarity * 35), 35),
            'similarity': highest_similarity,
            'type': 'typosquatting'
        }

    return {'similar': False, 'score': 0}

def advanced_heuristic_check(url):
    score = 0
    reasons = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    # URL Patterns
    url_patterns = [
        (r'https?://[^/]+@', 'URL contains @ symbol (credentials in URL)', 35),
        (r'https?://.*?\.\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'Raw IP address used', 30),
        (r'https?://[^/]+\.(?:tk|ml|ga|cf|gq|top|xyz|club|online|site|click|link|win)', 'Suspicious TLD', 25),
        (r'xn--', 'Punycode domain (homograph attack)', 25),
        (r'https?://[^/]+-\w+\.\w+', 'Hyphen in domain', 15),
        (r'[%][0-9a-fA-F]{2}', 'URL encoding detected', 10),
    ]

    for pattern, reason, points in url_patterns:
        if re.search(pattern, url):
            score += points
            reasons.append(reason)

    # Brand Similarity
    brand_similarity = check_brand_similarity(domain)
    if brand_similarity['similar']:
        score += brand_similarity['score']
        reasons.append(f"Looks similar to known brand: {brand_similarity['brand']}")

    # Other checks
    if len(domain) > 35:
        score += 10
        reasons.append(f"Excessively long domain ({len(domain)} chars)")

    if domain.count('.') > 2:
        extra = min((domain.count('.') - 2) * 3, 12)
        score += extra
        reasons.append(f"Unusual number of subdomains")

    if parsed.scheme != 'https':
        score += 15
        reasons.append("Not using HTTPS encryption")

    # Credential & Redirect checks (kept simple)
    credential_indicators = ['login', 'signin', 'auth', 'password', 'verify', 'account']
    credential_count = sum(1 for ind in credential_indicators if ind in path or ind in query)
    if credential_count > 0:
        score += min(credential_count * 6, 25)
        reasons.append(f'Contains {credential_count} credential-related terms')

    redirect_params = ['redirect', 'url=', 'goto=', 'return=', 'next=']
    if any(param in query for param in redirect_params):
        score += 12
        reasons.append('Contains redirect parameters')

    return min(score, 60), reasons, {}

# ==================== EXTERNAL APIs ====================
def check_google_safe_browsing(url):
    if not GSB_API:
        return {'flagged': False, 'threats': []}
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API}"
        payload = {
            "client": {"clientId": "qrshield", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(endpoint, json=payload, timeout=8)
        if response.status_code == 200 and 'matches' in response.json():
            return {'flagged': True, 'threats': [m['threatType'] for m in response.json()['matches']]}
        return {'flagged': False, 'threats': []}
    except:
        return {'flagged': False, 'threats': []}

def check_virustotal(url):
    if not VT_API:
        return {'malicious': 0, 'suspicious': 0, 'score': 0, 'skipped': False}
    if not can_call_virustotal():
        return {'malicious': 0, 'suspicious': 0, 'score': 0, 'skipped': True}

    try:
        headers = {"x-apikey": VT_API}
        submit = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=10)
        if submit.status_code not in (200, 201):
            return {'malicious': 0, 'suspicious': 0, 'score': 0, 'skipped': False}

        record_vt_call()
        analysis_id = submit.json()["data"]["id"]

        for _ in range(8):
            report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=10)
            if report.status_code == 200 and report.json()["data"]["attributes"]["status"] == "completed":
                break
            time.sleep(2)

        stats = report.json()["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)
        total = malicious + stats.get("harmless", 0) + stats.get("undetected", 0)
        score = int((malicious / total) * 100) if total > 0 else 0

        return {'malicious': malicious, 'suspicious': stats.get('suspicious', 0), 'score': score, 'skipped': False}
    except:
        return {'malicious': 0, 'suspicious': 0, 'score': 0, 'skipped': False}

# ==================== RISK SCORE ====================
def calculate_risk_score(vt_data, gsb_data, heuristic_data, url_status):
    total_score = 0
    all_reasons = []

    if vt_data and not vt_data.get('skipped'):
        total_score += vt_data.get('score', 0)
        all_reasons.append(f"VirusTotal: {vt_data.get('malicious', 0)} malicious detections")

    if gsb_data and gsb_data.get('flagged'):
        total_score += 50
        all_reasons.append("Google Safe Browsing flagged this URL")

    heuristic_score = heuristic_data[0] if isinstance(heuristic_data, tuple) else 0
    if heuristic_score > 0:
        total_score += heuristic_score
        all_reasons.extend(heuristic_data[1])

    if url_status is None or url_status >= 400:
        total_score += 10
        all_reasons.append("Website unreachable or returned error")

    return min(total_score, 100), all_reasons

# ==================== CACHE ====================
def get_cached(url):
    if url in scan_cache and time.time() - scan_cache[url]['time'] < CACHE_TTL:
        return scan_cache[url]['result']
    return None

def set_cache(url, result):
    scan_cache[url] = {'result': result, 'time': time.time()}

# ==================== ROUTES ====================
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "service": "QRShield URL Scanner API",
        "version": "6.1",
        "status": "active",
        "message": "Backend is running successfully! Use /check-url for scanning URLs.",
        "timestamp": datetime.now().isoformat(),
        "endpoints": {
            "/check-url": "POST - Scan a URL",
            "/health": "GET - Health check"
        }
    })

@app.route("/check-url", methods=["POST"])
@limiter.limit("30 per minute")
def check_url():
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "").strip()

    if not raw_url:
        return jsonify({"status": "error", "message": "No URL provided"}), 400

    url = normalize_url(raw_url)
    if not url or not is_valid_url(url):
        return jsonify({"status": "error", "message": "Invalid URL"}), 400

    cached = get_cached(url)
    if cached:
        return jsonify(cached)

    logger.info(f"Scanning URL: {url}")

    url_status = check_url_status(url)
    heuristic_result = advanced_heuristic_check(url)
    gsb_result = check_google_safe_browsing(url)
    vt_result = check_virustotal(url)

    final_score, all_reasons = calculate_risk_score(vt_result, gsb_result, heuristic_result, url_status)

    if final_score >= 80:
        status = "Malicious"
        advice = "⚠️ DANGEROUS: Do NOT open this link."
    elif final_score >= 60:
        status = "High Risk"
        advice = "🔴 HIGH RISK: Strong indicators of malicious intent."
    elif final_score >= 40:
        status = "Suspicious"
        advice = "🟡 SUSPICIOUS: Multiple red flags detected."
    else:
        status = "Safe"
        advice = "✅ SAFE: No significant threats detected."

    response = {
        "status": status,
        "risk_score": final_score,
        "url": url,
        "domain": urlparse(url).netloc,
        "reasons": all_reasons[:10],
        "advice": advice,
        "timestamp": datetime.now().isoformat()
    }

    set_cache(url, response)
    return jsonify(response)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "version": "6.1",
        "timestamp": datetime.now().isoformat()
    })

@app.route("/check", methods=["POST"])
def check():
    return check_url()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "False").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)