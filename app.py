from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import time
import os
import re
import math
from collections import Counter
from urllib.parse import urlparse
from datetime import datetime
import tldextract
from rapidfuzz import fuzz
import logging

# ==================== APP ====================
app = Flask(__name__)
CORS(app)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)

# ==================== CONFIG ====================
VT_API = os.getenv("VT_API_KEY", "")
GSB_API = os.getenv("GSB_API_KEY", "")

VT_RATE_LIMIT = 4
vt_request_timestamps = []

CACHE_TTL = 300
scan_cache = {}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==================== PHISHING DATA ====================
BRAND_DOMAINS = {
    'paypal.com','apple.com','google.com','microsoft.com','amazon.com',
    'facebook.com','instagram.com','twitter.com','linkedin.com',
    'netflix.com','github.com','youtube.com','whatsapp.com'
}

# ==================== UTIL ====================

def normalize_url(url):
    url = url.strip()
    if not re.match(r'^[a-zA-Z]+://', url):
        url = 'https://' + url
    return url

def is_valid_url(url):
    try:
        r = urlparse(url)
        return r.scheme in ("http","https") and r.netloc
    except:
        return False

def calculate_entropy(text):
    counter = Counter(text)
    length = len(text)

    entropy = 0
    for c in counter.values():
        p = c / length
        entropy -= p * math.log2(p)

    return entropy

# ==================== VIRUSTOTAL RATE LIMIT ====================

def can_call_virustotal():
    global vt_request_timestamps
    current = time.time()

    vt_request_timestamps = [
        ts for ts in vt_request_timestamps if current - ts < 60
    ]

    return len(vt_request_timestamps) < VT_RATE_LIMIT

def record_vt_call():
    vt_request_timestamps.append(time.time())

# ==================== HEURISTIC DETECTION ====================

def check_brand_similarity(domain):

    extracted = tldextract.extract(domain)
    domain_name = extracted.domain.lower()

    best_match = None
    best_score = 0

    for brand in BRAND_DOMAINS:

        brand_name = tldextract.extract(brand).domain.lower()

        similarity = fuzz.ratio(domain_name, brand_name)/100

        if similarity > best_score:
            best_score = similarity
            best_match = brand

    if best_score > 0.8:

        return {
            "similar":True,
            "brand":best_match,
            "score":int(best_score*35)
        }

    return {"similar":False,"score":0}


def advanced_heuristic(url):

    score = 0
    reasons = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # raw ip
    if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
        score += 30
        reasons.append("Raw IP used instead of domain")

    # @ symbol
    if "@" in url:
        score += 30
        reasons.append("@ symbol in URL")

    # suspicious tld
    if re.search(r'\.(tk|ml|ga|cf|gq|top|xyz|club|online)$', domain):
        score += 25
        reasons.append("Suspicious TLD")

    # entropy check
    entropy = calculate_entropy(domain)

    if entropy > 4:
        score += 10
        reasons.append("Random looking domain")

    # long domain
    if len(domain) > 35:
        score += 10
        reasons.append("Very long domain")

    # multiple subdomains
    if domain.count('.') > 3:
        score += 10
        reasons.append("Too many subdomains")

    # URL length
    if len(url) > 120:
        score += 10
        reasons.append("Very long URL")

    # base64 detection
    if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', url):
        score += 10
        reasons.append("Encoded payload detected")

    # https check
    if parsed.scheme != "https":
        score += 15
        reasons.append("Not using HTTPS")

    brand = check_brand_similarity(domain)

    if brand["similar"]:
        score += brand["score"]
        reasons.append(f"Looks similar to {brand['brand']}")

    return min(score,60), reasons


# ==================== GOOGLE SAFE BROWSING ====================

def check_gsb(url):

    if not GSB_API:
        return {"flagged":False}

    try:

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API}"

        payload = {
            "client":{"clientId":"qrshield","clientVersion":"1.0"},
            "threatInfo":{
                "threatTypes":["MALWARE","SOCIAL_ENGINEERING"],
                "platformTypes":["ANY_PLATFORM"],
                "threatEntryTypes":["URL"],
                "threatEntries":[{"url":url}]
            }
        }

        r = requests.post(endpoint,json=payload,timeout=8)

        if r.status_code == 200 and "matches" in r.json():
            return {"flagged":True}

        return {"flagged":False}

    except:
        return {"flagged":False}


# ==================== VIRUSTOTAL ====================

def check_vt(url):

    if not VT_API:
        return {"score":0,"malicious":0,"skipped":True}

    if not can_call_virustotal():
        return {"score":0,"malicious":0,"skipped":True}

    try:

        headers={"x-apikey":VT_API}

        submit=requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url":url}
        )

        record_vt_call()

        analysis=submit.json()["data"]["id"]

        time.sleep(3)

        report=requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis}",
            headers=headers
        )

        stats=report.json()["data"]["attributes"]["stats"]

        malicious=stats["malicious"]

        total=sum(stats.values())

        score=int((malicious/total)*100) if total else 0

        return {
            "score":score,
            "malicious":malicious,
            "skipped":False
        }

    except:
        return {"score":0,"malicious":0,"skipped":True}


# ==================== RISK ====================

def calculate_risk(vt,gsb,heuristic):

    score=0
    reasons=[]

    if vt and not vt.get("skipped"):
        score+=vt["score"]
        reasons.append(f"VirusTotal detections: {vt['malicious']}")

    if gsb.get("flagged"):
        score+=50
        reasons.append("Flagged by Google Safe Browsing")

    score+=heuristic[0]
    reasons+=heuristic[1]

    return min(score,100), reasons


# ==================== ROUTES ====================

@app.route("/")
def home():

    return jsonify({
        "service":"QRShield URL Scanner API",
        "status":"active",
        "version":"7.0",
        "timestamp":datetime.now().isoformat()
    })


@app.route("/check-url",methods=["POST"])
@limiter.limit("30/minute")
def scan():

    data=request.get_json()

    raw=data.get("url","")

    if not raw:
        return jsonify({"error":"No URL provided"}),400

    url=normalize_url(raw)

    if not is_valid_url(url):
        return jsonify({"error":"Invalid URL"}),400

    logger.info(f"Scanning {url}")

    heuristic=advanced_heuristic(url)

    gsb=check_gsb(url)

    vt=check_vt(url)

    score,reasons=calculate_risk(vt,gsb,heuristic)

    if score>=80:
        status="Malicious"
    elif score>=60:
        status="High Risk"
    elif score>=40:
        status="Suspicious"
    else:
        status="Safe"

    return jsonify({
        "url":url,
        "risk_score":score,
        "status":status,
        "reasons":reasons[:10],
        "timestamp":datetime.now().isoformat()
    })


@app.route("/health")
def health():

    return jsonify({
        "status":"ok",
        "time":datetime.now().isoformat()
    })


# ==================== MAIN ====================

if __name__ == "__main__":

    port=int(os.environ.get("PORT",10000))

    app.run(host="0.0.0.0",port=port)