from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import os
import re
import math
import time
import redis
import json
from urllib.parse import urlparse
from collections import Counter
from datetime import datetime
import tldextract
import hashlib

app = Flask(__name__)
CORS(app)

limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# ================= REDIS CACHE =================
redis_client = None
try:
    redis_url = os.getenv("REDIS_URL")
    if redis_url:
        redis_client = redis.from_url(redis_url)
        redis_client.ping()
except:
    redis_client = None

cache = {}

# ================= API KEYS & LIMITS =================
VT_API = os.getenv("VT_API_KEY")
GSB_API = os.getenv("GSB_API_KEY")

VT_DAILY_LIMIT = 100
VT_MINUTE_LIMIT = 4

vt_daily_count = 0
vt_minute_count = {}
last_minute_reset = time.time()

# ================= UTIL =================

def normalize_url(url):
    url = url.strip()
    if not re.match(r'^[a-zA-Z]+://', url):
        url = "https://" + url
    return url

def valid_url(url):
    try:
        p = urlparse(url)
        return bool(p.scheme and p.netloc)
    except:
        return False

def entropy(text):
    if not text:
        return 0
    c = Counter(text)
    l = len(text)
    e = 0
    for v in c.values():
        p = v / l
        e -= p * math.log2(p)
    return e

def get_domain_reputation(domain):
    try:
        info = tldextract.extract(domain)
        return {
            "domain": f"{info.domain}.{info.suffix}",
            "age_days": 3650,
            "blacklist_score": 0
        }
    except:
        return {"domain": domain, "age_days": 0, "blacklist_score": 50}

def hash_url(url):
    return hashlib.md5(url.encode()).hexdigest()

# ================= CACHE =================

def get_cache(key, expiry=3600):

    if redis_client:
        try:
            cached = redis_client.get(key)
            if cached:
                return json.loads(cached)
        except:
            pass

    if key in cache:
        if time.time() - cache[key]["timestamp"] < expiry:
            return cache[key]["data"]

    return None


def set_cache(key, data, expiry=3600):

    try:
        if redis_client:
            redis_client.setex(key, expiry, json.dumps(data))
        else:
            cache[key] = {
                "data": data,
                "timestamp": time.time()
            }
    except:
        pass

# ================= VT RATE LIMIT =================

def vt_rate_limiter():

    global vt_daily_count, vt_minute_count, last_minute_reset

    now = time.time()

    if now - last_minute_reset > 60:
        vt_minute_count = {}
        last_minute_reset = now

    if vt_daily_count >= VT_DAILY_LIMIT:
        return False, "Daily VT limit reached"

    minute_key = str(int(now // 60))

    vt_minute_count[minute_key] = vt_minute_count.get(minute_key, 0) + 1

    if vt_minute_count[minute_key] > VT_MINUTE_LIMIT:
        return False, "Minute VT limit reached"

    vt_daily_count += 1
    return True, "OK"

# ================= HEURISTIC =================

def heuristic_engine(url):

    score = 0
    reasons = []

    p = urlparse(url)
    domain = p.netloc.lower()
    path = p.path.lower()
    query = p.query.lower()

    if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain):
        score += 30
        reasons.append("IP address detected")

    phishing_keywords = ['login','secure','verify','account','bank','paypal','update']

    if any(keyword in domain for keyword in phishing_keywords):
        score += 15
        reasons.append("Phishing keywords in domain")

    if "@" in url:
        score += 25
        reasons.append("@ symbol phishing")

    if "%" in query and len(query) > 50:
        score += 15
        reasons.append("Suspicious URL encoding")

    subdomains = domain.split('.')

    if len(subdomains) > 4:
        score += 20
        reasons.append("Excessive subdomains")

    elif len(subdomains) > 2 and any(len(sd) > 15 for sd in subdomains[:-2]):
        score += 10
        reasons.append("Long suspicious subdomains")

    if len(url) > 150:
        score += 15
        reasons.append("Excessively long URL")

    elif len(url) > 100:
        score += 8
        reasons.append("Long URL")

    if entropy(domain) > 4.5:
        score += 20
        reasons.append("High entropy domain")

    elif entropy(domain) > 3.8:
        score += 10
        reasons.append("Suspicious entropy")

    if not url.startswith("https"):
        score += 20
        reasons.append("HTTP (not secure)")

    risky_tlds = [
        'tk','ml','ga','cf','xyz','top','gq','ru','cn','ws',
        'info','club','online','site','space','fun'
    ]

    tld = tldextract.extract(domain).suffix

    if tld in risky_tlds:
        score += 25
        reasons.append(f"Risky TLD: .{tld}")

    suspicious_paths = ['wp-admin','wp-login','admin','login','phpmyadmin']

    if any(x in path for x in suspicious_paths):
        score += 15
        reasons.append("Suspicious path detected")

    if '//' in url[8:]:
        score += 10
        reasons.append("Double slash evasion")

    rep = get_domain_reputation(domain)

    if rep["age_days"] < 90:
        score += 15
        reasons.append("New domain (<90 days)")

    if rep["blacklist_score"] > 30:
        score += 20
        reasons.append("Poor domain reputation")

    return min(score,100), reasons

# ================= GOOGLE SAFE =================

def google_safe_check(url):

    cache_key = f"gsb:{hash_url(url)}"

    cached = get_cache(cache_key,86400)

    if cached:
        return cached

    if not GSB_API:
        result = {"flagged":False}
        set_cache(cache_key,result)
        return result

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API}"

    payload = {
        "client":{"clientId":"qrshield","clientVersion":"2.0"},
        "threatInfo":{
            "threatTypes":["MALWARE","SOCIAL_ENGINEERING"],
            "platformTypes":["ANY_PLATFORM"],
            "threatEntryTypes":["URL"],
            "threatEntries":[{"url":url}]
        }
    }

    try:

        r = requests.post(endpoint,json=payload,timeout=10)

        result = {"flagged": r.status_code==200 and "matches" in r.json()}

    except:

        result = {"flagged":False}

    set_cache(cache_key,result)

    return result

# ================= VIRUSTOTAL =================

def virustotal_check(url):

    cache_key = f"vt:{hash_url(url)}"

    cached = get_cache(cache_key,86400*7)

    if cached:
        return cached

    can_use,msg = vt_rate_limiter()

    if not can_use:

        result = {"malicious":0,"score":0,"limited":True,"reason":msg}
        set_cache(cache_key,result)
        return result

    if not VT_API:

        result = {"malicious":0,"score":0}
        set_cache(cache_key,result)
        return result

    headers={"x-apikey":VT_API}

    try:

        submit=requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url":url}
        )

        analysis_id=submit.json()["data"]["id"]

        time.sleep(4)

        report=requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )

        stats=report.json()["data"]["attributes"]["stats"]

        malicious=stats.get("malicious",0)+stats.get("suspicious",0)

        total=sum(stats.values())

        score=int((malicious/total)*100) if total else 0

        result={"malicious":malicious,"score":score}

    except Exception as e:

        result={"malicious":0,"score":0,"error":str(e)}

    set_cache(cache_key,result)

    return result

# ================= RISK =================

def risk_engine(heuristic,gsb,vt):

    score=heuristic[0]
    reasons=heuristic[1][:]

    if gsb.get("flagged"):
        score+=60
        reasons.append("Google Safe Browsing BLOCK")

    if vt.get("malicious",0)>0:
        score+=vt["score"]
        reasons.append(f"VirusTotal: {vt['malicious']} engines")

    score=min(score,100)

    if score>=85:
        status="DANGER"
        advice="DO NOT VISIT"

    elif score>=70:
        status="HIGH RISK"
        advice="Avoid this site"

    elif score>=50:
        status="MEDIUM RISK"
        advice="Proceed carefully"

    elif score>=30:
        status="LOW RISK"
        advice="Verify domain"

    else:
        status="SAFE"
        advice="No major threats detected"

    return score,status,reasons[:12],advice

# ================= ROUTES =================

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/v1/check",methods=["POST"])
def scan_v1():
    return scan()

@app.route("/api/v1/check-url",methods=["POST"])
def scan_url():
    return scan()

@app.route("/api/health")
def health():
    return jsonify({
        "status":"healthy",
        "timestamp":datetime.now().isoformat()
    })

# ================= MAIN SCAN =================

def scan():

    data=request.get_json(silent=True) or {}

    raw=data.get("url","")

    if not raw:
        return jsonify({"error":"URL required"}),400

    url=normalize_url(raw)

    if not valid_url(url):
        return jsonify({"error":"Invalid URL"}),400

    cache_key=f"scan:{hash_url(url)}"

    cached=get_cache(cache_key)

    if cached:
        return jsonify(cached)

    heuristic=heuristic_engine(url)
    gsb=google_safe_check(url)
    vt=virustotal_check(url)

    score,status,reasons,advice=risk_engine(heuristic,gsb,vt)

    result={
        "url":url,
        "status":status,
        "risk_score":score,
        "risk_percent":f"{score}%",
        "reasons":reasons,
        "advice":advice,
        "scan_time":datetime.now().isoformat()
    }

    set_cache(cache_key,result,1800)

    return jsonify(result)

# ================= RUN =================

if __name__=="__main__":

    port=int(os.environ.get("PORT",10000))

    app.run(host="0.0.0.0",port=port)