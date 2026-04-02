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
import Levenshtein
from collections import defaultdict
import logging

# ==================== APP INITIALIZATION ====================
app = Flask(__name__)
CORS(app)

# Rate limiting for API protection
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# ==================== CONFIGURATION ====================
# API Keys from environment variables
VT_API = os.getenv("VT_API_KEY", "")  # VirusTotal API key
GSB_API = os.getenv("GSB_API_KEY", "")  # Google Safe Browsing API key

# VirusTotal rate limiting (4 requests per minute)
VT_RATE_LIMIT = 4
vt_request_timestamps = []

# Cache configuration
CACHE_TTL = 300
scan_cache = {}

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==================== PHISHING DETECTION PATTERNS ====================
PHISHING_KEYWORDS = {
    'high': [
        'login', 'verify', 'secure', 'account', 'update', 'banking',
        'paypal', 'icloud', 'signin', 'confirm', 'password', 'wallet',
        'credential', 'authenticate', 'verification', 'suspended'
    ],
    'medium': [
        'click', 'redirect', 'recover', 'unlock', 'restore', 'validate',
        'activate', 'deactivate', 'upgrade', 'payment', 'invoice'
    ],
    'low': [
        'offer', 'promotion', 'discount', 'free', 'win', 'prize',
        'gift', 'reward', 'bonus', 'exclusive'
    ]
}

# Known legitimate brands
BRAND_DOMAINS = {
    'paypal.com', 'apple.com', 'google.com', 'microsoft.com', 'amazon.com',
    'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'netflix.com',
    'github.com', 'stackoverflow.com', 'reddit.com', 'youtube.com', 'whatsapp.com'
}

# ==================== RATE LIMITING UTILITY ====================
def can_call_virustotal():
    global vt_request_timestamps
    current_time = time.time()
    vt_request_timestamps = [ts for ts in vt_request_timestamps if current_time - ts < 60]
    
    if len(vt_request_timestamps) >= VT_RATE_LIMIT:
        logger.warning(f"VirusTotal rate limit reached ({VT_RATE_LIMIT}/min)")
        return False
    return True

def record_vt_call():
    global vt_request_timestamps
    vt_request_timestamps.append(time.time())

# ==================== URL PROCESSING UTILITIES ====================
def normalize_url(url):
    url = url.strip()
    if not url:
        return None
    
    try:
        from urllib.parse import unquote
        url = unquote(url)
    except:
        pass
    
    if not re.match(r'^[a-zA-Z]+://', url):
        url = 'https://' + url
    
    return url

def is_valid_url(url):
    try:
        result = urlparse(url)
        if result.scheme not in ('http', 'https'):
            return False
        if not result.netloc:
            return False
        return True
    except:
        return False

def check_url_status(url):
    try:
        response = requests.get(
            url, 
            timeout=5, 
            allow_redirects=True,
            headers={"User-Agent": "QRShield/2.0 Security Scanner"}
        )
        return response.status_code
    except Exception as e:
        logger.debug(f"URL status check failed: {e}")
        return None

# ==================== HEURISTIC ANALYSIS ====================
def check_brand_similarity(domain):
    extracted = tldextract.extract(domain)
    domain_name = extracted.domain
    
    best_match = None
    highest_similarity = 0
    
    for brand in BRAND_DOMAINS:
        brand_extracted = tldextract.extract(brand)
        brand_name = brand_extracted.domain
        
        if domain_name == brand_name and extracted.subdomain:
            return {
                'similar': True,
                'brand': brand,
                'score': 25,
                'type': 'subdomain_abuse'
            }
        
        distance = Levenshtein.distance(domain_name, brand_name)
        similarity = 1 - (distance / max(len(domain_name), len(brand_name)))
        
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
    details = {}
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    
    # URL pattern detection
    url_patterns = [
        (r'https?://[^/]+@', 'URL contains @ symbol (credentials in URL)', 35),
        (r'https?://.*?\.\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'Raw IP address used instead of domain', 30),
        (r'https?://[^/]+\.(?:tk|ml|ga|cf|gq|top|xyz|club|online|site|website|click|link|win)', 'Suspicious TLD often used in phishing', 25),
        (r'xn--', 'Punycode domain detected (possible homograph attack)', 25),
        (r'https?://[^/]+-\w+\.\w+', 'Hyphen in domain (often used in typosquatting)', 15),
        (r'[%][0-9a-fA-F]{2}', 'URL encoding detected', 10),
    ]
    
    for pattern, reason, points in url_patterns:
        if re.search(pattern, url):
            score += points
            reasons.append(reason)
    
    # Phishing keyword detection
    keyword_score = 0
    detected_keywords = []
    
    for category, keywords in PHISHING_KEYWORDS.items():
        for keyword in keywords:
            if keyword in domain or keyword in path or keyword in query:
                if category == 'high':
                    points = 12
                elif category == 'medium':
                    points = 8
                else:
                    points = 5
                keyword_score += points
                detected_keywords.append(keyword)
                break
    
    if keyword_score > 0:
        score += min(keyword_score, 35)
        reasons.append(f"Phishing keywords detected: {', '.join(detected_keywords[:3])}")
    
    # Brand similarity detection
    brand_similarity = check_brand_similarity(domain)
    if brand_similarity['similar']:
        score += brand_similarity['score']
        reasons.append(f"Looks similar to known brand: {brand_similarity['brand']}")
    
    # Domain characteristics
    if len(domain) > 35:
        score += 10
        reasons.append(f"Excessively long domain name ({len(domain)} chars)")
    
    subdomain_count = domain.count('.')
    if subdomain_count > 2:
        extra_points = min((subdomain_count - 2) * 3, 12)
        score += extra_points
        reasons.append(f"Unusual number of subdomains ({subdomain_count})")
    
    # HTTPS check
    if parsed.scheme != 'https':
        score += 15
        reasons.append("Website not using HTTPS encryption")
    
    # Login/credential detection
    credential_indicators = ['login', 'signin', 'auth', 'password', 'verify', 'account']
    credential_count = sum(1 for ind in credential_indicators if ind in path or ind in query)
    if credential_count > 0:
        score += min(credential_count * 6, 25)
        reasons.append(f'Contains {credential_count} credential-related terms')
    
    # Redirect parameter detection
    redirect_params = ['redirect', 'url=', 'link=', 'goto=', 'return=', 'next=']
    if any(param in query for param in redirect_params):
        score += 12
        reasons.append('URL contains redirect parameters')
    
    return min(score, 60), reasons, details

# ==================== GOOGLE SAFE BROWSING API ====================
def check_google_safe_browsing(url):
    if not GSB_API:
        return {'flagged': False, 'threats': [], 'error': 'API key not configured'}
    
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API}"
        payload = {
            "client": {"clientId": "qrshield", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        
        response = requests.post(endpoint, json=payload, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if 'matches' in data:
                threats = [match['threatType'] for match in data['matches']]
                return {'flagged': True, 'threats': threats}
        
        return {'flagged': False, 'threats': []}
        
    except Exception as e:
        logger.error(f"Google Safe Browsing check failed: {e}")
        return {'flagged': False, 'threats': [], 'error': str(e)}

# ==================== VIRUSTOTAL API ====================
def check_virustotal(url):
    if not VT_API:
        return {'malicious': 0, 'suspicious': 0, 'score': 0, 'error': 'API key not configured', 'skipped': False}
    
    if not can_call_virustotal():
        return {'malicious': 0, 'suspicious': 0, 'score': 0, 'error': 'Rate limit exceeded', 'skipped': True}
    
    try:
        headers = {"x-apikey": VT_API}
        
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )
        
        if submit.status_code not in (200, 201):
            return {'malicious': 0, 'suspicious': 0, 'score': 0, 'error': 'Submission failed', 'skipped': False}
        
        record_vt_call()
        analysis_id = submit.json()["data"]["id"]
        
        # Wait for analysis
        for attempt in range(8):
            report = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=10
            )
            
            if report.status_code == 200:
                result = report.json()
                if result["data"]["attributes"]["status"] == "completed":
                    break
            time.sleep(2)
        
        stats = result["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        
        total = malicious + harmless + undetected
        score = int((malicious / total) * 100) if total > 0 else 0
        
        return {
            'malicious': malicious,
            'suspicious': stats.get('suspicious', 0),
            'score': score,
            'skipped': False
        }
        
    except Exception as e:
        logger.error(f"VirusTotal check failed: {e}")
        return {'malicious': 0, 'suspicious': 0, 'score': 0, 'error': str(e), 'skipped': False}

# ==================== RISK SCORE AGGREGATION ====================
def calculate_risk_score(vt_data, gsb_data, heuristic_data, url_status):
    total_score = 0
    all_reasons = []
    
    # VirusTotal contribution
    if vt_data and not vt_data.get('skipped'):
        vt_score = vt_data.get('score', 0)
        total_score += vt_score
        all_reasons.append(f"VirusTotal: {vt_data.get('malicious', 0)} engines flagged as malicious")
    
    # Google Safe Browsing contribution
    if gsb_data and gsb_data.get('flagged'):
        total_score += 50
        all_reasons.append(f"Google Safe Browsing flagged this URL")
    
    # Heuristic contribution
    heuristic_score = heuristic_data[0] if isinstance(heuristic_data, tuple) else 0
    heuristic_reasons = heuristic_data[1] if isinstance(heuristic_data, tuple) else []
    
    if heuristic_score > 0:
        total_score += heuristic_score
        all_reasons.extend(heuristic_reasons)
    
    # URL status contribution
    if url_status is None:
        total_score += 10
        all_reasons.append("Website unreachable or connection issues")
    elif url_status >= 400:
        total_score += 8
        all_reasons.append(f"Website returned error {url_status}")
    
    return min(total_score, 100), all_reasons

# ==================== CACHE MANAGEMENT ====================
def get_cached(url):
    if url in scan_cache:
        cached = scan_cache[url]
        if time.time() - cached['time'] < CACHE_TTL:
            return cached['result']
    return None

def set_cache(url, result):
    scan_cache[url] = {'result': result, 'time': time.time()}
    
    if len(scan_cache) > 500:
        current_time = time.time()
        to_delete = [k for k, v in scan_cache.items() 
                    if current_time - v['time'] > CACHE_TTL]
        for k in to_delete:
            del scan_cache[k]

# ==================== ROOT ENDPOINT (FIX FOR RENDER) ====================
@app.route("/", methods=["GET"])
def home():
    """Root endpoint - API information"""
    return jsonify({
        "service": "QRShield URL Scanner API",
        "version": "6.1",
        "status": "active",
        "timestamp": datetime.now().isoformat(),
        "endpoints": {
            "/check-url": {
                "method": "POST",
                "description": "Scan a URL for security threats",
                "example_body": {"url": "https://example.com"}
            },
            "/check": {"method": "POST", "description": "Alias for /check-url"},
            "/health": {"method": "GET", "description": "Service health status"},
            "/api/stats": {"method": "GET", "description": "Scanning statistics"}
        },
        "usage_example": {
            "curl": "curl -X POST https://your-app.onrender.com/check-url -H 'Content-Type: application/json' -d '{\"url\": \"https://google.com\"}'"
        }
    })

# ==================== MAIN SCAN ENDPOINT ====================
@app.route("/check-url", methods=["POST"])
@limiter.limit("30 per minute")
def check_url():
    """Main URL scanning endpoint"""
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "").strip()
    
    if not raw_url:
        return jsonify({
            "status": "error",
            "message": "No URL provided",
            "malicious_count": 0
        }), 400
    
    url = normalize_url(raw_url)
    
    if not url or not is_valid_url(url):
        return jsonify({
            "status": "error",
            "message": f"Invalid URL: '{raw_url}'",
            "malicious_count": 0
        }), 400
    
    cached = get_cached(url)
    if cached:
        return jsonify(cached)
    
    logger.info(f"Scanning URL: {url}")
    
    # Run security checks
    url_status = check_url_status(url)
    heuristic_result = advanced_heuristic_check(url)
    gsb_result = check_google_safe_browsing(url)
    vt_result = check_virustotal(url)
    
    # Calculate risk score
    final_score, all_reasons = calculate_risk_score(
        vt_result, gsb_result, heuristic_result, url_status
    )
    
    # Determine verdict
    if final_score >= 80:
        status = "Malicious"
        advice = "⚠️ DANGEROUS: Do NOT open this link."
        color = "danger"
    elif final_score >= 60:
        status = "High Risk"
        advice = "🔴 HIGH RISK: Strong indicators of malicious intent."
        color = "danger"
    elif final_score >= 40:
        status = "Suspicious"
        advice = "🟡 SUSPICIOUS: Multiple red flags detected."
        color = "warning"
    elif final_score >= 20:
        status = "Low Risk"
        advice = "🟠 LOW RISK: Some suspicious patterns."
        color = "warning"
    else:
        status = "Safe"
        advice = "✅ SAFE: No significant threats detected."
        color = "success"
    
    response = {
        "status": status,
        "status_color": color,
        "risk_score": final_score,
        "malicious_count": vt_result.get('malicious', 0) if vt_result else 0,
        "url": url,
        "domain": urlparse(url).netloc,
        "reasons": all_reasons[:10],
        "advice": advice,
        "timestamp": datetime.now().isoformat(),
        "api_status": {
            "virustotal": "skipped" if vt_result.get('skipped') else "completed",
            "google_safe": "completed" if gsb_result else "failed"
        }
    }
    
    set_cache(url, response)
    return jsonify(response)

# ==================== HEALTH CHECK ENDPOINT ====================
@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "ok",
        "version": "6.1",
        "services": {
            "virustotal": {
                "configured": bool(VT_API),
                "rate_limit": f"{VT_RATE_LIMIT}/min"
            },
            "google_safe_browsing": {
                "configured": bool(GSB_API)
            }
        },
        "timestamp": datetime.now().isoformat()
    })

# ==================== ALIAS ENDPOINTS ====================
@app.route("/check", methods=["POST"])
def check():
    """Alias for check-url endpoint"""
    return check_url()

# ==================== STATS ENDPOINT ====================
@app.route("/api/stats", methods=["GET"])
def stats():
    """Get scanning statistics"""
    return jsonify({
        "cache_size": len(scan_cache),
        "virustotal_rate_limit": {
            "max_per_minute": VT_RATE_LIMIT,
            "current_usage": len(vt_request_timestamps)
        }
    })

# ==================== MAIN EXECUTION ====================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "False").lower() == "true"
    
    app.run(host="0.0.0.0", port=port, debug=debug)