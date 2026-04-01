from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import time
import os
import re
import json
import hashlib
from urllib.parse import urlparse
from datetime import datetime, timedelta
import tldextract
import Levenshtein
from collections import defaultdict
import threading
from functools import wraps
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
VT_RATE_LIMIT = 4  # Max requests per minute
vt_request_timestamps = []  # Track request timestamps for rate limiting

# Cache configuration
CACHE_TTL = 300  # 5 minutes cache for URL scans
DOMAIN_REPUTATION_TTL = 3600  # 1 hour cache for domain reputation
scan_cache = {}  # In-memory cache for scan results
domain_reputation_cache = {}  # Cache for domain reputation data

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==================== PHISHING DETECTION PATTERNS ====================
# Weighted phishing keywords with risk levels
PHISHING_KEYWORDS = {
    'high': [  # High risk keywords (30-40% weight)
        'login', 'verify', 'secure', 'account', 'update', 'banking',
        'paypal', 'icloud', 'signin', 'confirm', 'password', 'wallet',
        'credential', 'authenticate', 'validation', 'verification',
        'suspended', 'limited', 'unusual-activity', 'security-alert',
        '2fa', 'mfa', 'multi-factor', 'authentication'
    ],
    'medium': [  # Medium risk keywords (15-25% weight)
        'click', 'redirect', 'recover', 'unlock', 'restore', 'validate',
        'activate', 'deactivate', 'upgrade', 'downgrade', 'payment',
        'invoice', 'receipt', 'statement', 'transaction', 'refund',
        'alert', 'notice', 'important', 'urgent', 'action-required'
    ],
    'low': [  # Low risk keywords (5-10% weight)
        'offer', 'promotion', 'discount', 'free', 'win', 'prize',
        'gift', 'reward', 'bonus', 'exclusive', 'limited-time',
        'newsletter', 'subscription', 'membership'
    ]
}

# Known legitimate brands for typosquatting detection
BRAND_DOMAINS = {
    'paypal.com', 'apple.com', 'google.com', 'microsoft.com', 'amazon.com',
    'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'netflix.com',
    'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citibank.com',
    'dropbox.com', 'drive.google.com', 'icloud.com', 'outlook.com', 'office.com',
    'github.com', 'stackoverflow.com', 'reddit.com', 'youtube.com', 'whatsapp.com'
}

# ==================== RATE LIMITING UTILITY ====================
def can_call_virustotal():
    """
    Check if we can call VirusTotal API based on rate limit (4/min)
    Returns: bool - True if allowed, False if rate limit exceeded
    """
    global vt_request_timestamps
    current_time = time.time()
    
    # Remove timestamps older than 60 seconds
    vt_request_timestamps = [ts for ts in vt_request_timestamps if current_time - ts < 60]
    
    # Check if we've hit the rate limit
    if len(vt_request_timestamps) >= VT_RATE_LIMIT:
        logger.warning(f"VirusTotal rate limit reached ({VT_RATE_LIMIT}/min). Skipping VT check.")
        return False
    
    return True

def record_vt_call():
    """Record a VirusTotal API call timestamp"""
    global vt_request_timestamps
    vt_request_timestamps.append(time.time())

# ==================== URL PROCESSING UTILITIES ====================
def normalize_url(url):
    """
    Normalize and clean URL
    - Auto-add https:// if missing
    - Remove URL encoding
    - Handle special characters
    """
    url = url.strip()
    if not url:
        return None
    
    # Remove URL encoding
    try:
        from urllib.parse import unquote
        url = unquote(url)
    except:
        pass
    
    # Add scheme if missing
    if not re.match(r'^[a-zA-Z]+://', url):
        url = 'https://' + url
    
    return url

def is_valid_url(url):
    """
    Validate URL format
    - Check scheme (http/https)
    - Validate domain format
    """
    try:
        result = urlparse(url)
        if result.scheme not in ('http', 'https'):
            return False
        if not result.netloc:
            return False
        
        # Validate domain format
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        domain = result.netloc.split(':')[0]
        if not re.match(domain_pattern, domain):
            return False
        
        return True
    except:
        return False

def check_url_status(url):
    """
    Check if URL is accessible
    Returns: status_code or None if unreachable
    """
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

# ==================== HEURISTIC ANALYSIS (ENHANCED) ====================
def advanced_heuristic_check(url):
    """
    Enhanced heuristic detection with phishing patterns
    Returns: (score, reasons, details)
    """
    score = 0
    reasons = []
    details = {}
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    
    # 1. URL pattern-based detection (most critical)
    url_patterns = [
        (r'https?://[^/]+@', 'URL contains @ symbol (credentials in URL)', 35),
        (r'https?://.*?\.\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'Raw IP address used instead of domain', 30),
        (r'https?://[^/]+\.(?:tk|ml|ga|cf|gq|top|xyz|club|online|site|website|click|link|win)', 'Suspicious TLD often used in phishing', 25),
        (r'xn--', 'Punycode domain detected (possible homograph attack)', 25),
        (r'https?://[^/]+-\w+\.\w+', 'Hyphen in domain (often used in typosquatting)', 15),
        (r'https?://[^/]+\.[^/]+\.\w+', 'Multiple subdomains (obfuscation technique)', 12),
        (r'[%][0-9a-fA-F]{2}', 'URL encoding detected (obfuscation technique)', 10),
    ]
    
    for pattern, reason, points in url_patterns:
        if re.search(pattern, url):
            score += points
            reasons.append(reason)
            details['pattern_match'] = pattern
    
    # 2. Phishing keyword detection (weighted by category)
    keyword_score = 0
    detected_keywords = defaultdict(list)
    
    # Check all parts of URL
    url_parts = [domain, path, query]
    
    for category, keywords in PHISHING_KEYWORDS.items():
        for keyword in keywords:
            for part in url_parts:
                if keyword in part:
                    if category == 'high':
                        points = 12  # High risk keywords
                    elif category == 'medium':
                        points = 8   # Medium risk keywords
                    else:
                        points = 5   # Low risk keywords
                    
                    keyword_score += points
                    detected_keywords[category].append(keyword)
                    break  # Avoid duplicate counting
    
    if keyword_score > 0:
        score += min(keyword_score, 35)  # Cap at 35 points
        reasons.append(f"Phishing keywords detected: {', '.join(detected_keywords['high'][:3])}")
        details['detected_keywords'] = dict(detected_keywords)
    
    # 3. Brand similarity detection (typosquatting)
    brand_similarity = check_brand_similarity(domain)
    if brand_similarity['similar']:
        score += brand_similarity['score']
        reasons.append(f"Looks similar to known brand: {brand_similarity['brand']}")
        details['brand_similarity'] = brand_similarity
    
    # 4. Domain characteristics
    # Check domain length
    if len(domain) > 35:
        score += 10
        reasons.append(f"Excessively long domain name ({len(domain)} chars)")
    elif len(domain) > 50:
        score += 15
        reasons.append("Domain name exceeds normal length significantly")
    
    # Check subdomain count
    subdomain_count = domain.count('.')
    if subdomain_count > 2:
        extra_points = min((subdomain_count - 2) * 3, 12)
        score += extra_points
        reasons.append(f"Unusual number of subdomains ({subdomain_count})")
    
    # 5. HTTPS check (critical)
    if parsed.scheme != 'https':
        score += 15
        reasons.append("Website not using HTTPS encryption")
        details['no_https'] = True
    
    # 6. Login/credential detection
    credential_indicators = [
        'login', 'signin', 'auth', 'authenticate', 'verify', 'validation',
        'credential', 'password', 'passwd', 'user', 'username', 'account',
        'secure', 'security', 'confirm', 'verification', '2fa', 'mfa'
    ]
    
    credential_count = sum(1 for ind in credential_indicators if ind in path or ind in query)
    if credential_count > 0:
        score += min(credential_count * 6, 25)
        reasons.append(f'Contains {credential_count} credential-related terms (possible login harvesting)')
        details['credential_indicators'] = credential_count
    
    # 7. Redirect parameter detection
    redirect_params = ['redirect', 'url=', 'link=', 'goto=', 'return=', 'next=']
    if any(param in query for param in redirect_params):
        score += 12
        reasons.append('URL contains redirect parameters (often used in phishing)')
        details['has_redirect'] = True
    
    # Cap heuristic score at 60 (max 60% from heuristics)
    return min(score, 60), reasons, details

def check_brand_similarity(domain):
    """
    Detect typosquatting and brand impersonation
    Uses Levenshtein distance for similarity detection
    """
    extracted = tldextract.extract(domain)
    domain_name = extracted.domain
    suffix = extracted.suffix
    
    best_match = None
    highest_similarity = 0
    
    for brand in BRAND_DOMAINS:
        brand_extracted = tldextract.extract(brand)
        brand_name = brand_extracted.domain
        
        # Check for exact match in subdomain (potential abuse)
        if domain_name == brand_name:
            if extracted.subdomain:
                return {
                    'similar': True,
                    'brand': brand,
                    'score': 25,
                    'type': 'subdomain_abuse'
                }
        
        # Levenshtein distance for typosquatting detection
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

# ==================== DOMAIN REPUTATION CHECK ====================
def check_domain_reputation(domain):
    """
    Comprehensive domain reputation analysis
    - Domain age
    - Security records (SPF, DMARC, MX)
    """
    # Check cache first
    if domain in domain_reputation_cache:
        cached = domain_reputation_cache[domain]
        if time.time() - cached['time'] < DOMAIN_REPUTATION_TTL:
            return cached['data']
    
    reputation_data = {
        'age_days': None,
        'has_whois': False,
        'mx_records': False,
        'spf_record': False,
        'dmarc_record': False,
        'risk_score': 0,
        'reasons': []
    }
    
    # 1. Check domain age using WHOIS
    try:
        import whois
        w = whois.whois(domain)
        if w.creation_date:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            
            age = (datetime.now() - creation_date).days
            reputation_data['age_days'] = age
            reputation_data['has_whois'] = True
            
            # Very new domains (high risk)
            if age < 7:
                reputation_data['risk_score'] += 35
                reputation_data['reasons'].append(f'Domain is extremely new ({age} days old) - common in phishing')
            elif age < 30:
                reputation_data['risk_score'] += 25
                reputation_data['reasons'].append(f'Domain is new ({age} days old) - requires caution')
            elif age < 90:
                reputation_data['risk_score'] += 15
                reputation_data['reasons'].append(f'Domain is relatively new ({age} days old)')
    except Exception as e:
        logger.debug(f"WHOIS check failed for {domain}: {e}")
        reputation_data['reasons'].append('Unable to verify domain age')
    
    # 2. Check DNS security records
    try:
        import dns.resolver
        
        # Check MX records (email servers)
        try:
            mx = dns.resolver.resolve(domain, 'MX')
            if mx:
                reputation_data['mx_records'] = True
        except:
            reputation_data['reasons'].append('No MX records found (unusual for legitimate sites)')
            reputation_data['risk_score'] += 5
        
        # Check SPF record (email authentication)
        try:
            spf = dns.resolver.resolve(domain, 'TXT')
            for record in spf:
                if 'v=spf1' in str(record):
                    reputation_data['spf_record'] = True
                    break
            if not reputation_data['spf_record']:
                reputation_data['reasons'].append('Missing SPF record')
                reputation_data['risk_score'] += 8
        except:
            reputation_data['reasons'].append('Missing SPF record')
            reputation_data['risk_score'] += 8
        
        # Check DMARC record (email security)
        try:
            dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for record in dmarc:
                if 'v=DMARC1' in str(record):
                    reputation_data['dmarc_record'] = True
                    break
            if not reputation_data['dmarc_record']:
                reputation_data['reasons'].append('Missing DMARC record')
                reputation_data['risk_score'] += 8
        except:
            reputation_data['reasons'].append('Missing DMARC record')
            reputation_data['risk_score'] += 8
            
    except Exception as e:
        logger.debug(f"DNS check failed for {domain}: {e}")
    
    # Cap risk score at 40 (max 40% from domain reputation)
    reputation_data['risk_score'] = min(reputation_data['risk_score'], 40)
    
    # Cache the result
    domain_reputation_cache[domain] = {
        'data': reputation_data,
        'time': time.time()
    }
    
    return reputation_data

# ==================== GOOGLE SAFE BROWSING API ====================
def check_google_safe_browsing(url):
    """
    Check URL against Google Safe Browsing database
    Returns: {'flagged': bool, 'threats': list}
    """
    if not GSB_API:
        return {'flagged': False, 'threats': [], 'error': 'API key not configured'}
    
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API}"
        payload = {
            "client": {"clientId": "qrshield", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", 
                    "SOCIAL_ENGINEERING", 
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
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

# ==================== VIRUSTOTAL API (WITH RATE LIMITING) ====================
def check_virustotal(url):
    """
    Check URL against VirusTotal
    Automatically skips if rate limit (4/min) is exceeded
    Returns: {'malicious': int, 'suspicious': int, 'score': int, 'details': dict}
    """
    if not VT_API:
        return {'malicious': 0, 'suspicious': 0, 'score': 0, 'error': 'API key not configured', 'skipped': False}
    
    # Check rate limit before proceeding
    if not can_call_virustotal():
        return {'malicious': 0, 'suspicious': 0, 'score': 0, 'error': 'Rate limit exceeded', 'skipped': True}
    
    try:
        headers = {"x-apikey": VT_API}
        
        # Step 1: Submit URL for scanning
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )
        
        if submit.status_code not in (200, 201):
            logger.error(f"VirusTotal submission failed: {submit.status_code}")
            return {'malicious': 0, 'suspicious': 0, 'score': 0, 'error': 'Submission failed', 'skipped': False}
        
        # Record this API call
        record_vt_call()
        
        analysis_id = submit.json()["data"]["id"]
        
        # Step 2: Wait for analysis to complete (max 15 seconds)
        max_retries = 8
        for attempt in range(max_retries):
            report = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=10
            )
            
            if report.status_code == 200:
                result = report.json()
                if result["data"]["attributes"]["status"] == "completed":
                    break
            time.sleep(2)  # Wait 2 seconds between retries
        
        # Step 3: Parse results
        stats = result["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        
        # Calculate risk score (0-100)
        total = malicious + suspicious + harmless + undetected
        if total > 0:
            score = int((malicious / total) * 100)
        else:
            score = 0
        
        return {
            'malicious': malicious,
            'suspicious': suspicious,
            'score': score,
            'skipped': False,
            'total_scanners': total
        }
        
    except Exception as e:
        logger.error(f"VirusTotal check failed: {e}")
        return {'malicious': 0, 'suspicious': 0, 'score': 0, 'error': str(e), 'skipped': False}

# ==================== RISK SCORE AGGREGATION ====================
def calculate_risk_score(vt_data, gsb_data, heuristic_data, domain_rep_data, url_status):
    """
    Aggregate risk scores from all sources
    Returns: (final_score, all_reasons, details)
    """
    total_score = 0
    all_reasons = []
    details = {
        'sources': {}
    }
    
    # 1. VirusTotal contribution (0-100 points)
    if vt_data and not vt_data.get('skipped'):
        vt_malicious = vt_data.get('malicious', 0)
        vt_score = vt_data.get('score', 0)
        
        # Convert VT score to our scoring system
        vt_contribution = vt_score  # Already 0-100
        total_score += vt_contribution
        all_reasons.append(f"VirusTotal: {vt_malicious} engines flagged as malicious")
        details['sources']['virustotal'] = {
            'malicious': vt_malicious,
            'contribution': vt_contribution
        }
    elif vt_data and vt_data.get('skipped'):
        all_reasons.append("VirusTotal check skipped (rate limit)")
        details['sources']['virustotal'] = {'skipped': True}
    
    # 2. Google Safe Browsing contribution (0-60 points)
    if gsb_data and gsb_data.get('flagged'):
        gsb_contribution = 50
        total_score += gsb_contribution
        threats = ', '.join(gsb_data.get('threats', []))
        all_reasons.append(f"Google Safe Browsing flagged this URL ({threats})")
        details['sources']['google_safe'] = {
            'flagged': True,
            'threats': gsb_data['threats'],
            'contribution': gsb_contribution
        }
    elif gsb_data:
        details['sources']['google_safe'] = {'flagged': False}
    
    # 3. Heuristic analysis contribution (0-60 points)
    heuristic_score = heuristic_data[0] if isinstance(heuristic_data, tuple) else 0
    heuristic_reasons = heuristic_data[1] if isinstance(heuristic_data, tuple) else []
    
    if heuristic_score > 0:
        total_score += heuristic_score
        all_reasons.extend(heuristic_reasons)
        details['sources']['heuristic'] = {
            'score': heuristic_score,
            'contribution': heuristic_score
        }
    
    # 4. Domain reputation contribution (0-40 points)
    if domain_rep_data:
        domain_score = domain_rep_data.get('risk_score', 0)
        if domain_score > 0:
            total_score += domain_score
            all_reasons.extend(domain_rep_data.get('reasons', []))
            details['sources']['domain_reputation'] = {
                'score': domain_score,
                'contribution': domain_score
            }
    
    # 5. URL status contribution (0-15 points)
    if url_status is None:
        total_score += 10
        all_reasons.append("Website unreachable or connection issues")
        details['sources']['url_status'] = {'status': 'unreachable', 'contribution': 10}
    elif url_status >= 400:
        total_score += 8
        all_reasons.append(f"Website returned error {url_status}")
        details['sources']['url_status'] = {'status': 'error', 'code': url_status, 'contribution': 8}
    
    # Cap final score at 100
    final_score = min(total_score, 100)
    
    return final_score, all_reasons, details

# ==================== CACHE MANAGEMENT ====================
def get_cached(url):
    """Retrieve cached scan result"""
    if url in scan_cache:
        cached = scan_cache[url]
        if time.time() - cached['time'] < CACHE_TTL:
            return cached['result']
    return None

def set_cache(url, result):
    """Store scan result in cache"""
    scan_cache[url] = {
        'result': result,
        'time': time.time()
    }
    
    # Clean old cache entries if too many
    if len(scan_cache) > 500:
        current_time = time.time()
        to_delete = [k for k, v in scan_cache.items() 
                    if current_time - v['time'] > CACHE_TTL]
        for k in to_delete:
            del scan_cache[k]

# ==================== MAIN SCAN ENDPOINT ====================
@app.route("/check-url", methods=["POST"])
@limiter.limit("30 per minute")
def check_url():
    """
    Main URL scanning endpoint
    Performs comprehensive security analysis with rate-limited APIs
    """
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "").strip()
    
    if not raw_url:
        return jsonify({
            "status": "error",
            "message": "No URL provided",
            "malicious_count": 0
        }), 400
    
    # Step 1: Normalize and validate URL
    url = normalize_url(raw_url)
    
    if not url or not is_valid_url(url):
        return jsonify({
            "status": "error",
            "message": f"Invalid URL: '{raw_url}' — could not parse as a valid web address",
            "malicious_count": 0
        }), 400
    
    # Step 2: Check cache
    cached = get_cached(url)
    if cached:
        return jsonify(cached)
    
    # Step 3: Parse URL components
    parsed = urlparse(url)
    domain = parsed.netloc
    
    # Step 4: Run all security checks
    logger.info(f"Scanning URL: {url}")
    
    # URL status check (lightweight)
    url_status = check_url_status(url)
    
    # Heuristic analysis (fast, no API)
    heuristic_result = advanced_heuristic_check(url)
    
    # Domain reputation check (moderate, DNS lookups)
    domain_rep = check_domain_reputation(domain)
    
    # Google Safe Browsing API (one API call)
    gsb_result = check_google_safe_browsing(url)
    
    # VirusTotal API (rate-limited to 4/min)
    vt_result = check_virustotal(url)
    
    # Step 5: Aggregate risk scores
    final_score, all_reasons, details = calculate_risk_score(
        vt_result, 
        gsb_result, 
        heuristic_result, 
        domain_rep, 
        url_status
    )
    
    # Step 6: Determine verdict and color
    if final_score >= 80:
        status = "Malicious"
        advice = "⚠️ DANGEROUS: Do NOT open this link. Confirmed malicious by security vendors."
        color = "danger"
    elif final_score >= 60:
        status = "High Risk"
        advice = "🔴 HIGH RISK: Strong indicators of malicious intent. Avoid this URL."
        color = "danger"
    elif final_score >= 40:
        status = "Suspicious"
        advice = "🟡 SUSPICIOUS: Multiple red flags detected. Exercise extreme caution."
        color = "warning"
    elif final_score >= 20:
        status = "Low Risk"
        advice = "🟠 LOW RISK: Some suspicious patterns. Verify before proceeding."
        color = "warning"
    else:
        status = "Safe"
        advice = "✅ SAFE: No significant threats detected. URL appears legitimate."
        color = "success"
    
    # Step 7: Prepare response
    response = {
        "status": status,
        "status_color": color,
        "risk_score": final_score,
        "malicious_count": vt_result.get('malicious', 0) if vt_result else 0,
        "url": url,
        "domain": domain,
        "reasons": all_reasons[:12],  # Limit to 12 reasons for readability
        "advice": advice,
        "scan_details": details,
        "timestamp": datetime.now().isoformat(),
        "api_status": {
            "virustotal": "skipped" if vt_result.get('skipped') else "completed" if vt_result else "failed",
            "google_safe": "completed" if gsb_result else "failed"
        }
    }
    
    # Step 8: Cache and return
    set_cache(url, response)
    return jsonify(response)

# ==================== HEALTH CHECK ENDPOINT ====================
@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint with service status"""
    return jsonify({
        "status": "ok",
        "version": "6.1",
        "services": {
            "virustotal": {
                "configured": bool(VT_API),
                "rate_limit": f"{VT_RATE_LIMIT}/min",
                "current_usage": len(vt_request_timestamps)
            },
            "google_safe_browsing": {
                "configured": bool(GSB_API)
            }
        },
        "cache": {
            "size": len(scan_cache),
            "ttl": CACHE_TTL
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
        "domain_cache_size": len(domain_reputation_cache),
        "virustotal_rate_limit": {
            "max_per_minute": VT_RATE_LIMIT,
            "current_usage": len(vt_request_timestamps)
        },
        "cached_urls": list(scan_cache.keys())[:10]
    })

# ==================== MAIN EXECUTION ====================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "False").lower() == "true"
    
    app.run(host="0.0.0.0", port=port, debug=debug)