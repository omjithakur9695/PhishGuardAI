"""
PhishGuard AI - Comprehensive Cyber Threat Intelligence & Feature Extraction Engine
Handles:
1. Deep Lexical & Structural URL Feature Extraction (25+ indicators)
2. Domain Shannon Entropy (DGA / Botnet detection)
3. Brand Impersonation & Homograph/Punycode Detection
4. Email & SMS Social Engineering Threat Extraction
5. Calibrated Multi-Vector Composite Threat Scoring
6. Explainable AI (XAI) Factor Attribution
"""

import math
import re
import ipaddress
from urllib.parse import urlparse, unquote
from collections import Counter
from typing import Dict, Any, List, Tuple

# High-risk Top Level Domains frequently abused in phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "pw", "tk", "ml", "ga", "cf", "gq", "buzz", "ru",
    "cc", "work", "icu", "fit", "link", "click", "surf", "rest", "bar",
    "country", "stream", "gdn", "mom", "monster", "date", "racing", "kim"
}

# Top 50 targeted brands in global phishing reports (APWG & CISA)
TARGETED_BRANDS = {
    "paypal", "microsoft", "office365", "google", "apple", "amazon",
    "netflix", "chase", "wellsfargo", "bankofamerica", "citibank",
    "facebook", "instagram", "whatsapp", "telegram", "twitter", "linkedin",
    "steam", "dropbox", "dhl", "fedex", "usps", "ups", "ebay",
    "binance", "coinbase", "metamask", "blockchain", "kraken",
    "adobe", "yahoo", "spotify", "uber", "airbnb", "docuSign", "intuit",
    "irs", "gov", "att", "verizon", "tmobile", "vodafone"
}

# Common URL Shortener Services used to mask phishing destinations
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly",
    "ow.ly", "cutt.ly", "rebrand.ly", "tiny.cc", "shorte.st", "clck.ru"
}

# Phishing sensitive keywords
SENSITIVE_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "banking", "update", "wallet", "confirm", "confirmation",
    "password", "support", "billing", "invoice", "auth", "authenticate",
    "recover", "recovery", "suspend", "suspended", "validation", "authenticate",
    "payment", "free", "claim", "reward", "token", "unlock", "webscr", "ebayisapi"
]

# Globally trusted root domains for baseline normalization
TRUSTED_ROOT_DOMAINS = {
    "google.com", "google.co.in", "wikipedia.org", "github.com",
    "microsoft.com", "apple.com", "amazon.com", "amazon.in",
    "youtube.com", "linkedin.com", "stackoverflow.com", "netflix.com",
    "cloudflare.com", "python.org", "w3.org", "mozilla.org"
}

def prepare_url_for_ml(url: str) -> str:
    """
    Normalizes URL string for ML vectorizer by stripping protocol schemes
    to prevent spurious protocol correlation learned from public dataset artifacts.
    """
    clean = re.sub(r'^[a-zA-Z0-9+.-]+://', '', url.strip())
    clean = re.sub(r'^www\.', '', clean)
    return clean

# Social Engineering keywords in Phishing Emails / SMS
EMAIL_URGENCY_TRIGGERS = [
    r"\b(immediately|urgent|within\s+\d+\s+hours?|act\s+now|action\s+required)\b",
    r"\b(account\s+(will\s+be\s+)?(suspended|terminated|closed|locked|disabled))\b",
    r"\b(unauthorized\s+access|security\s+alert|unusual\s+activity)\b",
    r"\b(failure\s+to\s+respond|last\s+warning|final\s+notice)\b"
]

EMAIL_FINANCIAL_TRIGGERS = [
    r"\b(wire\s+transfer|refund\s+processed|invoice\s+attached|unpaid\s+invoice)\b",
    r"\b(cryptocurrency|bitcoin|ethereum|wallet\s+connected|gift\s+card)\b",
    r"\b(claim\s+your\s+prize|winner|lottery|exclusive\s+reward|\$\d+[\d,]*)\b",
    r"\b(tax\s+refund|direct\s+deposit|payroll\s+update|bank\s+details)\b"
]

EMAIL_ACTION_TRIGGERS = [
    r"\b(click\s+here|click\s+the\s+link|follow\s+this\s+link|verify\s+now)\b",
    r"\b(update\s+your\s+credentials|reset\s+password|confirm\s+identity)\b",
    r"\b(open\s+attachment|view\s+document|download\s+file)\b"
]

def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon Entropy of a string to detect Domain Generation Algorithms (DGA)
    or algorithmic randomized URL components.
    Higher entropy (> 3.8 for domains) indicates randomness.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 3)

def is_ip_address(hostname: str) -> bool:
    """Check if the host is a raw IPv4 or IPv6 address."""
    clean_host = hostname.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False

def extract_registered_domain(hostname: str) -> Tuple[str, str, List[str]]:
    """
    Extracts the root domain, TLD, and subdomains list.
    E.g. 'login.paypal.com.attacker.co.uk' -> ('attacker', 'co.uk', ['login', 'paypal', 'com'])
    """
    if not hostname:
        return "", "", []
    parts = hostname.lower().split(".")
    if len(parts) <= 1:
        return hostname, "", []
    
    # Simple multi-part TLD handling (co.uk, com.br, gov.in, etc.)
    multi_tlds = {"co.uk", "org.uk", "gov.uk", "com.br", "gov.in", "co.in", "com.au", "net.au", "co.jp"}
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in multi_tlds:
        tld = f"{parts[-2]}.{parts[-1]}"
        domain = parts[-3]
        subdomains = parts[:-3]
    else:
        tld = parts[-1]
        domain = parts[-2]
        subdomains = parts[:-2]
        
    return domain, tld, subdomains

def analyze_url_heuristics(raw_url: str) -> Dict[str, Any]:
    """
    Performs comprehensive 25-point heuristic and lexical analysis of a URL.
    Returns structured metrics, extracted features, risk flags, and rule score.
    """
    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_path = path + ("?" + query if query else "")

    domain, tld, subdomains = extract_registered_domain(hostname)
    
    # 1. Feature extractions
    is_ip = is_ip_address(hostname)
    has_at = "@" in url
    double_slash_in_path = "//" in path
    has_dash_in_domain = "-" in hostname
    subdomain_count = len(subdomains)
    domain_entropy = calculate_shannon_entropy(domain)
    path_entropy = calculate_shannon_entropy(path)
    url_length = len(url)
    domain_length = len(hostname)
    path_depth = len([p for p in path.split("/") if p])
    has_non_standard_port = bool(parsed.port and parsed.port not in (80, 443))
    is_https = parsed.scheme.lower() == "https"
    has_punycode = "xn--" in hostname or any(ord(c) > 127 for c in url)
    is_shortener = hostname in URL_SHORTENERS
    suspicious_tld_found = tld in SUSPICIOUS_TLDS

    # 2. Keywords inspection
    lower_url = url.lower()
    matched_keywords = [kw for kw in SENSITIVE_KEYWORDS if kw in lower_url]
    
    # 3. Brand Impersonation check (brand present in subdomain or path, but NOT the registered domain)
    impersonated_brands = []
    for brand in TARGETED_BRANDS:
        if brand in hostname or brand in path:
            if domain != brand and not domain.endswith(brand):
                impersonated_brands.append(brand)

    # 4. Heuristic Rule Weight Calculation (Transparent Explanations)
    risk_factors = []
    heuristic_points = 0

    if is_ip:
        risk_factors.append({
            "code": "IP_HOST",
            "weight": 25,
            "title": "Raw IP Address Host",
            "description": "Legitimate organizations rarely use bare IP addresses instead of trusted domain names.",
            "severity": "CRITICAL"
        })
        heuristic_points += 25

    if impersonated_brands:
        risk_factors.append({
            "code": "BRAND_SPOOF",
            "weight": 30,
            "title": f"Targeted Brand Impersonation ({', '.join(impersonated_brands).upper()})",
            "description": f"URL mentions reputable brand '{', '.join(impersonated_brands)}' but is hosted on '{domain}.{tld}'.",
            "severity": "CRITICAL"
        })
        heuristic_points += 30

    if has_punycode:
        risk_factors.append({
            "code": "HOMOGRAPH_PUNYCODE",
            "weight": 25,
            "title": "Homograph / Punycode Deception",
            "description": "Contains encoded or internationalized characters (IDN) used to spoof visual appearances.",
            "severity": "HIGH"
        })
        heuristic_points += 25

    if has_at:
        risk_factors.append({
            "code": "AT_SYMBOL",
            "weight": 20,
            "title": "'@' Character in Authority",
            "description": "Browsers ignore strings before '@', leading users to misidentify destination servers.",
            "severity": "HIGH"
        })
        heuristic_points += 20

    if double_slash_in_path:
        risk_factors.append({
            "code": "DOUBLE_SLASH",
            "weight": 15,
            "title": "Double Slash '//' Redirection",
            "description": "Path contains unexpected forward slashes often used in open-redirect exploits.",
            "severity": "MEDIUM"
        })
        heuristic_points += 15

    if is_shortener:
        risk_factors.append({
            "code": "URL_SHORTENER",
            "weight": 15,
            "title": "Masked Shortened URL",
            "description": f"Uses shortening service '{hostname}' which hides the final target landing page.",
            "severity": "MEDIUM"
        })
        heuristic_points += 15

    if suspicious_tld_found:
        risk_factors.append({
            "code": "HIGH_RISK_TLD",
            "weight": 15,
            "title": f"High-Risk TLD (.{tld})",
            "description": f"Top Level Domain '.{tld}' has an elevated statistical incidence of abuse in threat reports.",
            "severity": "MEDIUM"
        })
        heuristic_points += 15

    if subdomain_count >= 3:
        risk_factors.append({
            "code": "SUBDOMAIN_STACKING",
            "weight": 15,
            "title": f"Excessive Subdomain Stacking ({subdomain_count} levels)",
            "description": "Deep subdomain hierarchies are frequently generated to impersonate corporate portals.",
            "severity": "MEDIUM"
        })
        heuristic_points += 15

    if domain_entropy > 3.8:
        risk_factors.append({
            "code": "HIGH_DOMAIN_ENTROPY",
            "weight": 15,
            "title": f"High Domain Entropy ({domain_entropy:.2f} bits)",
            "description": "Domain name displays high character randomness, typical of Domain Generation Algorithms (DGA).",
            "severity": "MEDIUM"
        })
        heuristic_points += 15

    if len(matched_keywords) >= 2:
        risk_factors.append({
            "code": "SENSITIVE_KEYWORDS",
            "weight": 12,
            "title": f"Multiple Phishing Keywords ({', '.join(matched_keywords[:4])})",
            "description": "Presence of multiple authentication and financial verification tokens.",
            "severity": "MEDIUM"
        })
        heuristic_points += 12

    if url_length > 80:
        weight = 10 if url_length < 120 else 15
        risk_factors.append({
            "code": "ABNORMAL_LENGTH",
            "weight": weight,
            "title": f"Abnormal URL Length ({url_length} chars)",
            "description": "Excessively long URLs are routinely used to bury malicious payload parameters.",
            "severity": "LOW"
        })
        heuristic_points += weight

    if not is_https and matched_keywords:
        risk_factors.append({
            "code": "INSECURE_AUTH",
            "weight": 15,
            "title": "Unencrypted HTTP on Authentication/Portal Path",
            "description": "Requesting credentials or sensitive actions over plain HTTP without TLS encryption.",
            "severity": "HIGH"
        })
        heuristic_points += 15

    if has_non_standard_port:
        risk_factors.append({
            "code": "NON_STD_PORT",
            "weight": 10,
            "title": f"Non-Standard Port (:{parsed.port})",
            "description": "Web traffic is directed to an unconventional network port.",
            "severity": "LOW"
        })
        heuristic_points += 10

    # Cap heuristic points at 100
    heuristic_score = min(100, heuristic_points)

    return {
        "url": url,
        "hostname": hostname,
        "domain": domain,
        "tld": tld,
        "subdomains": subdomains,
        "subdomain_count": subdomain_count,
        "is_ip": is_ip,
        "is_https": is_https,
        "has_at": has_at,
        "has_dash": has_dash_in_domain,
        "double_slash_path": double_slash_in_path,
        "is_shortener": is_shortener,
        "suspicious_tld": suspicious_tld_found,
        "punycode": has_punycode,
        "url_length": url_length,
        "domain_entropy": domain_entropy,
        "path_entropy": path_entropy,
        "path_depth": path_depth,
        "matched_keywords": matched_keywords,
        "impersonated_brands": impersonated_brands,
        "heuristic_score": heuristic_score,
        "risk_factors": risk_factors
    }

def compute_composite_threat(ml_prob: float, heuristics: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensemble combination:
    Fuses the statistical ML model probability with rule-based heuristic indicators.
    Weighted formula: 55% ML probability + 45% Heuristics score, with critical overrides.
    """
    heur_score = heuristics["heuristic_score"]
    
    # Base weighted threat score (0 to 100)
    raw_threat = (ml_prob * 100.0 * 0.55) + (heur_score * 0.45)
    
    # Hard overrides for critical red flags
    if heuristics["is_ip"] or len(heuristics["impersonated_brands"]) > 0:
        raw_threat = max(raw_threat, 75.0)
    if heuristics["punycode"] and heuristics["matched_keywords"]:
        raw_threat = max(raw_threat, 80.0)

    # Established trusted authority whitelist check (when zero risk flags are present)
    reg_dom = f"{heuristics.get('domain', '')}.{heuristics.get('tld', '')}".lower()
    if reg_dom in TRUSTED_ROOT_DOMAINS and len(heuristics.get("risk_factors", [])) == 0:
        raw_threat = min(raw_threat, 10.0)
        
    threat_score = round(min(100.0, max(0.0, raw_threat)), 1)
    
    # Categorization
    if threat_score < 25.0:
        verdict = "SAFE"
        verdict_label = "Benign / Verified Safe"
        severity = "LOW_RISK"
        color = "#4ade80"  # Green
        summary = "No anomalous patterns or phishing indicators were detected in this URL."
    elif threat_score < 50.0:
        verdict = "SUSPICIOUS"
        verdict_label = "Low to Moderate Risk"
        severity = "MODERATE_RISK"
        color = "#facc15"  # Amber
        summary = "Minor suspicious traits detected. Exercise standard caution before entering credentials."
    elif threat_score < 75.0:
        verdict = "HIGH_RISK"
        verdict_label = "High Threat Detected"
        severity = "HIGH_RISK"
        color = "#fb923c"  # Orange
        summary = "Strong indicators of deceptive infrastructure or brand imitation identified."
    else:
        verdict = "MALICIOUS"
        verdict_label = "Critical Malicious Threat"
        severity = "CRITICAL_RISK"
        color = "#f43f5e"  # Red
        summary = "Confirmed phishing or malware signature. Do NOT open or submit data to this link."

    return {
        "threat_score": threat_score,
        "verdict": verdict,
        "verdict_label": verdict_label,
        "severity": severity,
        "color": color,
        "summary": summary,
        "ml_probability": round(ml_prob * 100.0, 1),
        "heuristic_score": round(float(heur_score), 1),
        "risk_factors_count": len(heuristics["risk_factors"])
    }

def analyze_email_phishing(text: str) -> Dict[str, Any]:
    """
    NLP & Social Engineering Analyzer for Phishing Emails and SMS.
    Scans for urgency triggers, financial bait, action demands, and embedded links.
    """
    content = text or ""
    clean_text = content.strip()
    if not clean_text:
        return {"error": "Content cannot be empty"}

    urgency_hits = []
    for pattern in EMAIL_URGENCY_TRIGGERS:
        matches = re.findall(pattern, clean_text, re.IGNORECASE)
        for m in matches:
            val = m[0] if isinstance(m, tuple) else m
            urgency_hits.append(val.strip())

    financial_hits = []
    for pattern in EMAIL_FINANCIAL_TRIGGERS:
        matches = re.findall(pattern, clean_text, re.IGNORECASE)
        for m in matches:
            val = m[0] if isinstance(m, tuple) else m
            financial_hits.append(val.strip())

    action_hits = []
    for pattern in EMAIL_ACTION_TRIGGERS:
        matches = re.findall(pattern, clean_text, re.IGNORECASE)
        for m in matches:
            val = m[0] if isinstance(m, tuple) else m
            action_hits.append(val.strip())

    # Extract all embedded URLs
    extracted_urls = re.findall(r'(https?://[^\s<>"]+|www\.[^\s<>"]+)', clean_text)
    
    # Scoring
    score = 0
    factors = []

    if urgency_hits:
        pts = min(30, len(urgency_hits) * 12)
        score += pts
        factors.append({
            "factor": "Artificial Urgency & Fear Tactics",
            "matches": list(set(urgency_hits))[:4],
            "severity": "HIGH",
            "points": pts,
            "desc": "Uses pressure tactics to bypass rational suspicion (e.g., immediate suspension notice)."
        })

    if financial_hits:
        pts = min(30, len(financial_hits) * 12)
        score += pts
        factors.append({
            "factor": "Financial / Crypto / Incentive Bait",
            "matches": list(set(financial_hits))[:4],
            "severity": "HIGH",
            "points": pts,
            "desc": "Mentions transactions, invoices, cryptocurrency, or unexpected funds."
        })

    if action_hits:
        pts = min(25, len(action_hits) * 10)
        score += pts
        factors.append({
            "factor": "Urgent Call-To-Action (CTA)",
            "matches": list(set(action_hits))[:4],
            "severity": "MEDIUM",
            "points": pts,
            "desc": "Instructs recipient to immediately follow links, reset passwords, or download files."
        })

    if extracted_urls:
        pts = 20
        score += pts
        factors.append({
            "factor": "Embedded Hyperlinks Detected",
            "matches": extracted_urls[:3],
            "severity": "MEDIUM",
            "points": pts,
            "desc": f"Found {len(extracted_urls)} hyperlink(s) embedded in the message."
        })

    final_score = min(100, score)

    if final_score >= 65:
        verdict = "PHISHING_ATTACK"
        label = "High Probability Phishing / Smishing"
        color = "#f43f5e"
    elif final_score >= 35:
        verdict = "SUSPICIOUS_MESSAGE"
        label = "Suspicious Communication"
        color = "#facc15"
    else:
        verdict = "LIKELY_LEGITIMATE"
        label = "Low Social Engineering Risk"
        color = "#4ade80"

    return {
        "text_length": len(clean_text),
        "word_count": len(clean_text.split()),
        "phishing_score": final_score,
        "verdict": verdict,
        "label": label,
        "color": color,
        "factors": factors,
        "extracted_urls": extracted_urls,
        "urgency_count": len(urgency_hits),
        "financial_count": len(financial_hits),
        "action_count": len(action_hits)
    }
