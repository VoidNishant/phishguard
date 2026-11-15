"""
Cybersecurity Heuristic Rules Engine.
Evaluates URLs against industry-standard cybersecurity indicators,
providing calibrated risk scoring and explainable security analysis.
"""

from urllib.parse import urlparse
from features import (
    normalize_url,
    is_ip_address,
    extract_domain_components,
    count_subdomains,
    get_tld,
    check_brand_abuse,
    has_punycode_or_homograph,
    has_non_standard_port,
    KNOWN_SHORTENERS,
    SUSPICIOUS_TLDS,
    SECURITY_KEYWORDS,
    TARGETED_BRANDS
)

class SecurityRule:
    def __init__(self, rule_id: str, name: str, severity: str, weight: int, description: str, rationale: str):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity  # 'Critical', 'High', 'Medium', 'Low'
        self.weight = weight      # Contribution to heuristic risk score
        self.description = description
        self.rationale = rationale


RULES = {
    "R_PSEUDO_PROTOCOL": SecurityRule(
        "R_PSEUDO_PROTOCOL",
        "Script Execution / Pseudo-Protocol",
        "Critical",
        40,
        "The URL uses a client-side execution scheme (e.g. javascript:, data:, vbscript:).",
        "Attackers leverage pseudo-protocols to execute arbitrary JavaScript (DOM-based XSS) or render phishing HTML payloads directly in the victim's browser context."
    ),
    "R_PUNYCODE_HOMOGRAPH": SecurityRule(
        "R_PUNYCODE_HOMOGRAPH",
        "IDN Homograph / Punycode Deception",
        "Critical",
        35,
        "The hostname utilizes Punycode ('xn--') or non-ASCII lookalike characters.",
        "Attackers substitute Latin letters with identical-looking Cyrillic or Greek glyphs (e.g., 'р' vs 'p') to deceive users into visiting spoofed domains that render identically."
    ),
    "R_BRAND_SPOOF": SecurityRule(
        "R_BRAND_SPOOF",
        "Targeted Brand Impersonation",
        "Critical",
        35,
        "A recognized major brand name is embedded in the subdomain or credential path of an untrusted domain.",
        "Phishing attacks routinely embed trusted brand names (e.g. PayPal, Apple, Google) into third-party attacker domains to deceive victims."
    ),
    "R_AT_SYMBOL": SecurityRule(
        "R_AT_SYMBOL",
        "Userinfo '@' Symbol in URL",
        "Critical",
        30,
        "The URL contains an '@' symbol in the authority component.",
        "According to RFC 3986, characters preceding '@' are interpreted as credentials and ignored by modern browsers, misleading victims about the true destination host."
    ),
    "R_IP_HOST": SecurityRule(
        "R_IP_HOST",
        "IP Address Hostname Detected",
        "High",
        25,
        "The URL uses a raw IP address instead of a registered domain name.",
        "Attackers frequently use raw IP addresses to bypass domain reputation filters and avoid WHOIS registration tracking."
    ),
    "R_NO_HTTPS_SENSITIVE": SecurityRule(
        "R_NO_HTTPS_SENSITIVE",
        "Unencrypted Protocol for Sensitive Actions",
        "High",
        25,
        "Sensitive authentication or financial keywords detected over unencrypted HTTP.",
        "Legitimate financial and authentication services strictly enforce HTTPS (TLS). Requesting credentials over HTTP indicates severe insecurity or fraudulent intent."
    ),
    "R_NON_STANDARD_PORT": SecurityRule(
        "R_NON_STANDARD_PORT",
        "Non-Standard Web Port Anomaly",
        "High",
        20,
        "The URL specifies an abnormal port outside standard web ports (80/443).",
        "Phishing kits, remote administrative panels, and compromised command-and-control endpoints frequently operate on non-standard ports to bypass perimeter firewalls."
    ),
    "R_EXCESS_SUBDOMAIN": SecurityRule(
        "R_EXCESS_SUBDOMAIN",
        "Excessive Subdomain Depth",
        "High",
        20,
        "The domain contains more than two subdomain levels.",
        "Attackers chain multiple subdomains (e.g., secure.update.bank.com.hacker.com) to make the URL look authentic on mobile address bars with limited display width."
    ),
    "R_DOUBLE_SLASH": SecurityRule(
        "R_DOUBLE_SLASH",
        "Path Traversal / Redirection Token ('//')",
        "High",
        20,
        "The URL path contains an unexpected double slash '//'.",
        "A double slash in the path component is commonly used to trick web frameworks or proxy servers into forwarding requests to external attacker domains."
    ),
    "R_SHORTENER": SecurityRule(
        "R_SHORTENER",
        "URL Shortening Service",
        "Medium",
        15,
        "The URL uses a public URL shortener service.",
        "URL shorteners conceal the true endpoint, making it impossible for the user to visually inspect the destination domain before clicking."
    ),
    "R_SUSP_TLD": SecurityRule(
        "R_SUSP_TLD",
        "High-Risk / Free TLD",
        "Medium",
        15,
        "The domain uses a Top-Level Domain known for high rates of malicious registration.",
        "TLDs like .xyz, .top, .tk, .ml are frequently exploited due to low acquisition costs and lenient abuse mitigation policies."
    ),
    "R_SUSP_HYPHENS": SecurityRule(
        "R_SUSP_HYPHENS",
        "Multiple Hyphens in Domain",
        "Medium",
        15,
        "The domain name contains multiple hyphens (-).",
        "Hyphens are rarely stacked in legitimate brand domains, but are prevalent in typosquatting and combosquatting domains (e.g. 'paypal-security-update.com')."
    ),
    "R_HEX_OBFUSCATION": SecurityRule(
        "R_HEX_OBFUSCATION",
        "Excessive Hex / Percent Obfuscation",
        "Medium",
        15,
        "The URL contains multiple percent-encoded sequences (e.g., %20, %2f).",
        "Attackers encode characters to evade signature-based Web Application Firewalls (WAFs) and heuristic text matching engines."
    ),
    "R_EXCESS_LENGTH": SecurityRule(
        "R_EXCESS_LENGTH",
        "Abnormally Long URL (>75 Characters)",
        "Low",
        10,
        "The overall URL length is unusually long.",
        "Phishing kits often pack base64-encoded email strings, victim identifiers, or tracking tokens into the query parameters to track targets."
    )
}


def analyze_heuristics(raw_url: str) -> dict:
    """
    Applies cybersecurity heuristic rules to a URL.
    Returns triggered rules, a calibrated rule-based risk score (0-100),
    and safety recommendations.
    """
    raw_clean = raw_url.strip() if raw_url else ""
    triggered = []
    total_score = 0

    # Rule: Pseudo-protocols (javascript:, data:, vbscript:, file:)
    lower_raw = raw_clean.lower()
    if lower_raw.startswith(("javascript:", "data:", "vbscript:", "file:")):
        rule = RULES["R_PSEUDO_PROTOCOL"]
        triggered.append({
            "rule": rule,
            "evidence": f"Dangerous execution scheme detected: {raw_clean.split(':')[0]}:"
        })
        total_score += rule.weight

    parsed_url = normalize_url(raw_clean)
    try:
        parsed = urlparse(parsed_url)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
    except Exception:
        hostname = ""
        path = ""
        query = ""

    # Rule: Punycode / Homograph
    if has_punycode_or_homograph(hostname):
        rule = RULES["R_PUNYCODE_HOMOGRAPH"]
        triggered.append({
            "rule": rule,
            "evidence": f"Punycode / Homograph encoding found in domain: '{hostname}'"
        })
        total_score += rule.weight

    # Rule: IP address
    if is_ip_address(hostname):
        rule = RULES["R_IP_HOST"]
        triggered.append({
            "rule": rule,
            "evidence": f"Domain resolved as IP: {hostname}"
        })
        total_score += rule.weight

    # Rule: @ symbol in authority
    if "@" in raw_clean:
        rule = RULES["R_AT_SYMBOL"]
        triggered.append({
            "rule": rule,
            "evidence": "Found '@' character in URL authority string"
        })
        total_score += rule.weight

    # Rule: Brand abuse
    if check_brand_abuse(hostname, path):
        matched_brands = [b for b in TARGETED_BRANDS if b in hostname or b in path.lower()]
        rule = RULES["R_BRAND_SPOOF"]
        triggered.append({
            "rule": rule,
            "evidence": f"Impersonated brand keyword(s): {', '.join(matched_brands)}"
        })
        total_score += rule.weight

    # Rule: Shortener
    if any(s in hostname for s in KNOWN_SHORTENERS):
        rule = RULES["R_SHORTENER"]
        triggered.append({
            "rule": rule,
            "evidence": f"Recognized shortener domain: {hostname}"
        })
        total_score += rule.weight

    # Rule: Suspicious TLD
    tld = get_tld(hostname)
    if tld in SUSPICIOUS_TLDS or (tld.split(".")[-1] in SUSPICIOUS_TLDS):
        rule = RULES["R_SUSP_TLD"]
        triggered.append({
            "rule": rule,
            "evidence": f"High-risk top-level domain: .{tld}"
        })
        total_score += rule.weight

    # Rule: Subdomain count
    subdomains = count_subdomains(hostname)
    if subdomains >= 2:
        rule = RULES["R_EXCESS_SUBDOMAIN"]
        triggered.append({
            "rule": rule,
            "evidence": f"Detected {subdomains} subdomain levels in {hostname}"
        })
        total_score += rule.weight

    # Rule: Non-standard port
    if has_non_standard_port(raw_clean):
        try:
            port_val = urlparse(normalize_url(raw_clean)).port
        except Exception:
            port_val = "Non-standard"
        rule = RULES["R_NON_STANDARD_PORT"]
        triggered.append({
            "rule": rule,
            "evidence": f"Non-standard web port detected: {port_val}"
        })
        total_score += rule.weight

    # Rule: Double slash in path
    if "//" in path:
        rule = RULES["R_DOUBLE_SLASH"]
        triggered.append({
            "rule": rule,
            "evidence": f"Double slash found in path: {path}"
        })
        total_score += rule.weight

    # Rule: Insecure protocol with sensitive keyword
    is_https = raw_clean.lower().startswith("https://")
    has_keywords = any(kw in (hostname + path + query).lower() for kw in SECURITY_KEYWORDS)
    if not is_https and has_keywords:
        rule = RULES["R_NO_HTTPS_SENSITIVE"]
        triggered.append({
            "rule": rule,
            "evidence": "HTTP protocol used with sensitive keywords in target"
        })
        total_score += rule.weight

    # Rule: Hyphens in domain
    if hostname.count("-") >= 2:
        rule = RULES["R_SUSP_HYPHENS"]
        triggered.append({
            "rule": rule,
            "evidence": f"Hostname contains {hostname.count('-')} hyphens"
        })
        total_score += rule.weight

    # Rule: Hex / percent encoding
    if raw_clean.count("%") >= 2:
        rule = RULES["R_HEX_OBFUSCATION"]
        triggered.append({
            "rule": rule,
            "evidence": f"Contains {raw_clean.count('%')} percent-encoding tokens"
        })
        total_score += rule.weight

    # Rule: Excessive length
    if len(raw_clean) > 75:
        rule = RULES["R_EXCESS_LENGTH"]
        triggered.append({
            "rule": rule,
            "evidence": f"URL length is {len(raw_clean)} characters (threshold: 75)"
        })
        total_score += rule.weight

    # If any Critical rule fired, ensure minimum heuristic score of 60
    has_critical = any(item["rule"].severity == "Critical" for item in triggered)
    if has_critical and total_score < 60:
        total_score = 60

    # Cap score at 100
    capped_score = min(100, total_score)

    if capped_score >= 55:
        verdict = "PHISHING / MALICIOUS"
        color = "red"
    elif capped_score >= 25:
        verdict = "SUSPICIOUS"
        color = "orange"
    else:
        verdict = "LEGITIMATE / SAFE"
        color = "green"

    return {
        "rule_risk_score": capped_score,
        "verdict": verdict,
        "color": color,
        "triggered_rules": triggered,
        "rules_checked_count": len(RULES),
        "rules_triggered_count": len(triggered)
    }
