"""
Feature extraction module for Phishing URL Detection.
Extracts lexical, structural, and domain-based cybersecurity indicators from URLs.
"""

import re
import ipaddress
from urllib.parse import urlparse

# Well-known URL shortening services often abused by cyber attackers
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "shorte.st", "tiny.cc",
    "v.gd", "qr.ae", "rb.gy", "rebrand.ly", "t.ly", "bc.vc"
}

# High-risk / frequently abused Top-Level Domains (Spamhaus, SURBL, APWG stats)
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club",
    "work", "click", "loan", "surf", "date", "racing", "vip", "men",
    "stream", "download", "bid", "trade", "accountant", "review", "party",
    "cam", "fit", "rest", "cricket", "link", "win"
}

# Common multi-part public suffixes (country-code second-level domains)
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "com.br", "net.br", "org.br",
    "co.za", "org.za", "net.za",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "com.sg", "edu.sg", "gov.sg",
    "com.my", "net.my", "org.my",
    "com.mx", "org.mx", "gob.mx",
    "com.tr", "org.tr", "edu.tr",
    "co.kr", "ne.kr", "or.kr"
}

# Reputable platform domains where brands frequently appear in URLs legitimately (e.g. documentation, articles, repos)
REPUTABLE_PLATFORMS = {
    "wikipedia.org", "wikimedia.org", "github.com", "gitlab.com",
    "stackoverflow.com", "reddit.com", "youtube.com", "medium.com",
    "twitter.com", "x.com", "linkedin.com", "nytimes.com", "bbc.com",
    "cnn.com", "theguardian.com", "bloomberg.com", "reuters.com",
    "cisa.gov", "microsoft.com", "google.com", "apple.com", "amazon.com"
}

# Sensitive cybersecurity keywords frequently found in credential phishing URLs
SECURITY_KEYWORDS = [
    "login", "verify", "verification", "signin", "sign-in", "security",
    "update", "account", "banking", "secure", "wallet", "authenticate",
    "password", "credential", "confirm", "billing", "invoice", "recover",
    "webscr", "ebayisapi", "suspended", "urgent", "unlock", "portal",
    "auth", "validation", "passcode", "identity"
]

# Targeted brands often spoofed in phishing campaigns
TARGETED_BRANDS = [
    "paypal", "google", "apple", "microsoft", "netflix", "amazon",
    "facebook", "instagram", "whatsapp", "twitter", "chase", "wellsfargo",
    "binance", "coinbase", "dropbox", "yahoo", "linkedin", "steam"
]

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "count_dots",
    "count_hyphens",
    "count_at",
    "count_question",
    "count_equal",
    "count_slash",
    "count_percent",
    "count_digits",
    "digit_ratio",
    "has_ip",
    "has_shortener",
    "has_suspicious_tld",
    "keyword_count",
    "subdomain_count",
    "is_https",
    "double_slash_redirect",
    "brand_in_subdomain_or_path",
    "has_punycode",
    "has_non_standard_port"
]


def normalize_url(url: str) -> str:
    """Strip whitespace and add fallback scheme if missing."""
    url = url.strip()
    # Check if URL starts with a scheme
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        return "http://" + url
    return url


def is_ip_address(hostname: str) -> int:
    """Check if the hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return 0
    clean_host = hostname.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return 1
    except ValueError:
        pass
    
    # Fallback regex for IPv4
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, clean_host):
        return 1
    return 0


def extract_domain_components(hostname: str) -> tuple:
    """
    Accurately extracts (subdomain, registered_domain, tld)
    taking into account multi-part ccTLDs like '.co.uk' and raw IP addresses.
    """
    if not hostname:
        return ("", "", "")

    if is_ip_address(hostname):
        return ("(none - IP)", hostname, "(none - IP)")

    clean_host = hostname.lower()
    parts = clean_host.split(".")

    if len(parts) <= 1:
        return ("", clean_host, "")

    # Check for multi-part TLD (e.g. co.uk, com.au)
    if len(parts) >= 3:
        potential_two_part_tld = f"{parts[-2]}.{parts[-1]}"
        if potential_two_part_tld in MULTI_PART_TLDS:
            tld = potential_two_part_tld
            registered_domain = f"{parts[-3]}.{tld}"
            subdomain = ".".join(parts[:-3]) if len(parts) > 3 else ""
            return (subdomain, registered_domain, tld)

    # Standard single-part TLD (e.g. .com, .org, .xyz)
    tld = parts[-1]
    registered_domain = f"{parts[-2]}.{tld}"
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    return (subdomain, registered_domain, tld)


def count_subdomains(hostname: str) -> int:
    """Calculate the number of subdomains accurately."""
    if is_ip_address(hostname) or not hostname:
        return 0
    subdomain, _, _ = extract_domain_components(hostname)
    if not subdomain or subdomain == "(none - IP)":
        return 0
    return len(subdomain.split("."))


def get_tld(hostname: str) -> str:
    """Extract top-level domain accurately."""
    _, _, tld = extract_domain_components(hostname)
    return tld


def check_brand_abuse(hostname: str, path: str) -> int:
    """
    Detects if a known brand is present deceptively:
    1. Inside a subdomain of an untrusted domain (e.g. paypal.com.attacker.com)
    2. Inside the path COMBINED with a security/login keyword on an untrusted domain (e.g. attacker.com/paypal/login.php)
    Excludes reputable media/developer platforms (Wikipedia, GitHub) to eliminate false positives.
    """
    if not hostname:
        return 0

    clean_host = hostname.lower()
    path_lower = path.lower()

    subdomain, registered_domain, _ = extract_domain_components(clean_host)

    # If the registered domain itself belongs to a reputable platform (e.g. wikipedia.org, github.com),
    # brand mentions in path or query are benign references.
    if any(registered_domain.endswith(p) for p in REPUTABLE_PLATFORMS):
        return 0

    for brand in TARGETED_BRANDS:
        # If brand is part of the legitimate registered domain (e.g. paypal.com, paypal.co.uk)
        # then it is legitimate.
        if brand in registered_domain:
            continue

        # Condition 1: Brand appears in subdomain (Deceptive spoofing)
        if subdomain and brand in subdomain:
            return 1

        # Condition 2: Brand in path AND sensitive keyword in path (Phishing credential folder)
        if brand in path_lower and any(kw in path_lower for kw in SECURITY_KEYWORDS):
            return 1

    return 0


def has_punycode_or_homograph(hostname: str) -> int:
    """Checks for Punycode encoding (xn--) or non-ASCII characters in domain."""
    if not hostname:
        return 0
    clean_host = hostname.lower()
    if "xn--" in clean_host:
        return 1
    # Check for non-ASCII characters
    try:
        clean_host.encode("ascii")
    except UnicodeEncodeError:
        return 1
    return 0


def has_non_standard_port(url_str: str) -> int:
    """Checks if the URL specifies an unusual non-standard port."""
    try:
        norm = normalize_url(url_str)
        parsed = urlparse(norm)
        port = parsed.port
        if port is not None and port not in (80, 443, 8080):
            return 1
    except (ValueError, TypeError):
        pass
    return 0


def extract_features(raw_url: str) -> dict:
    """
    Extracts numerical and categorical cybersecurity features from a URL.
    Returns a dictionary of feature values keyed by FEATURE_NAMES.
    Guaranteed not to throw unhandled exceptions on malformed inputs.
    """
    raw_url = raw_url.strip() if raw_url else ""
    parsed_url = normalize_url(raw_url)
    
    try:
        parsed = urlparse(parsed_url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
    except Exception:
        hostname = ""
        path = ""
        query = ""

    full_clean = raw_url
    url_len = len(full_clean)
    host_len = len(hostname)
    path_len = len(path)

    # Lexical counts
    count_dots = full_clean.count(".")
    count_hyphens = full_clean.count("-")
    count_at = full_clean.count("@")
    count_question = full_clean.count("?")
    count_equal = full_clean.count("=")
    count_slash = full_clean.count("/")
    count_percent = full_clean.count("%")
    count_digits = sum(c.isdigit() for c in full_clean)
    digit_ratio = count_digits / url_len if url_len > 0 else 0.0

    # Structural & Behavioral flags
    has_ip = is_ip_address(hostname)
    has_shortener = 1 if any(shortener in hostname.lower() for shortener in KNOWN_SHORTENERS) else 0
    
    tld = get_tld(hostname)
    has_suspicious_tld = 1 if (tld in SUSPICIOUS_TLDS or tld.split(".")[-1] in SUSPICIOUS_TLDS) else 0

    # Sensitive keyword occurrences in path, query, and subdomain
    lower_target = (hostname + path + query).lower()
    keyword_count = sum(1 for kw in SECURITY_KEYWORDS if kw in lower_target)

    # Subdomain depth
    subdomain_count = count_subdomains(hostname)

    # Protocol
    is_https = 1 if raw_url.lower().startswith("https://") else 0

    # Double slash in path (redirect evasion)
    double_slash_redirect = 1 if "//" in path else 0

    # Brand abuse / Typosquatting in subdomain or path
    brand_flag = check_brand_abuse(hostname, path)

    # Punycode / Homograph
    punycode_flag = has_punycode_or_homograph(hostname)

    # Non-standard port
    port_flag = has_non_standard_port(raw_url)

    return {
        "url_length": url_len,
        "hostname_length": host_len,
        "path_length": path_len,
        "count_dots": count_dots,
        "count_hyphens": count_hyphens,
        "count_at": count_at,
        "count_question": count_question,
        "count_equal": count_equal,
        "count_slash": count_slash,
        "count_percent": count_percent,
        "count_digits": count_digits,
        "digit_ratio": round(digit_ratio, 4),
        "has_ip": has_ip,
        "has_shortener": has_shortener,
        "has_suspicious_tld": has_suspicious_tld,
        "keyword_count": keyword_count,
        "subdomain_count": subdomain_count,
        "is_https": is_https,
        "double_slash_redirect": double_slash_redirect,
        "brand_in_subdomain_or_path": brand_flag,
        "has_punycode": punycode_flag,
        "has_non_standard_port": port_flag
    }


def features_to_vector(features: dict) -> list:
    """Converts a feature dictionary to an ordered feature vector matching FEATURE_NAMES."""
    return [features.get(name, 0) for name in FEATURE_NAMES]
