"""
features.py
Extracts lexical and structural features from a URL that are commonly
predictive of phishing behavior. No network calls are made here — this
is pure string/structure analysis of the URL itself so it works offline
and instantly (sub-millisecond per URL).

For a production system you would add a second stage that fetches the
page (HTML/DOM) and checks things like login-form presence, favicon
hash, and brand-logo similarity — see content_features.py stub at the
bottom for where that would plug in.
"""

import re
import math
from urllib.parse import urlparse

# A small list of high-value brand names commonly targeted by phishing.
# Used to detect "brand + noise" domains like "paypal-secure-login.com"
KNOWN_BRANDS = [
    "paypal", "google", "microsoft", "amazon", "apple", "netflix",
    "facebook", "instagram", "whatsapp", "bankofamerica", "chase",
    "hdfc", "icici", "sbi", "axisbank", "phonepe", "paytm", "gpay",
    "irctc", "flipkart", "linkedin", "outlook", "netbanking",
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "work", "info", "biz", "gq", "tk", "ml",
    "cf", "ga", "loan", "win", "review", "download",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly",
}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(
                prev[j] + 1,
                cur[j - 1] + 1,
                prev[j - 1] + (ca != cb),
            )
        prev = cur
    return prev[-1]


def closest_brand_distance(domain: str):
    """Return (brand, edit_distance) for the nearest known brand name."""
    core = domain.split(".")[0]
    best_brand, best_dist = None, 99
    for brand in KNOWN_BRANDS:
        d = levenshtein(core, brand)
        if d < best_dist:
            best_brand, best_dist = brand, d
    return best_brand, best_dist


def extract_features(url: str) -> dict:
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url_full = "http://" + url
    else:
        url_full = url

    parsed = urlparse(url_full)
    domain = parsed.netloc.lower().split(":")[0]
    path = parsed.path or ""
    query = parsed.query or ""

    tld = domain.split(".")[-1] if "." in domain else ""
    subdomain_count = max(domain.count(".") - 1, 0)

    brand, brand_dist = closest_brand_distance(domain)
    # "brand_lookalike": close to a brand name but not an exact/legit match
    brand_lookalike = 1 if (brand and 0 < brand_dist <= 2) else 0
    brand_in_subdomain = 1 if (
        brand and brand in domain and not domain.startswith(brand + ".")
        and not domain.split(".")[-2:] == [brand, tld]
    ) else 0

    feats = {
        "url_length": len(url_full),
        "domain_length": len(domain),
        "path_length": len(path),
        "num_dots": domain.count("."),
        "num_hyphens": domain.count("-"),
        "num_digits_domain": sum(c.isdigit() for c in domain),
        "num_subdomains": subdomain_count,
        "has_ip_address": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0,
        "has_at_symbol": 1 if "@" in url_full else 0,
        "has_https": 1 if parsed.scheme == "https" else 0,
        "is_shortener": 1 if domain in SHORTENERS else 0,
        "suspicious_tld": 1 if tld in SUSPICIOUS_TLDS else 0,
        "num_query_params": query.count("=") if query else 0,
        "path_entropy": round(shannon_entropy(path), 3),
        "domain_entropy": round(shannon_entropy(domain), 3),
        "has_double_slash_redirect": 1 if "//" in path else 0,
        "count_sensitive_words": sum(
            w in url_full.lower()
            for w in ["login", "secure", "account", "update", "verify",
                      "bank", "confirm", "signin", "webscr", "password"]
        ),
        "brand_lookalike": brand_lookalike,
        "brand_in_subdomain_not_root": brand_in_subdomain,
        "excessive_hyphens": 1 if domain.count("-") >= 3 else 0,
        "long_url": 1 if len(url_full) > 75 else 0,
    }
    return feats


FEATURE_ORDER = list(extract_features("http://example.com").keys())


if __name__ == "__main__":
    samples = [
        "https://www.paypal.com/signin",
        "http://paypal-secure-login.verify-account.xyz/signin",
        "http://192.168.1.5/update-account",
        "https://bit.ly/3xJ9klm",
        "https://www.hdfcbank.com/personal/pay",
    ]
    for s in samples:
        print(s)
        print(extract_features(s))
        print()
