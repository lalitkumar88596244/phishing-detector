"""
generate_dataset.py

Builds a labeled training set of URLs. This environment has no network
access, so instead of downloading PhishTank/OpenPhish/UCI data live,
we procedurally generate a realistic synthetic corpus:

  - LEGIT urls: drawn from well-known real domains with typical clean
    paths (as they'd actually appear).
  - PHISHING urls: generated using well-documented phishing URL
    patterns (typosquatting, brand-in-subdomain, IP hosts, suspicious
    TLDs, excess hyphens, sensitive keywords, URL shorteners, long
    obfuscated paths) — the same patterns real phishing kits use.

IMPORTANT for the real project: swap this out for actual PhishTank /
OpenPhish CSV feeds and the UCI Phishing Websites Dataset once you have
network access — the training pipeline (train.py) doesn't need to
change, only this file.
"""

import random
import csv

random.seed(42)

LEGIT_DOMAINS = [
    "google.com", "youtube.com", "wikipedia.org", "amazon.com", "reddit.com",
    "github.com", "stackoverflow.com", "nytimes.com", "bbc.com", "linkedin.com",
    "microsoft.com", "apple.com", "netflix.com", "instagram.com", "twitter.com",
    "paypal.com", "hdfcbank.com", "icicibank.com", "sbi.co.in", "irctc.co.in",
    "flipkart.com", "paytm.com", "phonepe.com", "outlook.com", "dropbox.com",
    "adobe.com", "zoom.us", "spotify.com", "salesforce.com", "shopify.com",
]

LEGIT_PATHS = [
    "", "/login", "/home", "/en/index.html", "/products", "/account/settings",
    "/watch?v=dQw4w9WgXcQ", "/search?q=news", "/help/support", "/about-us",
    "/blog/2026/new-features", "/pricing", "/user/profile", "/checkout/cart",
    "/api/v1/status", "/docs/getting-started",
]

BRANDS = [
    "paypal", "google", "microsoft", "amazon", "apple", "netflix", "facebook",
    "instagram", "hdfcbank", "icici", "sbi", "phonepe", "paytm", "irctc",
    "outlook", "flipkart", "linkedin",
]

SUSPICIOUS_TLDS = ["xyz", "top", "club", "work", "info", "biz", "gq", "tk", "ml", "cf"]
SENSITIVE_WORDS = ["secure", "login", "verify", "update", "account", "confirm", "signin", "webscr", "billing"]
NOISE_WORDS = ["portal", "customer", "service", "id", "auth", "session", "check", "alert", "support2026"]


def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def make_legit_url():
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    scheme = "https"
    sub = random.choice(["www.", "", "m.", "app."])
    return f"{scheme}://{sub}{domain}{path}"


def make_phishing_url():
    pattern = random.choice(["typosquat", "brand_subdomain", "ip_host", "shortener", "long_obfuscated", "hyphen_spam"])
    brand = random.choice(BRANDS)
    tld = random.choice(SUSPICIOUS_TLDS)
    word = random.choice(SENSITIVE_WORDS)
    noise = random.choice(NOISE_WORDS)

    if pattern == "typosquat":
        # swap/drop a character in the brand name
        b = list(brand)
        i = random.randrange(len(b))
        b[i] = random.choice("aeioubcdfg")
        typo = "".join(b)
        return f"http://{typo}.{tld}/{word}"

    if pattern == "brand_subdomain":
        return f"http://{brand}.{word}-{noise}.{tld}/{word}.php"

    if pattern == "ip_host":
        return f"http://{random_ip()}/{brand}/{word}/index.html"

    if pattern == "shortener":
        code = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEF0123456789", k=7))
        return f"http://bit.ly/{code}"

    if pattern == "long_obfuscated":
        junk = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789-", k=random.randint(25, 45)))
        return f"http://{brand}-{word}.{junk}.{tld}/{noise}/{word}/{junk[:10]}"

    # hyphen_spam
    return f"http://{brand}-{word}-{noise}-online.{tld}/{word}"


def build_dataset(n_per_class=600):
    rows = []
    for _ in range(n_per_class):
        rows.append((make_legit_url(), 0))
    for _ in range(n_per_class):
        rows.append((make_phishing_url(), 1))
    random.shuffle(rows)
    return rows


if __name__ == "__main__":
    rows = build_dataset(700)
    with open("data/urls.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])  # label: 1 = phishing, 0 = legit
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to data/urls.csv")
    print("Sample legit:", [r for r in rows if r[1] == 0][:3])
    print("Sample phishing:", [r for r in rows if r[1] == 1][:3])
