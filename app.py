"""
app.py
Flask API serving the phishing detection model.

Endpoints:
  GET  /                 -> demo web UI
  POST /api/check        -> {"url": "..."} => phishing probability + verdict + feature breakdown
  GET  /api/health        -> health check
"""

from flask import Flask, request, jsonify, send_from_directory
import joblib
import numpy as np
import os

from features import extract_features

app = Flask(__name__, static_folder="static", static_url_path="")

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.joblib")
_bundle = joblib.load(MODEL_PATH)
MODEL = _bundle["model"]
FEATURE_ORDER = _bundle["feature_order"]

# Reasons shown to the user when a feature strongly indicates phishing
FEATURE_EXPLANATIONS = {
    "has_ip_address": "URL uses a raw IP address instead of a domain name",
    "has_at_symbol": "URL contains an '@' symbol, often used to obscure the real destination",
    "suspicious_tld": "Domain uses a top-level domain commonly abused for phishing (.xyz, .top, .tk, etc.)",
    "is_shortener": "URL uses a link-shortening service, hiding the true destination",
    "brand_lookalike": "Domain closely resembles a well-known brand name (possible typosquatting)",
    "brand_in_subdomain_not_root": "A brand name appears in the subdomain rather than the actual domain",
    "excessive_hyphens": "Domain contains an unusually high number of hyphens",
    "count_sensitive_words": "URL contains sensitive keywords (login, verify, secure, account, etc.)",
    "long_url": "URL is unusually long, a common obfuscation tactic",
    "has_double_slash_redirect": "Path contains a suspicious double-slash redirect pattern",
    "has_https": "Connection is not using HTTPS",
}


def build_explanation(feats: dict, verdict: str):
    reasons = []
    if verdict == "phishing":
        for key, msg in FEATURE_EXPLANATIONS.items():
            if key == "has_https":
                if feats.get(key) == 0:
                    reasons.append(msg)
            elif feats.get(key, 0) >= 1:
                reasons.append(msg)
    return reasons


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Please provide a 'url' field."}), 400

    feats = extract_features(url)
    x = np.array([[feats[k] for k in FEATURE_ORDER]], dtype=float)
    prob_phishing = float(MODEL.predict_proba(x)[0][1])
    verdict = "phishing" if prob_phishing >= 0.5 else "legit"
    confidence = prob_phishing if verdict == "phishing" else 1 - prob_phishing

    return jsonify({
        "url": url,
        "verdict": verdict,
        "phishing_probability": round(prob_phishing, 4),
        "confidence": round(confidence, 4),
        "reasons": build_explanation(feats, verdict),
        "features": feats,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=True)
