# URLGuard

### AI Powered Phishing Website Detection System

**Date:** July 02, 2026 | **Author/Lead: Lalit Kumar | **Status:** V1 — Functional Prototype

**Project Links:** [Repository Link] | [Live Application / Demo Link]

---

## 1. Executive Overview

- **Objective:** Detect phishing websites in real time by scoring URLs with a trained machine learning classifier, before a user ever submits credentials.
- **The Challenge:** Traditional phishing defenses rely on blacklists (PhishTank, Google Safe Browsing) that only catch a site *after* it has already been reported — leaving a window of hours to days where brand-new phishing domains go undetected. Phishing kits also mass-produce near-identical lookalike domains faster than blacklists can be updated.
- **The Solution:** A hybrid, feature-based detection engine that extracts 20 lexical and structural signals directly from a URL (domain entropy, brand typosquatting distance, suspicious TLDs, IP-literal hosts, sensitive keywords, etc.) and feeds them into a RandomForest classifier that outputs a phishing probability — with zero dependency on blacklists, so it can flag zero-day phishing domains instantly.
- **Business Impact:** Enables sub-10ms, offline URL scoring suitable for embedding in browser extensions, email gateways, or SMS-link scanners — closing the detection gap that blacklist-only systems leave open.

## 2. Technical Architecture & Stack

- **Frontend:** Static HTML/CSS/JS demo scanner (`static/index.html`) — no framework dependency
- **Backend/API:** Python 3, Flask (`app.py`)
- **ML:** scikit-learn RandomForestClassifier, trained on engineered URL features
- **Database & Caching:** None in V1 (stateless scoring); logging store is a natural Phase 2 addition
- **Infrastructure & Deployment:** Runs anywhere with Python 3.10+; containerizable with Docker
- **System Flow:** `URL input` → `feature extractor (features.py)` → `RandomForest model (model/phishing_model.joblib)` → `probability + explanation` → `JSON API response` → `demo UI`

## 3. Key Deliverables & Features

- **Feature Extractor (`features.py`):** Pulls 20 signals from a raw URL string alone (no network fetch required) — entropy, brand-distance (Levenshtein), suspicious TLD/keyword detection, IP-literal hosts, etc.
- **Trained Classifier (`train.py` + `model/phishing_model.joblib`):** RandomForest model with balanced class weights and feature-importance reporting for explainability.
- **Scoring API (`app.py`):** `POST /api/check` returns a verdict, phishing probability, human-readable reasons, and the full feature vector for auditability.
- **Demo Scanner UI (`static/index.html`):** Terminal-styled single-page scanner with example URLs and a live confidence meter.

## 4. Implementation Highlights & Performance

- **Security & Compliance:** All scoring is done client-server side without ever rendering or executing the target page — no risk of the scanning tool itself triggering a payload.
- **Performance Metrics:** Feature extraction + inference completes in low single-digit milliseconds per URL on CPU; no external API calls in the hot path.
- **Quality Assurance:** Model evaluated via train/test split with precision/recall/F1 and ROC-AUC reported in `train.py` output; feature importances printed for sanity-checking that the model relies on meaningful signals (HTTPS presence, suspicious TLD, hyphen count ranked highest).
- **Explainability:** Every phishing verdict includes plain-language reasons (e.g. "Domain uses a suspicious TLD", "Brand name appears in subdomain") rather than a black-box score alone.

## 5. Challenges & Strategic Roadmap

- **Primary Technical Hurdle:** No live network access during development meant real PhishTank/OpenPhish/UCI feeds could not be pulled for training.
- **Resolution:** Built `generate_dataset.py`, which procedurally generates a labeled corpus using the same documented phishing URL patterns (typosquatting, brand-in-subdomain, IP hosts, shorteners, hyphen-spam, suspicious TLDs) real attackers use, so the training pipeline is fully ready to be pointed at live data.
- **Next Steps (Phase 2):**
  - Swap synthetic data for live PhishTank/OpenPhish CSV feeds + the UCI Phishing Websites Dataset for real-world generalization
  - Add a content-analysis stage (fetch page HTML, check for login forms, favicon hash mismatch, brand logo similarity) for cases where the URL alone is ambiguous
  - Add a WHOIS/domain-age lookup as a strong secondary signal for zero-day domains
  - Package as a browser extension (Manifest V3) for real-time protection while browsing

---

## Setup & Usage

```bash
pip install -r requirements.txt

# 1. Generate the training dataset (synthetic; swap for live feeds in production)
python3 generate_dataset.py

# 2. Train the model
python3 train.py

# 3. Run the API + demo UI
python3 app.py
# Visit http://localhost:5050
```

### API Example

```bash
curl -X POST http://localhost:5050/api/check \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-secure-login.verify-account.xyz/signin"}'
```

```json
{
  "verdict": "phishing",
  "phishing_probability": 0.9967,
  "reasons": [
    "Domain uses a top-level domain commonly abused for phishing (.xyz, .top, .tk, etc.)",
    "A brand name appears in the subdomain rather than the actual domain",
    "Domain contains an unusually high number of hyphens",
    "URL contains sensitive keywords (login, verify, secure, account, etc.)",
    "Connection is not using HTTPS"
  ]
}
```

### Project Structure

```
phishing-detector/
├── app.py                  # Flask API + demo server
├── features.py              # URL feature extraction (20 signals)
├── generate_dataset.py      # Synthetic dataset generator
├── train.py                 # Model training + evaluation
├── requirements.txt
├── data/
│   └── urls.csv              # Labeled training data
├── model/
│   └── phishing_model.joblib # Trained RandomForest
└── static/
    └── index.html            # Demo scanner UI
```

**Note:** For production deployment, retrain `train.py` on real PhishTank/OpenPhish/UCI data rather than the bundled synthetic dataset — synthetic patterns are clean-cut and will overstate accuracy on live traffic.
