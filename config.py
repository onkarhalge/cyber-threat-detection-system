"""
config.py
─────────
Central place for every constant and environment variable.
Import from here instead of using os.environ scattered across files.

Set values in a .env file locally:
    OTX_API_KEY=your_key
    VT_API_KEY=your_key

On a deployment platform (Render, Railway, Fly.io) set them as env vars
in the dashboard — no .env file needed there.
"""

import os

# ── API Keys ──────────────────────────────────────────────────────────────────
# Keys are loaded from environment only — no hardcoded fallbacks.
# Rotate your OTX and VT keys if they were ever committed in source.
OTX_API_KEY: str | None = os.environ.get("OTX_API_KEY")
VT_API_KEY:  str | None = os.environ.get("VT_API_KEY")
VT_HEADERS = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}

# ── Model paths ───────────────────────────────────────────────────────────────
MODELS_DIR            = os.environ.get("MODELS_DIR", "models")
BINARY_VECTORIZER_PKL = os.path.join(MODELS_DIR, "binary_vectorizer.pkl")
SVM_MODEL_PKL         = os.path.join(MODELS_DIR, "svm_binary_relevant.pkl")
DISTILBERT_DIR        = os.path.join(MODELS_DIR, "distilbert_cti_final")

# ── Threat categories ─────────────────────────────────────────────────────────
CLASS_NAMES = [
    "Irrelevant",
    "DDoS Attack",
    "Botnets",
    "Malware",
    "Phishing",
    "Spam",
    "Ransomware",
]

# Shown in the UI — excludes "Irrelevant"
ALL_CATEGORIES = CLASS_NAMES[1:]

# Keywords used by is_meaningful_threat_text() to pre-filter noise
CTI_KEYWORDS = {
    "ransomware", "malware", "phishing", "ddos", "botnet",
    "trojan", "virus", "exploit", "attack", "breach",
    "leak", "encrypted", "bitcoin", "credential",
    "payload", "command", "control", "spam",
}

# ── LDA / Emerging threats ────────────────────────────────────────────────────
MIN_LDA_DOCS = 5   # minimum threat records needed to train a topic model