"""
ioc.py
──────
Indicator-of-Compromise (IOC) extraction and VirusTotal enrichment.

extract_ioc()              — pull the first IP, hash, or domain from text
fetch_virustotal_context() — query VT and return a summary dict (or None)
"""

import re

import requests

from config import VT_API_KEY, VT_HEADERS


# ── IOC patterns (checked in priority order) ──────────────────────────────────
_IOC_PATTERNS = [
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",          # IPv4
    r"\b[a-fA-F0-9]{64}\b",                   # SHA-256
    r"\b[a-fA-F0-9]{40}\b",                   # SHA-1
    r"\b[a-fA-F0-9]{32}\b",                   # MD5
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",  # domain
]


def extract_ioc(text: str) -> str | None:
    """Return the first IOC found in `text`, or None."""
    for pattern in _IOC_PATTERNS:
        m = re.search(pattern, text)
        if m:
            return m.group(0)
    return None


def fetch_virustotal_context(text: str) -> dict | None:
    """
    Extract an IOC from `text` and look it up on VirusTotal.
    Returns a dict with detection stats, or None if VT is unconfigured,
    no IOC was found, or the request fails.
    """
    if not VT_API_KEY:
        return None

    ioc = extract_ioc(text)
    if not ioc:
        return None

    # Route to the correct VT endpoint based on IOC type
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif re.match(r"^[a-fA-F0-9]{32,64}$", ioc):
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"

    try:
        r = requests.get(url, headers=VT_HEADERS, timeout=10)
        if r.status_code != 200:
            return None
        data  = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "ioc":        ioc,
            "malicious":  stats.get("malicious",  0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless",   0),
            "undetected": stats.get("undetected", 0),
            "reputation": data.get("reputation",  0),
            "tags":       data.get("tags",        []),
        }
    except Exception as e:
        print(f"VirusTotal lookup failed: {e}")
        return None