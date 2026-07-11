"""
sources/urlhaus.py
──────────────────
Fetches recent malware distribution URLs from URLhaus (abuse.ch).

URLhaus tracks URLs actively serving malware payloads. Data includes
the URL itself, delivery method (e.g. malware_download), and associated
malware tags. Updated very frequently — good for near-real-time signal.

API docs: https://urlhaus.abuse.ch/api/
Free key: https://auth.abuse.ch/ (same account as ThreatFox/MalwareBazaar)

.env variable needed:
    ABUSECH_API_KEY=your_key_here
"""

import os
import requests

_API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


def _get_key() -> str | None:
    return os.environ.get("ABUSECH_API_KEY")


def fetch_urlhaus_urls(limit: int = 20) -> list[dict]:
    """
    Fetch the most recently added malware URLs from URLhaus.

    Returns a list of dicts, each with:
        text       — combined text string for the classifier
        source_id  — unique ID for deduplication (e.g. "urlhaus:abc123")
        meta       — raw fields for logging/display
    """
    key = _get_key()
    if not key:
        print("ABUSECH_API_KEY not set — skipping URLhaus fetch.")
        return []

    try:
        r = requests.post(
            _API_URL,
            headers={"Auth-Key": key},
            data={"limit": limit},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print(f"URLhaus fetch error: {e}")
        return []

    if data.get("query_status") != "ok" or not data.get("urls"):
        return []

    results = []
    for item in data["urls"][:limit]:
        url        = item.get("url", "")
        threat     = item.get("threat", "")  # e.g. "malware_download"
        url_status = item.get("url_status", "")  # "online" / "offline"
        tags       = " ".join(item.get("tags") or [])
        host       = item.get("host", "")

        # Build descriptive text — keeping the domain context helps the classifier
        text = (
            f"Malware distribution URL detected: {url}. "
            f"Host: {host}. "
            f"Threat type: {threat.replace('_', ' ')}. "
            f"Status: {url_status}. "
            f"Tags: {tags}."
        ).strip()

        results.append({
            "text":      text,
            "source_id": f"urlhaus:{item.get('id', url)}",
            "meta": {
                "url":        url,
                "host":       host,
                "threat":     threat,
                "status":     url_status,
                "tags":       tags,
                "date_added": item.get("date_added"),
            },
        })

    return results