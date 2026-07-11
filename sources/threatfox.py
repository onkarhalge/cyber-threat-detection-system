"""
sources/threatfox.py
────────────────────
Fetches recent IOCs from ThreatFox (abuse.ch).

ThreatFox tracks malware-associated indicators: C2 servers, botnet
controllers, phishing domains, and similar. Each IOC comes with a
malware family name and a confidence level.

API docs: https://threatfox.abuse.ch/api/
Free key: https://auth.abuse.ch/

.env variable needed:
    ABUSECH_API_KEY=your_key_here
"""

import os
import requests

_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


def _get_key() -> str | None:
    return os.environ.get("ABUSECH_API_KEY")


def fetch_threatfox_iocs(days: int = 1, limit: int = 20) -> list[dict]:
    """
    Fetch recent IOCs from ThreatFox.

    Returns a list of dicts, each with:
        text       — combined text string for the classifier
        source_id  — unique ID for deduplication (e.g. "threatfox:1234")
        meta       — raw fields from ThreatFox for logging/display
    """
    key = _get_key()
    if not key:
        print("ABUSECH_API_KEY not set — skipping ThreatFox fetch.")
        return []

    try:
        r = requests.post(
            _API_URL,
            headers={"Auth-Key": key},
            json={"query": "get_iocs", "days": days},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print(f"ThreatFox fetch error: {e}")
        return []

    if data.get("query_status") != "ok" or not data.get("data"):
        return []

    results = []
    for item in data["data"][:limit]:
        ioc              = item.get("ioc", "")
        threat_type_desc = item.get("threat_type_desc", "")
        malware_name     = item.get("malware_printable", "")
        tags             = " ".join(item.get("tags") or [])
        confidence       = item.get("confidence_level", 0)

        # Build a descriptive text the classifier can understand
        text = (
            f"ThreatFox IOC: {ioc}. "
            f"Threat type: {threat_type_desc}. "
            f"Malware family: {malware_name}. "
            f"Tags: {tags}. "
            f"Confidence level: {confidence}%."
        ).strip()

        results.append({
            "text":      text,
            "source_id": f"threatfox:{item.get('id', ioc)}",
            "meta": {
                "ioc":        ioc,
                "threat":     threat_type_desc,
                "malware":    malware_name,
                "confidence": confidence,
                "tags":       tags,
                "first_seen": item.get("first_seen"),
            },
        })

    return results