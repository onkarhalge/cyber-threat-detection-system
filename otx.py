"""
otx.py
──────
AlienVault OTX pulse fetching.
Returns a list of raw pulse dicts — classification is done in the route.
"""

import requests

from config import OTX_API_KEY

_OTX_BASE = "https://otx.alienvault.com/api/v1/pulses/subscribed"


def fetch_otx_pulses(limit: int = 10) -> list[dict]:
    """
    Fetch the most recent `limit` subscribed OTX pulses.
    Returns an empty list if the key is not set or the request fails.
    """
    if not OTX_API_KEY:
        print("OTX_API_KEY is not set — skipping OTX fetch.")
        return []

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(
            _OTX_BASE,
            params={"limit": limit, "page": 1},
            headers=headers,
            timeout=15,
        )
        r.raise_for_status()
        return r.json().get("results", [])
    except Exception as e:
        print(f"OTX fetch error: {e}")
        return []