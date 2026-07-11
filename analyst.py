"""
analyst.py
──────────
Builds the human-readable analyst summary attached to every threat record.
Kept separate so the intent/mitigation maps are easy to extend without
touching routing or ML code.
"""


# ── Intent and mitigation reference maps ──────────────────────────────────────

_INTENT_MAP = {
    "Phishing":    "Likely objective is credential theft via social engineering or spoofed delivery.",
    "Malware":     "Likely objective is payload execution, persistence, and host compromise.",
    "Ransomware":  "Likely objective is encryption, extortion, and operational disruption.",
    "DDoS Attack": "Likely objective is service disruption and resource exhaustion.",
    "Botnets":     "Likely objective is command-and-control coordination and distributed abuse.",
    "Spam":        "Likely objective is unsolicited distribution, lures, or payload delivery.",
}

_MITIGATION_MAP = {
    "Phishing":    "Block sender/domain, inspect URLs, and enforce MFA for exposed accounts.",
    "Malware":     "Isolate affected hosts, scan payloads, and block known indicators.",
    "Ransomware":  "Isolate infected systems, disable lateral movement, and validate backups.",
    "DDoS Attack": "Apply rate limiting, enable WAF/CDN protection, and monitor ingress spikes.",
    "Botnets":     "Block C2 traffic, isolate infected nodes, and rotate exposed credentials.",
    "Spam":        "Quarantine suspicious messages and strengthen mail filtering policies.",
}


# ── Public function ───────────────────────────────────────────────────────────

def build_threat_summary(
    original_text: str,
    cleaned: str,
    category: str,
    confidence: float,
    vt_data: dict | None = None,
) -> str:
    """
    Compose a bullet-point analyst summary.

    Parameters
    ----------
    original_text : raw input text
    cleaned       : lemmatised text (not currently used in output, reserved for future use)
    category      : threat category label from DistilBERT
    confidence    : mc_confidence score (0–1)
    vt_data       : optional VirusTotal enrichment dict from ioc.fetch_virustotal_context()
    """
    lines = [f"Threat classified as {category} with {confidence * 100:.1f}% confidence."]

    if vt_data:
        lines.append(
            f"VirusTotal IOC match: {vt_data['ioc']} "
            f"({vt_data['malicious']} malicious / {vt_data['suspicious']} suspicious detections)."
        )
        if vt_data.get("tags"):
            lines.append(f"Associated tags: {', '.join(vt_data['tags'][:4])}.")

    lines.append(_INTENT_MAP.get(category,    "Potential malicious activity detected."))
    lines.append(_MITIGATION_MAP.get(category, "Investigate and contain affected assets."))

    return "\n• " + "\n• ".join(lines)