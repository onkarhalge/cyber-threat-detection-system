"""
routes/api.py
─────────────
JSON API endpoints:
    POST /predict               — classify a single piece of text
    POST /fetch                 — pull and classify latest OTX pulses
    POST /fetch/threatfox       — pull and classify ThreatFox IOCs
    POST /fetch/urlhaus         — pull and classify URLhaus malware URLs
    POST /fetch/malwarebazaar   — pull and classify MalwareBazaar samples
    POST /fetch-all             — fetch from all sources in one call
    GET  /api/insights          — dashboard chart data
    GET  /api/emerging-threats  — LDA topic modelling data
"""

import sqlite3

from flask import Blueprint, jsonify, request

from classifier              import process_text
from db                      import get_insights_data, pulse_exists, save_threat, source_id_exists
from lda_engine              import run_emerging_analysis
from otx                     import fetch_otx_pulses
from sources.threatfox       import fetch_threatfox_iocs
from sources.urlhaus         import fetch_urlhaus_urls
from sources.malwarebazaar   import fetch_malwarebazaar_samples

api_bp = Blueprint("api", __name__)


# ── /predict ──────────────────────────────────────────────────────────────────

@api_bp.route("/predict", methods=["POST"])
def predict():
    text = request.form.get("text", "").strip()
    if not text:
        return jsonify({"error": "No text provided"}), 400

    result = process_text(text)
    if not result:
        return jsonify({"relevant": False, "message": "No threat indicators detected"})

    try:
        save_threat(result)
    except sqlite3.OperationalError as e:
        print(f"DB write failed in /predict: {e}")

    return jsonify(result)


# ── /fetch (OTX) ──────────────────────────────────────────────────────────────

@api_bp.route("/fetch", methods=["POST"])
def fetch():
    pulses = fetch_otx_pulses(limit=10)
    count  = 0

    for pulse in pulses:
        pid  = pulse.get("id")
        text = pulse.get("name", "") + "\n" + pulse.get("description", "")

        if pulse_exists(pid):
            continue

        result = process_text(text, pulse_id=pid)
        if not result:
            continue

        try:
            save_threat(result)
            count += 1
        except sqlite3.OperationalError as e:
            print(f"DB write failed in /fetch (OTX): {e}")

    return jsonify({"source": "OTX", "message": f"Processed {count} new pulses"})


# ── /fetch/threatfox ──────────────────────────────────────────────────────────

@api_bp.route("/fetch/threatfox", methods=["POST"])
def fetch_threatfox():
    days  = int(request.form.get("days", 1))
    limit = int(request.form.get("limit", 20))
    items = fetch_threatfox_iocs(days=days, limit=limit)
    count = 0

    for item in items:
        sid = item["source_id"]
        if source_id_exists(sid):
            continue

        result = process_text(item["text"], pulse_id=sid)
        if not result:
            continue

        try:
            save_threat(result)
            count += 1
        except sqlite3.OperationalError as e:
            print(f"DB write failed in /fetch/threatfox: {e}")

    return jsonify({"source": "ThreatFox", "message": f"Processed {count} new IOCs"})


# ── /fetch/urlhaus ────────────────────────────────────────────────────────────

@api_bp.route("/fetch/urlhaus", methods=["POST"])
def fetch_urlhaus():
    limit = int(request.form.get("limit", 20))
    items = fetch_urlhaus_urls(limit=limit)
    count = 0

    for item in items:
        sid = item["source_id"]
        if source_id_exists(sid):
            continue

        result = process_text(item["text"], pulse_id=sid)
        if not result:
            continue

        try:
            save_threat(result)
            count += 1
        except sqlite3.OperationalError as e:
            print(f"DB write failed in /fetch/urlhaus: {e}")

    return jsonify({"source": "URLhaus", "message": f"Processed {count} new URLs"})


# ── /fetch/malwarebazaar ──────────────────────────────────────────────────────

@api_bp.route("/fetch/malwarebazaar", methods=["POST"])
def fetch_malwarebazaar():
    limit = int(request.form.get("limit", 20))
    items = fetch_malwarebazaar_samples(limit=limit)
    count = 0

    for item in items:
        sid = item["source_id"]
        if source_id_exists(sid):
            continue

        result = process_text(item["text"], pulse_id=sid)
        if not result:
            continue

        try:
            save_threat(result)
            count += 1
        except sqlite3.OperationalError as e:
            print(f"DB write failed in /fetch/malwarebazaar: {e}")

    return jsonify({"source": "MalwareBazaar", "message": f"Processed {count} new samples"})


# ── /fetch-all ────────────────────────────────────────────────────────────────

@api_bp.route("/fetch-all", methods=["POST"])
def fetch_all():
    """Trigger all sources in sequence and return a combined summary."""
    summary = {}

    # OTX
    otx_count = 0
    for pulse in fetch_otx_pulses(limit=10):
        pid  = pulse.get("id")
        text = pulse.get("name", "") + "\n" + pulse.get("description", "")
        if pulse_exists(pid):
            continue
        result = process_text(text, pulse_id=pid)
        if result:
            try:
                save_threat(result)
                otx_count += 1
            except sqlite3.OperationalError:
                pass
    summary["OTX"] = otx_count

    # ThreatFox
    tf_count = 0
    for item in fetch_threatfox_iocs(days=1, limit=20):
        if source_id_exists(item["source_id"]):
            continue
        result = process_text(item["text"], pulse_id=item["source_id"])
        if result:
            try:
                save_threat(result)
                tf_count += 1
            except sqlite3.OperationalError:
                pass
    summary["ThreatFox"] = tf_count

    # URLhaus
    uh_count = 0
    for item in fetch_urlhaus_urls(limit=20):
        if source_id_exists(item["source_id"]):
            continue
        result = process_text(item["text"], pulse_id=item["source_id"])
        if result:
            try:
                save_threat(result)
                uh_count += 1
            except sqlite3.OperationalError:
                pass
    summary["URLhaus"] = uh_count

    # MalwareBazaar
    mb_count = 0
    for item in fetch_malwarebazaar_samples(limit=20):
        if source_id_exists(item["source_id"]):
            continue
        result = process_text(item["text"], pulse_id=item["source_id"])
        if result:
            try:
                save_threat(result)
                mb_count += 1
            except sqlite3.OperationalError:
                pass
    summary["MalwareBazaar"] = mb_count

    total = sum(summary.values())
    return jsonify({
        "total": total,
        "breakdown": summary,
        "message": f"Fetched {total} new threats across all sources",
    })


# ── /api/insights ─────────────────────────────────────────────────────────────

@api_bp.route("/api/insights")
def get_insights():
    data = get_insights_data(
        time_filter   = request.args.get("time",   "all"),
        threat_filter = request.args.get("threat", "all"),
        source_filter = request.args.get("source", "all"),
    )
    return jsonify(data)


# ── /api/emerging-threats ─────────────────────────────────────────────────────

@api_bp.route("/api/emerging-threats")
def api_emerging_threats():
    try:
        num_topics = int(request.args.get("topics", 5))
    except ValueError:
        num_topics = 5
    try:
        weeks = int(request.args.get("weeks", 8))
    except ValueError:
        weeks = 8

    return jsonify(run_emerging_analysis(num_topics=num_topics, weeks=weeks))