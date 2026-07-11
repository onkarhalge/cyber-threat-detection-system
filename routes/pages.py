"""
routes/pages.py
───────────────
Page routes — every endpoint that renders an HTML template.
Registered on the Flask app in run.py via blueprint.
"""

from flask import Blueprint, render_template, request

from config import ALL_CATEGORIES
from db     import get_categories, get_all_threats, search_threats

pages_bp = Blueprint("pages", __name__)


# ── Static / simple pages ─────────────────────────────────────────────────────

@pages_bp.route("/")
def index():
    return render_template("about.html", active_page="about")


@pages_bp.route("/threats")
def threats():
    return render_template("threats.html", active_page="threats")


@pages_bp.route("/insights")
def insights():
    return render_template(
        "insights.html",
        active_page    = "insights",
        all_categories = get_categories(),
    )


@pages_bp.route("/emerging-threats")
def emerging_threats():
    return render_template("emerging_threats.html", active_page="emerging")


# ── Analyze / search pages ────────────────────────────────────────────────────

@pages_bp.route("/analyze")
def analyze():
    rows = get_all_threats()
    cats = get_categories()
    return render_template(
        "analyze.html",
        active_page       = "analysis",
        threats           = rows,
        categories        = ["All"] + cats,
        all_categories    = cats,
        search_query      = "",
        selected_category = "All",
    )


@pages_bp.route("/search")
def search():
    query    = request.args.get("query",    "").strip()
    category = request.args.get("category", "All")
    rows     = search_threats(query, category)
    cats     = get_categories()
    return render_template(
        "analyze.html",
        active_page       = "analysis",
        threats           = rows,
        categories        = ["All"] + cats,
        all_categories    = cats,
        search_query      = query,
        selected_category = category,
    )


# ── Threat detail page ────────────────────────────────────────────────────────

@pages_bp.route("/threat/<int:threat_id>")
def threat_detail(threat_id: int):
    from db import get_threat_by_id  # local import avoids circular at module level
    threat = get_threat_by_id(threat_id)
    if not threat:
        return "Threat not found", 404
    return render_template(
        "threat_detail.html",
        threat         = threat,
        all_categories = ALL_CATEGORIES,
        active_page    = "analysis",
    )