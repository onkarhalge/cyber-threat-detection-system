"""
run.py
──────
Single entry point — the only file you need to run:

    python run.py          (development)
    flask --app run run    (also works)
    gunicorn run:app       (production)

Startup order:
    1. Load .env (if present) via python-dotenv
    2. Import config  → sets up API keys and constants
    3. Import db      → ensures the threats table exists
    4. Import models  → loads spaCy / SVM / DistilBERT (takes a few seconds)
    5. Register blueprints (pages + api)
    6. Serve
"""

import os
import warnings

warnings.filterwarnings("ignore")

# ── 1. Load environment variables from .env (dev only) ────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv is optional; on prod the host sets env vars directly

# ── 2. Create the Flask app ───────────────────────────────────────────────────
from flask import Flask

app = Flask(__name__, template_folder="templates", static_folder="static")

# ── 3. Initialise the database ────────────────────────────────────────────────
from db import init_db
init_db()

# ── 4. Load ML models (imported for side-effects; models are module singletons)
import models  # noqa: F401  — triggers the print("Loading…") block

# ── 5. Register route blueprints ─────────────────────────────────────────────
from routes.pages import pages_bp
from routes.api   import api_bp

app.register_blueprint(pages_bp)
app.register_blueprint(api_bp)

# ── 6. Run ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(debug=debug, host="0.0.0.0", port=port, threaded=True)