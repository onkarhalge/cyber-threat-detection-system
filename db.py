"""
db.py
─────
SQLite connection helpers and every database query in one place.
Keeps SQL out of route handlers and makes it easy to swap backends later.

Column order for the `threats` table (used by positional tuple indexing
in Jinja templates):
    [0] id  [1] pulse_id  [2] original_text  [3] clean_text
    [4] relevant  [5] bin_confidence  [6] category  [7] mc_confidence
    [8] analyst_summary  [9] timestamp
"""

import sqlite3

from config import ALL_CATEGORIES


# ── Connection ────────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    """Return a WAL-mode SQLite connection. Use as a context manager:
        with get_db() as conn:
            ...
    The `with` block auto-commits on success and rolls back on error.
    """
    conn = sqlite3.connect("threats.db", timeout=30)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    return conn


# ── Schema ────────────────────────────────────────────────────────────────────

def init_db() -> None:
    """Create the threats table if it doesn't exist yet (idempotent)."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                pulse_id         TEXT,
                original_text    TEXT,
                clean_text       TEXT,
                relevant         INTEGER,
                bin_confidence   REAL,
                category         TEXT,
                mc_confidence    REAL,
                analyst_summary  TEXT,
                timestamp        DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


# ── Read helpers ──────────────────────────────────────────────────────────────

def get_all_threats(limit: int = 300) -> list:
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?", (limit,))
        return c.fetchall()


def get_threat_by_id(threat_id: int):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM threats WHERE id = ?", (threat_id,))
        return c.fetchone()


def get_categories() -> list[str]:
    """All categories: static list merged with anything already in the DB."""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT DISTINCT category FROM threats WHERE category IS NOT NULL")
        db_cats = [r[0] for r in c.fetchall()]
    return sorted(set(ALL_CATEGORIES) | set(db_cats))


def search_threats(query: str = "", category: str = "All", limit: int = 100) -> list:
    sql    = "SELECT * FROM threats WHERE 1=1"
    params = []

    if query:
        sql += " AND (original_text LIKE ? OR analyst_summary LIKE ?)"
        like = f"%{query}%"
        params.extend([like, like])

    if category and category != "All":
        sql += " AND category = ?"
        params.append(category)

    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with get_db() as conn:
        c = conn.cursor()
        c.execute(sql, params)
        return c.fetchall()


def pulse_exists(pulse_id: str) -> bool:
    """True if a pulse with this OTX id has already been stored."""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM threats WHERE pulse_id = ?", (pulse_id,))
        return c.fetchone() is not None


def get_relevant_count() -> int:
    """Count of all relevant (threat) records — used by LDA availability check."""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM threats WHERE relevant = 1")
        return c.fetchone()[0] or 0


def get_lda_training_rows() -> list:
    """Cleaned text + timestamp for every relevant record (LDA training input)."""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT clean_text, timestamp FROM threats
            WHERE relevant = 1 AND clean_text IS NOT NULL AND clean_text != ''
            ORDER BY timestamp ASC
        """)
        return c.fetchall()


# ── Write helpers ─────────────────────────────────────────────────────────────

def save_threat(result: dict) -> None:
    """Insert one classified threat record. `result` is the dict from process_text()."""
    with get_db() as conn:
        conn.execute("""
            INSERT INTO threats
                (pulse_id, original_text, clean_text, relevant,
                 bin_confidence, category, mc_confidence, analyst_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result["pulse_id"],       result["original_text"],
            result["clean_text"],     result["relevant"],
            result["bin_confidence"], result["category"],
            result["mc_confidence"],  result["analyst_summary"],
        ))
        conn.commit()


# ── Insights queries ──────────────────────────────────────────────────────────

def get_insights_data(time_filter="all", threat_filter="all", source_filter="all") -> dict:
    """Run all dashboard queries in a single connection and return a dict."""
    with get_db() as conn:
        c = conn.cursor()

        where  = ["relevant = 1"]
        params = []

        if time_filter != "all":
            days = {"7d": 7, "30d": 30, "90d": 90}.get(time_filter, 7)
            where.append(f"timestamp >= datetime('now', '-{days} days')")

        if threat_filter != "all":
            where.append("category = ?")
            params.append(threat_filter)

        if source_filter == "otx":
            where.append("pulse_id IS NOT NULL")
        elif source_filter == "manual":
            where.append("pulse_id IS NULL")

        w = " AND ".join(where)

        # Metrics
        c.execute(f"SELECT COUNT(*), AVG(mc_confidence)*100 FROM threats WHERE {w}", params)
        total, avg_conf = c.fetchone()
        total    = total    or 0
        avg_conf = round(avg_conf or 0, 1)

        c.execute(f"SELECT COUNT(DISTINCT category) FROM threats WHERE category IS NOT NULL AND {w}", params)
        cats_count = c.fetchone()[0] or 0

        # Trends
        c.execute(
            f"SELECT date(timestamp), COUNT(*) FROM threats WHERE {w} "
            f"GROUP BY date(timestamp) ORDER BY date(timestamp)",
            params,
        )
        rows   = c.fetchall()
        trends = {"labels": [r[0] for r in rows], "data": [r[1] for r in rows]}

        # Confidence distribution buckets
        c.execute(f"SELECT mc_confidence FROM threats WHERE {w}", params)
        dist = [0, 0, 0, 0, 0]
        for (v,) in c.fetchall():
            v = v or 0
            if   v <= 0.2: dist[0] += 1
            elif v <= 0.4: dist[1] += 1
            elif v <= 0.6: dist[2] += 1
            elif v <= 0.8: dist[3] += 1
            else:          dist[4] += 1

        # Source distribution
        c.execute(
            f"""
            SELECT CASE WHEN pulse_id IS NOT NULL THEN 'OTX' ELSE 'Manual' END, COUNT(*)
            FROM threats WHERE {w}
            GROUP BY CASE WHEN pulse_id IS NOT NULL THEN 'OTX' ELSE 'Manual' END
            """,
            params,
        )
        rows        = c.fetchall()
        source_dist = {"labels": [r[0] for r in rows], "data": [r[1] for r in rows]}

        # Top categories
        c.execute(
            f"""
            SELECT category, COUNT(*) FROM threats
            WHERE category IS NOT NULL AND {w}
            GROUP BY category ORDER BY COUNT(*) DESC LIMIT 6
            """,
            params,
        )
        rows     = c.fetchall()
        top_cats = {"labels": [r[0] for r in rows], "data": [r[1] for r in rows]}

        # Timeline scatter
        c.execute(
            f"SELECT timestamp, mc_confidence FROM threats WHERE {w} ORDER BY timestamp",
            params,
        )
        timeline = [{"x": r[0], "y": round((r[1] or 0) * 100, 1)} for r in c.fetchall()]

        # Category comparison table
        c.execute(
            f"""
            SELECT category, COUNT(*), AVG(mc_confidence)*100
            FROM threats WHERE category IS NOT NULL AND {w}
            GROUP BY category ORDER BY COUNT(*) DESC
            """,
            params,
        )
        comparison = []
        for cat, tot, avg in c.fetchall():
            status = "critical" if tot >= 10 else ("warning" if tot >= 5 else "active")
            comparison.append({
                "category":      cat,
                "total":         tot,
                "avgConfidence": round(avg or 0, 1),
                "trend":         0,
                "status":        status,
            })

    return {
        "metrics": {
            "total":         total,
            "active":        total,
            "categories":    cats_count,
            "avgConfidence": avg_conf,
        },
        "trends":                 trends,
        "confidenceDistribution": dist,
        "sourceDistribution":     source_dist,
        "topCategories":          top_cats,
        "timeline":               timeline,
        "comparison":             comparison,
    }


def source_id_exists(source_id: str) -> bool:
    """True if a record with this source_id was already stored.
    Used by ThreatFox/URLhaus/MalwareBazaar to skip duplicates.
    source_id is stored in the pulse_id column (same dedup pattern as OTX).
    """
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM threats WHERE pulse_id = ?", (source_id,))
        return c.fetchone() is not None


def source_id_exists(source_id: str) -> bool:
    """True if a record with this source_id was already stored.
    Used by ThreatFox/URLhaus/MalwareBazaar to skip duplicates.
    """
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM threats WHERE pulse_id = ?", (source_id,))
        return c.fetchone() is not None