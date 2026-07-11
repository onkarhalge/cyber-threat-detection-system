"""
lda_engine.py
─────────────
Emerging threat detection via LDA topic modelling.

Tracks how topic proportions shift across ISO weeks to surface
attack themes the fixed 6-category classifier alone misses —
e.g. zero-day campaigns, new TTP clusters.

Uses scikit-learn (CountVectorizer + LatentDirichletAllocation) rather
than gensim: sklearn ships universal wheels, gensim currently requires
compiling Cython extensions that break on CPython 3.13+.

Public API
──────────
run_emerging_analysis(num_topics, weeks)
    → dict  (ready to jsonify)
"""

import datetime
from collections import defaultdict

from sklearn.decomposition import LatentDirichletAllocation
from sklearn.feature_extraction.text import CountVectorizer

from config import MIN_LDA_DOCS
from db     import get_lda_training_rows, get_relevant_count


# ── Week bucket helper ────────────────────────────────────────────────────────

def _week_bucket(ts) -> str | None:
    """Convert a SQLite timestamp string to an ISO-week label like '2025-W12'."""
    if not ts:
        return None
    try:
        ts_str = str(ts).split(".")[0]
        d = datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        try:
            d = datetime.datetime.strptime(str(ts)[:10], "%Y-%m-%d")
        except ValueError:
            return None
    iso_year, iso_week, _ = d.isocalendar()
    return f"{iso_year}-W{iso_week:02d}"


# ── LDA training ──────────────────────────────────────────────────────────────

def _train_lda(num_topics: int = 5):
    """
    Train an LDA model over all currently classified threat text.
    Returns (lda, vectorizer, doc_topic, rows) or None if not enough data.
    """
    rows = get_lda_training_rows()
    if len(rows) < MIN_LDA_DOCS:
        return None

    texts = [r[0] for r in rows]
    vectorizer = CountVectorizer(min_df=2, max_df=0.65)
    try:
        dtm = vectorizer.fit_transform(texts)
    except ValueError:
        return None  # empty vocabulary after filtering

    if dtm.shape[1] < 3:
        return None

    lda = LatentDirichletAllocation(
        n_components=num_topics,
        max_iter=100,
        learning_method="batch",
        random_state=42,
    )
    doc_topic = lda.fit_transform(dtm)
    return lda, vectorizer, doc_topic, rows


# ── Topic keyword extraction ──────────────────────────────────────────────────

def _get_topic_keywords(lda, vectorizer, num_topics: int, topn: int = 8) -> list[dict]:
    """Top weighted keywords per topic plus a short human-readable label."""
    feature_names = vectorizer.get_feature_names_out()
    topics = []
    for i in range(num_topics):
        component = lda.components_[i]
        total     = component.sum() or 1.0
        top_idx   = component.argsort()[::-1][:topn]
        terms     = [(feature_names[idx], component[idx] / total) for idx in top_idx]
        keywords  = [{"word": w, "weight": round(float(wt), 4)} for w, wt in terms]
        label     = " / ".join(w for w, _ in terms[:3]).title() if terms else f"Topic {i + 1}"
        topics.append({"id": i, "label": label, "keywords": keywords})
    return topics


# ── Topics over time ──────────────────────────────────────────────────────────

def _get_topics_over_time(doc_topic, rows: list, num_topics: int, weeks: int = 8) -> dict:
    """Average topic-probability per ISO week across the most recent N weeks."""
    week_sums   = defaultdict(lambda: [0.0] * num_topics)
    week_counts = defaultdict(int)

    for (clean, ts), probs in zip(rows, doc_topic):
        wk = _week_bucket(ts)
        if not wk:
            continue
        for topic_id in range(num_topics):
            week_sums[wk][topic_id] += probs[topic_id]
        week_counts[wk] += 1

    sorted_weeks = sorted(week_sums.keys())[-weeks:]
    series = []
    for i in range(num_topics):
        data = [
            round((week_sums[wk][i] / (week_counts.get(wk) or 1)) * 100, 2)
            for wk in sorted_weeks
        ]
        series.append({"topic": i, "data": data})

    return {"labels": sorted_weeks, "series": series}


# ── Emerging signal detection ─────────────────────────────────────────────────

def _detect_emerging_signal(topics_over_time: dict, topic_meta: list) -> dict:
    """Plain-English callout for the strongest topic shift."""
    labels = topics_over_time["labels"]
    series = topics_over_time["series"]

    if len(labels) < 2:
        return {
            "text": (
                "Not enough historical data spread across weeks yet to detect a trend. "
                "Keep analyzing or fetching threats and check back once activity spans a few weeks."
            ),
            "direction": "neutral",
            "topic": None,
        }

    best_topic, best_delta = None, 0
    for s in series:
        data  = s["data"]
        if len(data) < 2:
            continue
        delta = data[-1] - data[0]
        if abs(delta) > abs(best_delta):
            best_delta, best_topic = delta, s["topic"]

    if best_topic is None or best_delta == 0:
        return {
            "text": "Topic proportions have stayed roughly stable — no strong emerging or fading theme detected.",
            "direction": "neutral",
            "topic": None,
        }

    label     = topic_meta[best_topic]["label"] if best_topic < len(topic_meta) else f"Topic {best_topic + 1}"
    rising    = best_delta > 0
    direction = "rising" if rising else "fading"
    verb      = "emerging" if rising else "declining"

    return {
        "text": (
            f'Topic "{label}" is the strongest mover this period — {direction} by '
            f'{abs(best_delta):.1f} pp (from {labels[0]} to {labels[-1]}). '
            f"This may indicate {verb} discussion volume worth a closer look."
        ),
        "direction": "up" if rising else "down",
        "topic":     best_topic,
    }


# ── Public entry point ────────────────────────────────────────────────────────

def run_emerging_analysis(num_topics: int = 5, weeks: int = 8) -> dict:
    """
    Train LDA and return a dict ready to pass to jsonify().
    Includes an `available: False` response if there isn't enough data yet.
    """
    num_topics = max(2, min(num_topics, 10))
    weeks      = max(2, min(weeks, 26))

    result = _train_lda(num_topics=num_topics)
    if result is None:
        have = get_relevant_count()
        return {
            "available":     False,
            "documentCount": have,
            "minRequired":   MIN_LDA_DOCS,
            "message": (
                f"Not enough classified threat data yet to model topics "
                f"({have}/{MIN_LDA_DOCS} minimum). "
                f"Analyze more text or fetch OTX pulses, then check back."
            ),
        }

    lda, vectorizer, doc_topic, rows = result
    topic_keywords   = _get_topic_keywords(lda, vectorizer, num_topics)
    topics_over_time = _get_topics_over_time(doc_topic, rows, num_topics, weeks=weeks)
    signal           = _detect_emerging_signal(topics_over_time, topic_keywords)

    return {
        "available":     True,
        "numTopics":     num_topics,
        "weeks":         weeks,
        "documentCount": len(rows),
        "topics":        topic_keywords,
        "topicsOverTime": topics_over_time,
        "signal":        signal,
    }