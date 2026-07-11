"""
classifier.py
─────────────
The full text-processing and classification pipeline:

    raw text
      → clean_text()           (spaCy lemmatise, strip noise)
      → is_meaningful_threat_text()  (keyword gate — drops junk early)
      → SVM binary classifier  (relevant vs. not relevant)
      → DistilBERT multi-class (6 threat categories)
      → VirusTotal enrichment  (optional IOC lookup)
      → build_threat_summary() (analyst notes)
      → process_text()         returns a dict ready to store in the DB
"""

import re

from analyst  import build_threat_summary
from config   import CLASS_NAMES, CTI_KEYWORDS
from ioc      import fetch_virustotal_context
from models   import binary_vectorizer, classifier, nlp, svm_binary


# ── Text cleaning ─────────────────────────────────────────────────────────────

def clean_text(text: str) -> str:
    """Strip HTML, lowercase, lemmatise, remove stop-words and short tokens."""
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", text)       # strip HTML tags
    text = text.lower()
    text = re.sub(r"[^a-z0-9.\-\s:/]", " ", text)
    doc  = nlp(text)
    return " ".join(t.lemma_ for t in doc if not t.is_stop and len(t.text.strip()) > 1)


def is_meaningful_threat_text(original: str, cleaned: str) -> bool:
    """
    Quick pre-filter before the expensive models run.
    Returns False if the text is too short or contains no CTI keywords.
    """
    if len(original.strip()) < 15:
        return False
    tokens = cleaned.split()
    if len(tokens) < 3:
        return False
    if set(tokens).isdisjoint(CTI_KEYWORDS):
        return False
    return True


# ── Full pipeline ─────────────────────────────────────────────────────────────

def process_text(text: str, pulse_id: str | None = None) -> dict | None:
    """
    Run the complete classify-and-enrich pipeline on one piece of text.

    Returns a dict suitable for db.save_threat(), or None if the text
    fails the meaningfulness gate (too short / no CTI keywords).
    """
    cleaned = clean_text(text)
    if not is_meaningful_threat_text(text, cleaned):
        return None

    # ── Stage 1: SVM binary classification ───────────────────────────────────
    X_bin    = binary_vectorizer.transform([cleaned])
    relevant = int(svm_binary.predict(X_bin)[0])
    bin_conf = float(abs(svm_binary.decision_function(X_bin)[0]))

    category = mc_conf = summary = None

    # ── Stage 2: DistilBERT multi-class (only for relevant threats) ───────────
    if relevant:
        result   = classifier(cleaned)[0]
        label_id = int(result["label"].split("_")[-1])
        category = CLASS_NAMES[label_id]
        mc_conf  = float(result["score"])

        # ── Stage 3: VirusTotal IOC enrichment ───────────────────────────────
        vt_data = fetch_virustotal_context(text)
        summary = build_threat_summary(text, cleaned, category, mc_conf, vt_data)

    return {
        "pulse_id":        pulse_id,
        "original_text":   text,
        "clean_text":      cleaned,
        "relevant":        relevant,
        "bin_confidence":  bin_conf,
        "category":        category,
        "mc_confidence":   mc_conf,
        "analyst_summary": summary,
    }