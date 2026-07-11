"""
models.py
─────────
Loads every ML model exactly once at startup and exposes them as
module-level singletons. Import from here in classifier.py only —
no other file should touch these directly.

Heavy imports (torch, transformers) live here so the rest of the
codebase stays lean.
"""

import joblib
import spacy
import torch
from transformers import pipeline

from config import BINARY_VECTORIZER_PKL, SVM_MODEL_PKL, DISTILBERT_DIR


print("Loading classification models...")

# spaCy — lemmatiser only (parser, NER, textcat not needed)
nlp = spacy.load("en_core_web_sm", disable=["parser", "ner", "textcat"])

# SVM binary classifier + its TF-IDF vectorizer
binary_vectorizer = joblib.load(BINARY_VECTORIZER_PKL)
svm_binary        = joblib.load(SVM_MODEL_PKL)

# DistilBERT multi-class classifier (fine-tuned on CTI data)
_device    = 0 if torch.cuda.is_available() else -1
classifier = pipeline(
    "text-classification",
    model=DISTILBERT_DIR,
    tokenizer=DISTILBERT_DIR,
    device=_device,
)

print("All models loaded successfully\n")