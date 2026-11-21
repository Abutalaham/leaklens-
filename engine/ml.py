"""Lightweight text classifier (TF-IDF char n-grams + Logistic Regression).

The model only ESTIMATES how likely a snippet is to contain a sensitive value. It never decides the
final risk on its own: engine.risk combines it with deterministic rules and context."""
from __future__ import annotations

import json
import threading

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

import config

_lock = threading.Lock()
_cached = None


def build_pipeline() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=10000, sublinear_tf=True)),
        ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])


class MLClassifier:
    def __init__(self, pipe: Pipeline):
        self.pipe = pipe
        self._idx = list(pipe.classes_).index("SENSITIVE")

    def prob_sensitive(self, snippets: list[str]) -> list[float]:
        if not snippets:
            return []
        return [float(p[self._idx]) for p in self.pipe.predict_proba(snippets)]


def load_thresholds() -> dict:
    cfg = dict(config.DEFAULT_ML)
    try:
        cfg.update(json.loads(config.THRESHOLDS_PATH.read_text()))
    except (OSError, ValueError):
        pass
    return cfg


def load_classifier() -> MLClassifier | None:
    """Load the saved model; if it is missing, train one quickly from the synthetic data."""
    global _cached
    with _lock:
        if _cached is None:
            try:
                if not config.MODEL_PATH.exists():
                    from training.train import train_model_only
                    train_model_only()
                _cached = MLClassifier(joblib.load(config.MODEL_PATH))
            except Exception:  # ML is optional: fall back to rules-only
                _cached = False
        return _cached or None


def snippet_for(lines: list[str], i: int) -> str:
    """The line itself, plus the previous line when it is a comment (useful context)."""
    cur = lines[i].strip()[:300]
    if i > 0 and lines[i - 1].lstrip().startswith(("#", "//", "*", "/*", "<!--")):
        return lines[i - 1].strip()[:200] + "\n" + cur
    return cur
