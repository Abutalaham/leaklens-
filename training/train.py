"""Train the TF-IDF + Logistic Regression model, tune ML thresholds on a validation split, and
evaluate four systems on a held-out test split.

    python -m training.train            # full train + evaluation (about a minute on CPU)
"""
from __future__ import annotations

import csv
import itertools
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.metrics import precision_recall_fscore_support

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402
from engine.detector import Detector  # noqa: E402
from engine.ml import MLClassifier, build_pipeline  # noqa: E402
from training.dataset import generate  # noqa: E402

N_TRAIN, N_VAL, N_TEST = 4000, 1200, 1500
SEEDS = {"train": 42, "val": 99, "test": 7}


def _save_csv(name, rows):
    with open(config.BASE_DIR / "data" / name, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["snippet", "label"])
        w.writerows(rows)


def fit(train_rows):
    pipe = build_pipeline()
    pipe.fit([t for t, _ in train_rows], [y for _, y in train_rows])
    return pipe


def train_model_only():
    """Fast path used by the app when no saved model exists."""
    rows = generate(N_TRAIN, SEEDS["train"], "train")
    config.MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(fit(rows), config.MODEL_PATH)


def metrics(y_true, y_pred):
    p, r, f, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    tp = sum(1 for a, b in zip(y_true, y_pred) if a and b)
    fp = sum(1 for a, b in zip(y_true, y_pred) if not a and b)
    tn = sum(1 for a, b in zip(y_true, y_pred) if not a and not b)
    fn = sum(1 for a, b in zip(y_true, y_pred) if a and not b)
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4),
            "fpr": round(fp / (fp + tn), 4) if fp + tn else 0.0, "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def run_system(name, rows, clf, ml_cfg):
    y = [lab == "SENSITIVE" for _, lab in rows]
    if name == "ml_only":
        probs = clf.prob_sensitive([t for t, _ in rows])
        pred = [p >= 0.5 for p in probs]
    else:
        det = {"baseline_regex": Detector(use_ml=False, use_context=False),
               "rules_context": Detector(use_ml=False, use_context=True),
               "hybrid": Detector(clf, use_ml=True, use_context=True, ml_cfg=ml_cfg)}[name]
        pred = [det.flagged(t) for t, _ in rows]
    return y, pred


def main():
    t0 = time.time()
    train = generate(N_TRAIN, SEEDS["train"], "train")
    val = generate(N_VAL, SEEDS["val"], "test")      # includes held-out names/syntax, like the test set
    test = generate(N_TEST, SEEDS["test"], "test")
    _save_csv("train.csv", train)
    _save_csv("val.csv", val)
    _save_csv("test.csv", test)

    pipe = fit(train)
    config.MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(pipe, config.MODEL_PATH)
    clf = MLClassifier(pipe)

    # --- tune ML thresholds on the VALIDATION split only (never on test) ---
    best = None
    for disc, ben in itertools.product([0.5, 0.6, 0.7, 0.8, 0.9], [0.05, 0.15, 0.3]):
        cfg = {"discover": disc, "benign": ben, "boost": 0.8}
        y, pred = run_system("hybrid", val, clf, cfg)
        m = metrics(y, pred)
        key = (m["f1"], -m["fpr"])
        if best is None or key > best[0]:
            best = (key, cfg, m)
    cfg = best[1]
    config.THRESHOLDS_PATH.write_text(json.dumps(cfg, indent=2))
    print("tuned thresholds (validation):", cfg, best[2])

    # --- final evaluation on the held-out TEST split ---
    systems = {}
    errors = {}
    for name in ["baseline_regex", "rules_context", "ml_only", "hybrid"]:
        y, pred = run_system(name, test, clf, cfg)
        systems[name] = metrics(y, pred)
        if name == "hybrid":
            errors = {"false_negatives": [t for (t, _), a, b in zip(test, y, pred) if a and not b][:10],
                      "false_positives": [t for (t, _), a, b in zip(test, y, pred) if not a and b][:10]}
        print(f"{name:15s}", systems[name])

    out = {
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": {"train": N_TRAIN, "validation": N_VAL, "test": N_TEST,
                    "test_sensitive": sum(1 for _, l in test if l == "SENSITIVE"),
                    "test_non_sensitive": sum(1 for _, l in test if l == "NON_SENSITIVE"),
                    "seeds": SEEDS, "synthetic": True},
        "thresholds": cfg, "systems": systems, "hybrid_errors_sample": errors,
        "notes": [
            "All data are synthetic (randomly generated values). Real-world performance will differ.",
            "The test split uses variable names and syntax templates never seen in training (held-out families).",
            "Thresholds were tuned on a separate validation split, not on the test split.",
            "A snippet counts as 'flagged' if any ACTIVE finding exists (placeholders/likely-benign are not flagged).",
            "baseline_regex = rules without placeholder/context/ML filtering; rules_context adds placeholder and "
            "context checks; ml_only = classifier alone at p>=0.5; hybrid = rules + context + ML.",
            "Class balance is ~45% sensitive, far higher than in real files, so precision here is optimistic.",
        ],
    }
    (config.BASE_DIR / "evaluation").mkdir(exist_ok=True)
    config.EVAL_PATH.write_text(json.dumps(out, indent=2))
    write_markdown(out)
    print(f"done in {time.time() - t0:.0f}s")


def write_markdown(out):
    names = {"baseline_regex": "Baseline regex (no context)", "rules_context": "Rules + context",
             "ml_only": "ML only (TF-IDF + LR)", "hybrid": "Hybrid (rules + context + ML)"}
    lines = ["# LeakLens evaluation (held-out synthetic test set)", "",
             f"Test snippets: {out['dataset']['test']} ({out['dataset']['test_sensitive']} sensitive, "
             f"{out['dataset']['test_non_sensitive']} non-sensitive). Generated {out['created']}.", "",
             "| System | Precision | Recall | F1 | False-positive rate | TP | FP | TN | FN |", "|---|---|---|---|---|---|---|---|---|"]
    for k, m in out["systems"].items():
        lines.append(f"| {names[k]} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.3f} | "
                     f"{m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} |")
    lines += ["", "## Notes", *[f"- {n}" for n in out["notes"]], ""]
    (config.BASE_DIR / "evaluation" / "EVALUATION.md").write_text("\n".join(lines))


if __name__ == "__main__":
    main()
