# LeakLens evaluation (held-out synthetic test set)

Test snippets: 1500 (704 sensitive, 796 non-sensitive). Generated 2026-11-21T01:21:13+00:00.

| System | Precision | Recall | F1 | False-positive rate | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|---|
| Baseline regex (no context) | 0.611 | 0.903 | 0.729 | 0.509 | 636 | 405 | 391 | 68 |
| Rules + context | 0.991 | 0.888 | 0.936 | 0.007 | 625 | 6 | 790 | 79 |
| ML only (TF-IDF + LR) | 0.993 | 0.983 | 0.988 | 0.006 | 692 | 5 | 791 | 12 |
| Hybrid (rules + context + ML) | 0.991 | 0.972 | 0.981 | 0.007 | 684 | 6 | 790 | 20 |

## Notes
- All data are synthetic (randomly generated values). Real-world performance will differ.
- The test split uses variable names and syntax templates never seen in training (held-out families).
- Thresholds were tuned on a separate validation split, not on the test split.
- A snippet counts as 'flagged' if any ACTIVE finding exists (placeholders/likely-benign are not flagged).
- baseline_regex = rules without placeholder/context/ML filtering; rules_context adds placeholder and context checks; ml_only = classifier alone at p>=0.5; hybrid = rules + context + ML.
- Class balance is ~45% sensitive, far higher than in real files, so precision here is optimistic.
