# ACS: Agentic Compliance System for Cross-Border Payments

Reference implementation supporting the manuscript *"A Decentralized Agentic
Architecture for Real-Time Compliance and Fraud Detection in Cross-Border
Payment Systems"* (Sankaranainar Parmsivan, submitted to IEEE IT
Professional).

The system simulates a decentralized multi-agent pipeline for real-time
fraud detection and compliance enforcement over ISO 20022-style cross-border
transactions: an anomaly detection agent, a policy enforcement agent, a
cross-domain risk agent, a supervised ML agent (XGBoost), a human-on-the-loop
review step, and a hashed audit/trust layer — all coordinated by an
`ACS_Orchestrator`.

## ⚠️ Known limitation — please read before citing results from this repo

The original project notebook (`notebooks/Code_RunFile.ipynb`) references
three features that are used to train the anomaly and ML agents —
`velocity_score`, `device_risk_score`, and `time_diff` — but the script that
computes them from the raw source data was not included in the delivered
project files. As provided, the notebook cannot run past the EDA section.

`src/acs/feature_engineering.py` includes a **provisional, clearly-labeled
reconstruction** of those three features (velocity from per-user transaction
gaps, device risk from the device fraud hint blended with IP risk) so the
full pipeline is runnable end to end. Running the pipeline with these proxy
features does **not** reproduce the precision/recall/F1 numbers reported in
the manuscript's Tables 2–3 — see `reports/metrics_summary.txt` for the
actual output of this repo's pipeline.

**This module is a placeholder.** It should be replaced with the original
feature-engineering logic (or a documented, agreed-upon substitute) before
this repository is treated as the authoritative validation artifact for the
published paper.

## Project structure

```
.
├── data/                       # Source CSVs (transactions, users, devices, ips, merchants, chargebacks)
├── notebooks/
│   └── Code_RunFile.ipynb      # Original exploratory notebook, unmodified
├── src/acs/
│   ├── data_loader.py          # Load + merge source tables
│   ├── feature_engineering.py  # Compliance features + PROVISIONAL risk features (see warning above)
│   ├── agents.py                # AnomalyAgent, PolicyAgent, RiskAgent, HumanAgent, AuditLayer, MLAgent
│   ├── orchestrator.py          # ACS_Orchestrator: fuses agent outputs into a decision
│   └── evaluate.py              # Confusion matrix / classification report helpers
├── scripts/
│   └── run_pipeline.py          # End-to-end runnable script
├── tests/
│   └── test_pipeline.py         # Smoke tests (data load, feature shapes, no missing values)
├── reports/                     # Generated: confusion_matrix.png, metrics_summary.txt
├── requirements.txt
└── README.md
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
python scripts/run_pipeline.py
```

This loads the six CSVs from `data/`, merges them, engineers features,
trains the anomaly detector and XGBoost classifier on a SMOTETomek-balanced
split, runs the full agent pipeline, and writes:

- `reports/confusion_matrix.png`
- `reports/metrics_summary.txt`

## Tests

```bash
pytest tests/ -v
```

## Architecture reference

The four-layer architecture (Input → Agentic Orchestrator → Agent →
Decision/Implementation) and the human-on-the-loop escalation workflow are
described in full in the manuscript. This repository implements the
proof-of-concept version of that architecture over a synthetic 120,000-row
cross-border transaction dataset.

## License

MIT — see `LICENSE`.

## Citation

If you use this repository, please cite the manuscript once published
(details to be added upon acceptance). ORCID: 0009-0006-1738-3863.
