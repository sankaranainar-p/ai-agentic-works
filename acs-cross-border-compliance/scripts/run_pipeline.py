"""
End-to-end ACS pipeline runner.

Usage:
    python scripts/run_pipeline.py

Loads data/*.csv -> engineers features -> trains agents -> evaluates ->
writes a confusion matrix figure and a metrics summary to reports/.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import matplotlib.pyplot as plt  # noqa: E402
from imblearn.combine import SMOTETomek  # noqa: E402
from sklearn.metrics import ConfusionMatrixDisplay, confusion_matrix  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402

from acs.data_loader import build_merged_dataframe  # noqa: E402
from acs.evaluate import evaluate_decisions  # noqa: E402
from acs.feature_engineering import engineer_features  # noqa: E402
from acs.orchestrator import ACS_Orchestrator  # noqa: E402

FEATURES = ["amount", "velocity_score", "device_risk_score", "is_cross_border", "time_diff"]


def main():
    reports_dir = ROOT / "reports"
    reports_dir.mkdir(exist_ok=True)

    print("Loading and merging source tables...")
    df = build_merged_dataframe()

    print("Engineering features (compliance + PROVISIONAL risk features)...")
    df = engineer_features(df)

    X = df[FEATURES].fillna(0)
    y = df["is_fraud"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Balancing training set with SMOTETomek...")
    smt = SMOTETomek(random_state=42)
    X_train_res, y_train_res = smt.fit_resample(X_train, y_train)

    print("Running ACS orchestrator (anomaly + ML + policy + human-on-the-loop)...")
    acs = ACS_Orchestrator()
    result_df = acs.run(df, X_train_res, y_train_res, X_test)

    metrics = evaluate_decisions(result_df)
    print("\n=== Confusion Matrix ===")
    print(metrics["confusion_matrix"])
    print("\n=== Classification Report ===")
    print(metrics["report"])
    print("\n=== Decision Breakdown ===")
    print(metrics["decision_counts"])

    # Save figure
    cm = confusion_matrix(result_df["is_fraud"], (result_df["decision"] != "APPROVED").astype(int))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm)
    disp.plot()
    plt.title("Confusion Matrix - ACS Pipeline (reconstructed features)")
    plt.savefig(reports_dir / "confusion_matrix.png", dpi=150, bbox_inches="tight")
    print(f"\nSaved figure to {reports_dir / 'confusion_matrix.png'}")

    with open(reports_dir / "metrics_summary.txt", "w") as f:
        f.write("ACS pipeline run (provisional/reconstructed velocity_score, "
                "device_risk_score, time_diff -- see feature_engineering.py)\n\n")
        f.write(str(metrics["confusion_matrix"]) + "\n\n")
        f.write(metrics["report"] + "\n\n")
        f.write(str(metrics["decision_counts"]))
    print(f"Saved metrics summary to {reports_dir / 'metrics_summary.txt'}")


if __name__ == "__main__":
    main()
