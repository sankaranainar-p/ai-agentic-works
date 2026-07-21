"""Evaluation helpers: confusion matrix + classification report on ACS decisions."""
from sklearn.metrics import classification_report, confusion_matrix


def evaluate_decisions(result_df):
    y_true = result_df["is_fraud"]
    y_pred = (result_df["decision"] != "APPROVED").astype(int)

    cm = confusion_matrix(y_true, y_pred)
    report = classification_report(y_true, y_pred, digits=4)
    return {
        "confusion_matrix": cm,
        "report": report,
        "decision_counts": result_df["decision"].value_counts(),
    }
