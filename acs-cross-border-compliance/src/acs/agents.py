"""
Agent implementations for the Agentic Compliance System (ACS).

Ported 1:1 from Code_RunFile.ipynb cells 15, 17, 19, 21, 23, 26 with no
behavioral changes -- only reorganized into importable classes.
"""
import hashlib

from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier


class AnomalyAgent:
    """Unsupervised outlier detector over amount / velocity / device risk."""

    def __init__(self, contamination: float = 0.02, random_state: int = 42):
        self.model = IsolationForest(contamination=contamination, random_state=random_state)

    def train(self, df):
        self.model.fit(df[["amount", "velocity_score", "device_risk_score"]])

    def predict(self, df):
        return (self.model.predict(df[["amount", "velocity_score", "device_risk_score"]]) == -1).astype(int)


class PolicyAgent:
    """Rule-based jurisdiction threshold check."""

    def evaluate(self, df):
        return df["compliance_violation"]


class RiskAgent:
    """Weighted composite risk score."""

    def compute(self, df):
        return (
            0.4 * df["velocity_score"]
            + 0.3 * df["device_risk_score"]
            + 0.3 * df["is_cross_border"]
        )


class HumanAgent:
    """Human-on-the-loop rule for high-value transactions."""

    def review(self, row):
        return 1 if row["amount"] > 20000 else 0  # 1 = reject


class AuditLayer:
    """Append-only hashed decision log (distributed trust simulation)."""

    def __init__(self):
        self.logs = []

    def log(self, row, decision):
        record = str(row["transaction_id"]) + str(decision)
        self.logs.append(hashlib.sha256(record.encode()).hexdigest())


class MLAgent:
    """Supervised fraud probability model (XGBoost)."""

    def __init__(
        self,
        n_estimators: int = 300,
        max_depth: int = 8,
        learning_rate: float = 0.05,
        scale_pos_weight: int = 10,
        random_state: int = 42,
    ):
        self.model = XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            scale_pos_weight=scale_pos_weight,
            random_state=random_state,
            eval_metric="logloss",
        )

    def train(self, X, y):
        self.model.fit(X, y)

    def predict_proba(self, X):
        return self.model.predict_proba(X)[:, 1]
