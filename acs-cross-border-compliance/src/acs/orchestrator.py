"""
ACS_Orchestrator: coordinates all agents and fuses their outputs into a
final decision per transaction. Ported from Code_RunFile.ipynb cell 26.
"""
from .agents import AnomalyAgent, AuditLayer, HumanAgent, MLAgent, PolicyAgent, RiskAgent


class ACS_Orchestrator:
    def __init__(self, flag_threshold: float = 0.8):
        self.anomaly = AnomalyAgent()
        self.policy = PolicyAgent()
        self.risk = RiskAgent()
        self.human = HumanAgent()
        self.audit = AuditLayer()
        self.ml = MLAgent()
        self.flag_threshold = flag_threshold

    def run(self, df, X_train, y_train, X_test):
        # Train agents
        self.anomaly.train(df)
        self.ml.train(X_train, y_train)

        # Predictions
        df["anomaly_flag"] = self.anomaly.predict(df)
        df["policy_flag"] = self.policy.evaluate(df)
        df["risk_score"] = self.risk.compute(df)

        # ML probabilities
        ml_score = self.ml.predict_proba(X_test)

        decisions = []
        for i, (_, row) in enumerate(df.iloc[X_test.index].iterrows()):
            decision = "APPROVED"

            # Fusion: weighted blend of ML score, anomaly flag, policy flag
            score = (
                0.75 * ml_score[i]
                + 0.15 * row["anomaly_flag"]
                + 0.1 * row["policy_flag"]
            )

            if score > self.flag_threshold:
                decision = "FLAGGED"
                if self.human.review(row):
                    decision = "REJECTED"

            self.audit.log(row, decision)
            decisions.append(decision)

        result_df = df.iloc[X_test.index].copy()
        result_df["decision"] = decisions
        return result_df
