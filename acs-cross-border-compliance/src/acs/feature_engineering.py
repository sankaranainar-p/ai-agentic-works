"""
Feature engineering for the ACS pipeline.

IMPORTANT / KNOWN GAP
----------------------
The original Code_RunFile.ipynb delivered by the development vendor
references three model-critical columns that are never computed anywhere
in that notebook and do not exist in any of the six source CSVs:

    - velocity_score
    - device_risk_score
    - time_diff

Running the notebook as delivered raises a KeyError as soon as those
columns are used (EDA cell 9, AnomalyAgent/RiskAgent, and the XGBoost
feature list in the orchestrator cell).

The functions below (`add_derived_risk_features`) are a REBUILT, CLEARLY
PROVISIONAL reconstruction of those three features, written from first
principles so the pipeline is runnable end to end:

    - time_diff        = seconds since the same user's previous transaction
    - velocity_score    = inverse-time-decay proxy for transaction velocity
    - device_risk_score = blend of the device fraud hint and IP risk level

These are NOT verified against whatever produced the metrics reported in
the submitted manuscript (Tables 2-3, Figs 4-5). Running this pipeline
with these proxy features does NOT reproduce the paper's numbers (see
reports/reconstructed_metrics.md). Treat this module as a placeholder
until the original feature-engineering script is obtained and swapped in.
"""
import numpy as np
import pandas as pd

THRESHOLDS = {"IN": 10000, "US": 20000, "UK": 15000, "SG": 25000, "AE": 30000}


def add_compliance_features(df: pd.DataFrame) -> pd.DataFrame:
    """ISO 20022 simulation, cross-border flag, jurisdiction threshold check."""
    df = df.copy()
    df["sender_country"] = df["card_country"]
    df["receiver_country"] = df["country"]
    df["is_cross_border"] = (df["sender_country"] != df["receiver_country"]).astype(int)

    rng = np.random.default_rng(42)
    df["message_type"] = rng.choice(["pacs.008", "pacs.009", "camt.056"], len(df))
    df["purpose_code"] = rng.choice(["SALA", "SUPP", "CASH", "GDSV"], len(df))

    df["sender_threshold"] = df["sender_country"].map(THRESHOLDS)
    df["receiver_threshold"] = df["receiver_country"].map(THRESHOLDS)
    df["compliance_violation"] = (
        (df["amount"] > df["sender_threshold"]) | (df["amount"] > df["receiver_threshold"])
    ).astype(int)
    df["compliance_violation"] = df["compliance_violation"].fillna(0)
    return df


def add_derived_risk_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    PROVISIONAL reconstruction of velocity_score, device_risk_score, time_diff.
    See module docstring — replace with the original vendor logic once available.
    """
    df = df.copy().sort_values(["user_id", "created_at_x"])

    df["time_diff"] = (
        df.groupby("user_id")["created_at_x"].diff().dt.total_seconds()
    )
    df["time_diff"] = df["time_diff"].fillna(df["time_diff"].median())

    df["velocity_score"] = (1.0 / (1.0 + df["time_diff"] / 60.0)).clip(0, 1)

    ip_risk_col = "ip_risk_level_y" if "ip_risk_level_y" in df.columns else "ip_risk_level"
    df["device_risk_score"] = (
        0.6 * df["is_fraud_device_hint"].fillna(0)
        + 0.4 * df[ip_risk_col].fillna(df[ip_risk_col].median())
    ).clip(0, 1)

    return df


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Full feature pipeline: compliance features + provisional risk features."""
    df = add_compliance_features(df)
    df = add_derived_risk_features(df)
    return df
