"""Smoke tests: pipeline runs end-to-end and produces sane shapes/types."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import pandas as pd  # noqa: E402

from acs.data_loader import build_merged_dataframe  # noqa: E402
from acs.feature_engineering import engineer_features  # noqa: E402


def test_merge_shape():
    df = build_merged_dataframe()
    assert len(df) == 120_000
    assert "is_fraud" in df.columns


def test_feature_engineering_adds_expected_columns():
    df = build_merged_dataframe()
    df = engineer_features(df)
    for col in ["is_cross_border", "compliance_violation", "velocity_score",
                "device_risk_score", "time_diff"]:
        assert col in df.columns
    assert df["velocity_score"].between(0, 1).all()
    assert df["device_risk_score"].between(0, 1).all()


def test_no_missing_engineered_features():
    df = build_merged_dataframe()
    df = engineer_features(df)
    assert not df["time_diff"].isna().any()
