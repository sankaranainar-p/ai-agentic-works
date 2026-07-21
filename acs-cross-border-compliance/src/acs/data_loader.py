"""
Data loading and merging for the Agentic Compliance System (ACS).

Reads the six source CSVs and merges them into a single transaction-level
dataframe, exactly mirroring the merge logic from the original
Code_RunFile.ipynb (cell 2).
"""
from pathlib import Path
import pandas as pd

DEFAULT_DATA_DIR = Path(__file__).resolve().parents[2] / "data"


def load_raw_tables(data_dir: Path = DEFAULT_DATA_DIR) -> dict:
    """Load each source CSV into its own dataframe."""
    return {
        "transactions": pd.read_csv(data_dir / "transactions_raw.csv"),
        "users": pd.read_csv(data_dir / "users.csv"),
        "devices": pd.read_csv(data_dir / "devices.csv"),
        "ips": pd.read_csv(data_dir / "ips.csv"),
        "merchants": pd.read_csv(data_dir / "merchants.csv"),
        "chargebacks": pd.read_csv(data_dir / "chargebacks.csv"),
    }


def build_merged_dataframe(data_dir: Path = DEFAULT_DATA_DIR) -> pd.DataFrame:
    """Merge all source tables on their shared keys and derive is_fraud."""
    tables = load_raw_tables(data_dir)

    df = (
        tables["transactions"]
        .merge(tables["users"], on="user_id", how="left")
        .merge(tables["devices"], on="device_id", how="left")
        .merge(tables["ips"], on="ip_id", how="left")
        .merge(tables["merchants"], on="merchant_id", how="left")
        .merge(tables["chargebacks"], on="transaction_id", how="left")
    )

    df["is_fraud"] = df["fraud_label"].astype(int)
    df["created_at_x"] = pd.to_datetime(df["created_at_x"])
    return df
