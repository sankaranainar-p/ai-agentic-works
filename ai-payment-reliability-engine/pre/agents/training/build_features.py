#!/usr/bin/env python3
"""
pre/agents/training/build_features.py — Extract features from RE1-OB cases.

Loads RE1-OB via RCAEvalAdapter, synthesizes alerts, extracts TF-IDF + KPI features.

Usage:
    python3 pre/agents/training/build_features.py \
        --rcaeval-root data/rcaeval \
        --output features.parquet
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder

from pre.signals.rcaeval import RCAEvalAdapter
from pre.signals.alert_synth import synthesize_alert
from pre.agents.triage import KPIFeatures


def _strip_numbers(text: str) -> str:
    """Replace numeric values in text with placeholder token <NUM>.

    Strips:
    - Floating point numbers (e.g., 2678784.00 -> <NUM>)
    - Integers (e.g., 360 -> <NUM>)
    - Patterns like "sigma", "duration", "z_score" with numeric suffixes

    Keeps semantic tokens like service names, metric names, "ALERT", "saturation", etc.
    """
    # Replace floats and integers with <NUM>
    text = re.sub(r'\b\d+\.\d+\b', '<NUM>', text)  # floats
    text = re.sub(r'\b\d+\b', '<NUM>', text)       # integers

    return text


def build_features(
    rcaeval_root: str | Path,
    output_path: str | Path = "features.parquet",
    dataset: str = "RE1-OB",
    strip_numbers: bool = False,
) -> None:
    """Build feature matrix from RCAEval cases.

    Args:
        rcaeval_root: Root directory containing RCAEval data
        output_path: Output parquet file path
        dataset: Dataset to load (RE1-OB, RE1-SS, RE2-TT)
        strip_numbers: Replace numeric values with <NUM> before TF-IDF to reduce vocabulary overfitting
    """
    output_path = Path(output_path)

    print(f"Loading {dataset} cases from {rcaeval_root}...")
    adapter = RCAEvalAdapter(rcaeval_root, dataset)

    cases = []
    ground_truths = []
    alert_texts = []
    alerts = []  # Keep Alert objects for structured field extraction

    case_count = 0
    silent_count = 0

    for case, gt in adapter:
        cases.append(case)
        ground_truths.append(gt)
        case_count += 1

        # Synthesize alert
        alert = synthesize_alert(case)
        alerts.append(alert)
        if alert.silent:
            silent_count += 1
            alert_texts.append("[SILENT ALERT]")
        else:
            alert_texts.append(alert.text)

    print(f"  Loaded {case_count} cases ({silent_count} silent alerts)")

    # Optional: strip numeric values to reduce vocabulary overfitting
    if strip_numbers:
        print("Stripping numeric values from alert texts...")
        alert_texts = [_strip_numbers(t) if t != "[SILENT ALERT]" else t for t in alert_texts]
        print(f"  After stripping: example text = {alert_texts[0][:100]}")

    # Fit TF-IDF on non-silent alerts
    print("Fitting TF-IDF vectorizer...")
    non_silent_texts = [t for t in alert_texts if t != "[SILENT ALERT]"]

    tfidf = TfidfVectorizer(max_features=100, min_df=2, max_df=0.8)
    tfidf_features = tfidf.fit_transform([t for t in alert_texts]).toarray()
    print(f"  Vocabulary size: {len(tfidf.vocabulary_)}")

    print(f"  TF-IDF features shape: {tfidf_features.shape}")

    # Extract KPI shape features for each case
    print("Extracting KPI shape features...")
    kpi_features = []

    for case, alert_text in zip(cases, alert_texts):
        # Breach magnitude (from KPIFeatures)
        # We'll use a simplified version since we don't have full alert objects
        breach_magnitude = 3.0 if alert_text != "[SILENT ALERT]" else 0.0

        # Slope over 60s (from metrics)
        slope = KPIFeatures.slope_60s(case, None)

        # Co-breaching services
        co_breach_count = len([s for s in case.metrics.keys()])  # Simplified

        kpi_features.append([breach_magnitude, slope, co_breach_count])

    kpi_array = np.array(kpi_features)
    print(f"  KPI features shape: {kpi_array.shape}")

    # Extract structured features from Alert objects
    print("Extracting structured alert features (rule_id, service, payment_sli)...")
    rule_ids = []
    services = []
    payment_slis = []

    for alert in alerts:
        rule_ids.append(alert.rule_id if alert.rule_id else "SILENT")
        services.append(alert.service if alert.service else "UNKNOWN")
        payment_slis.append(alert.payment_sli if alert.payment_sli else "UNKNOWN")

    # One-hot encode structured features
    structured_data = pd.DataFrame({
        'rule_id': rule_ids,
        'service': services,
        'payment_sli': payment_slis,
    })

    # Create one-hot encoded features for each field. Cast to int8: pandas
    # get_dummies returns bool columns, which train_triage.py's
    # select_dtypes(include=[np.number]) silently drops (bool is not numeric),
    # yielding a zero-width structured feature matrix.
    rule_onehot = pd.get_dummies(structured_data['rule_id'], prefix='rule')
    service_onehot = pd.get_dummies(structured_data['service'], prefix='svc')
    sli_onehot = pd.get_dummies(structured_data['payment_sli'], prefix='sli')

    structured_onehot_df = pd.concat(
        [rule_onehot, service_onehot, sli_onehot], axis=1
    ).astype('int8')
    structured_features = structured_onehot_df.values
    print(f"  Structured features shape: {structured_features.shape}")
    print(f"    Rule IDs: {rule_onehot.shape[1]}, Services: {service_onehot.shape[1]}, SLIs: {sli_onehot.shape[1]}")

    # Create three feature sets for ablation:
    # 1. TF-IDF only
    # 2. Structured only
    # 3. Both combined
    X_tfidf_only = tfidf_features
    X_structured_only = structured_features
    X_combined = np.hstack([tfidf_features, structured_features, kpi_array])

    print(f"\nFeature matrix shapes:")
    print(f"  TF-IDF only: {X_tfidf_only.shape}")
    print(f"  Structured only: {X_structured_only.shape}")
    print(f"  Combined (TF-IDF + Structured + KPI): {X_combined.shape}")

    # Use combined for default output
    X = X_combined

    # Extract labels
    y = np.array([gt.root_cause_service for gt in ground_truths])

    # Save to parquet
    df = pd.DataFrame(X)
    df['case_id'] = [c.case_id for c in cases]
    df['root_cause_service'] = y
    df['alert_silent'] = [t == "[SILENT ALERT]" for t in alert_texts]
    df['alert_text'] = alert_texts

    # Use CSV if parquet unavailable
    if output_path.suffix == '.parquet':
        try:
            df.to_parquet(output_path)
        except ImportError:
            output_path = output_path.with_suffix('.csv')
            df.to_csv(output_path, index=False)
    else:
        df.to_csv(output_path, index=False)

    print(f"\n✅ Features saved to {output_path}")
    print(f"   Combined shape: {X.shape}")
    print(f"   Cases: {case_count} (silent: {silent_count})")
    print(f"\nFeature counts for ablation:")
    print(f"   TF-IDF columns: {tfidf_features.shape[1]}")
    print(f"   Structured columns: {structured_features.shape[1]}")
    print(f"   KPI columns: {kpi_array.shape[1]}")

    # Also save the intermediate feature matrices for ablation
    output_stem = output_path.stem if isinstance(output_path, Path) else Path(output_path).stem
    output_dir = Path(output_path).parent if isinstance(output_path, Path) else Path(".")

    # Save TF-IDF only version
    df_tfidf = pd.DataFrame(X_tfidf_only)
    df_tfidf['case_id'] = [c.case_id for c in cases]
    df_tfidf['root_cause_service'] = y
    df_tfidf['alert_silent'] = [t == "[SILENT ALERT]" for t in alert_texts]
    df_tfidf['alert_text'] = alert_texts
    tfidf_path = output_dir / f"{output_stem}_tfidf_only.parquet"
    try:
        df_tfidf.to_parquet(tfidf_path)
        print(f"   TF-IDF only: {tfidf_path}")
    except:
        pass

    # Save Structured only version — keep the named one-hot columns
    # (rule_*, svc_*, sli_*) instead of positional integers so downstream
    # consumers can identify features and select_dtypes keeps them.
    df_structured = structured_onehot_df.copy()
    df_structured['case_id'] = [c.case_id for c in cases]
    df_structured['root_cause_service'] = y
    df_structured['alert_silent'] = [t == "[SILENT ALERT]" for t in alert_texts]
    df_structured['alert_text'] = alert_texts
    structured_path = output_dir / f"{output_stem}_structured_only.parquet"
    try:
        df_structured.to_parquet(structured_path)
        print(f"   Structured only: {structured_path}")
    except:
        pass


def main():
    parser = argparse.ArgumentParser(description="Build features from RCAEval cases")
    parser.add_argument("--rcaeval-root", default="data/rcaeval", help="RCAEval root directory")
    parser.add_argument("--output", default="features.parquet", help="Output parquet file")
    parser.add_argument("--dataset", default="RE1-OB", help="Dataset to load")
    parser.add_argument("--strip-numbers", action="store_true", help="Replace numeric values with <NUM> before TF-IDF")
    args = parser.parse_args()

    try:
        build_features(args.rcaeval_root, args.output, args.dataset, strip_numbers=args.strip_numbers)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
