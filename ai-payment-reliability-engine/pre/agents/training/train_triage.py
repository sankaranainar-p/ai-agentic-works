#!/usr/bin/env python3
"""
pre/agents/training/train_triage.py — Train logistic regression + isotonic calibration.

Loads features from build_features.py output, trains model, sweeps tau for 95% precision.

Usage:
    python3 pre/agents/training/train_triage.py \
        --features features.parquet \
        --output-dir models \
        --report-dir docs
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.isotonic import IsotonicRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib

try:
    import matplotlib.pyplot as plt
except ImportError:
    plt = None


def run_diagnostics(X, y, X_train, X_val, y_train, y_val, alert_texts=None, case_ids=None, train_indices=None, val_indices=None, numeric_cols=None):
    """Run diagnostic checks on feature sets and regularization.

    Args:
        X: Full feature matrix (numeric-only)
        y: Full labels
        X_train, X_val: Train/val splits (numeric-only, unscaled)
        y_train, y_val: Train/val labels
        alert_texts: Original alert text for vocabulary overlap check
        case_ids: Original case IDs
        train_indices: Indices of training samples in original data
        val_indices: Indices of validation samples in original data
        numeric_cols: List of numeric column names (for documentation/validation)
    """
    # Defensive check: X_train and X_val must be numeric numpy arrays
    if not isinstance(X_train, np.ndarray) or not np.issubdtype(X_train.dtype, np.number):
        raise TypeError(f"X_train must be numeric numpy array, got {type(X_train)} with dtype {X_train.dtype}")
    if not isinstance(X_val, np.ndarray) or not np.issubdtype(X_val.dtype, np.number):
        raise TypeError(f"X_val must be numeric numpy array, got {type(X_val)} with dtype {X_val.dtype}")

    print("\n" + "="*80)
    print("DIAGNOSTICS: Class Distribution, Ablation, Regularization Sweep")
    print("="*80)

    # 1. Class distribution
    print("\n[1/3] Class Distribution")
    print("-" * 80)
    train_classes, train_counts = np.unique(y_train, return_counts=True)
    val_classes, val_counts = np.unique(y_val, return_counts=True)

    print("\nTrain split class counts:")
    print(f"{'Class':<10} {'Count':<10} {'Pct':<10}")
    print("-" * 30)
    for cls, cnt in zip(train_classes, train_counts):
        print(f"{cls:<10} {cnt:<10} {cnt/len(y_train)*100:.1f}%")

    print("\nValidation split class counts:")
    print(f"{'Class':<10} {'Count':<10} {'Pct':<10}")
    print("-" * 30)
    for cls, cnt in zip(val_classes, val_counts):
        print(f"{cls:<10} {cnt:<10} {cnt/len(y_val)*100:.1f}%")

    # 2. Ablation: KPI-only, TF-IDF-only, combined
    print("\n[2/3] Feature Ablation Study")
    print("-" * 80)

    # Identify which columns are TF-IDF (first 75) vs KPI (last 3)
    # Based on build_features.py: 75 TF-IDF + 3 KPI = 78 total
    n_tfidf = X.shape[1] - 3
    tfidf_cols = list(range(n_tfidf))
    kpi_cols = list(range(n_tfidf, X.shape[1]))

    scaler = StandardScaler()

    # Combined model (baseline)
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    lr_combined = LogisticRegression(max_iter=1000, random_state=42, multi_class='multinomial', solver='lbfgs', class_weight='balanced')
    lr_combined.fit(X_train_scaled, y_train)
    combined_train = lr_combined.score(X_train_scaled, y_train)
    combined_val = lr_combined.score(X_val_scaled, y_val)

    # KPI-only model
    X_train_kpi = X_train[:, kpi_cols]
    X_val_kpi = X_val[:, kpi_cols]
    scaler_kpi = StandardScaler()
    X_train_kpi_scaled = scaler_kpi.fit_transform(X_train_kpi)
    X_val_kpi_scaled = scaler_kpi.transform(X_val_kpi)
    lr_kpi = LogisticRegression(max_iter=1000, random_state=42, multi_class='multinomial', solver='lbfgs', class_weight='balanced')
    lr_kpi.fit(X_train_kpi_scaled, y_train)
    kpi_train = lr_kpi.score(X_train_kpi_scaled, y_train)
    kpi_val = lr_kpi.score(X_val_kpi_scaled, y_val)

    # TF-IDF-only model
    X_train_tfidf = X_train[:, tfidf_cols]
    X_val_tfidf = X_val[:, tfidf_cols]
    scaler_tfidf = StandardScaler()
    X_train_tfidf_scaled = scaler_tfidf.fit_transform(X_train_tfidf)
    X_val_tfidf_scaled = scaler_tfidf.transform(X_val_tfidf)
    lr_tfidf = LogisticRegression(max_iter=1000, random_state=42, multi_class='multinomial', solver='lbfgs', class_weight='balanced')
    lr_tfidf.fit(X_train_tfidf_scaled, y_train)
    tfidf_train = lr_tfidf.score(X_train_tfidf_scaled, y_train)
    tfidf_val = lr_tfidf.score(X_val_tfidf_scaled, y_val)

    print("\nFeature Set Comparison:")
    print(f"{'Feature Set':<20} {'Train Acc':<15} {'Val Acc':<15} {'Gap':<10}")
    print("-" * 60)
    print(f"{'Combined (TF+KPI)':<20} {combined_train:.3f}       {combined_val:.3f}       {combined_train-combined_val:.3f}")
    print(f"{'KPI-only':<20} {kpi_train:.3f}       {kpi_val:.3f}       {kpi_train-kpi_val:.3f}")
    print(f"{'TF-IDF-only':<20} {tfidf_train:.3f}       {tfidf_val:.3f}       {tfidf_train-tfidf_val:.3f}")

    # Determine which has largest gap
    gaps = {
        'combined': combined_train - combined_val,
        'kpi': kpi_train - kpi_val,
        'tfidf': tfidf_train - tfidf_val,
    }
    worst_feature_set = max(gaps, key=gaps.get)
    print(f"\nLargest train/val gap: {worst_feature_set} ({gaps[worst_feature_set]:.3f})")

    # 3. Regularization sweep on worst feature set
    print("\n[3/3] Regularization Sweep (C parameter)")
    print("-" * 80)
    print(f"Testing on: {worst_feature_set} feature set\n")

    c_values = [0.01, 0.1, 1.0]

    if worst_feature_set == 'kpi':
        X_train_test = X_train_kpi_scaled
        X_val_test = X_val_kpi_scaled
        feature_name = "KPI-only"
    elif worst_feature_set == 'tfidf':
        X_train_test = X_train_tfidf_scaled
        X_val_test = X_val_tfidf_scaled
        feature_name = "TF-IDF-only"
    else:
        X_train_test = X_train_scaled
        X_val_test = X_val_scaled
        feature_name = "Combined"

    print(f"{'C':<10} {'Train Acc':<15} {'Val Acc':<15} {'Gap':<10}")
    print("-" * 50)

    for c in c_values:
        lr_c = LogisticRegression(C=c, max_iter=1000, random_state=42, multi_class='multinomial', solver='lbfgs', class_weight='balanced')
        lr_c.fit(X_train_test, y_train)
        c_train = lr_c.score(X_train_test, y_train)
        c_val = lr_c.score(X_val_test, y_val)
        c_gap = c_train - c_val
        print(f"{c:<10} {c_train:.3f}       {c_val:.3f}       {c_gap:.3f}")

    # 4. TF-IDF vocabulary overlap (if alert texts available)
    if alert_texts is not None and len(alert_texts) > 0:
        print("[4/4] TF-IDF Vocabulary Overlap (Train vs Validation)")
        print("-" * 80)

        # Fit TF-IDF on training text only to see vocabulary
        from sklearn.feature_extraction.text import TfidfVectorizer
        train_texts = [alert_texts[i] for i in range(len(alert_texts)) if i in train_indices] if train_indices is not None else alert_texts[:len(X_train)]

        tfidf_train = TfidfVectorizer(max_features=100, min_df=2, max_df=0.8)
        tfidf_train.fit(train_texts)
        vocab_size = len(tfidf_train.vocabulary_)

        print(f"\nTF-IDF Vocabulary size (from training texts): {vocab_size}")

        # Get validation texts and compute nonzero fractions
        val_texts = [alert_texts[i] for i in range(len(alert_texts)) if i in val_indices] if val_indices is not None else alert_texts[len(X_train):]

        nonzero_fractions = []
        for val_text in val_texts:
            # Transform to TF-IDF using training vocabulary
            val_vec = tfidf_train.transform([val_text]).toarray()
            nonzero_count = np.count_nonzero(val_vec)
            nonzero_fraction = nonzero_count / vocab_size
            nonzero_fractions.append(nonzero_fraction)

        nonzero_fractions = np.array(nonzero_fractions)

        print(f"\nValidation set vocabulary overlap:")
        print(f"  Average nonzero fraction: {nonzero_fractions.mean():.3f}")
        print(f"  Median: {np.median(nonzero_fractions):.3f}")
        print(f"  Min: {nonzero_fractions.min():.3f}")
        print(f"  Max: {nonzero_fractions.max():.3f}")

        # Show example alert texts side-by-side
        print(f"\nExample Alert Texts (Training vs Validation from same class):")
        print("-" * 80)

        # Find one class that appears in both train and val
        train_classes = np.unique(y_train)
        val_classes = np.unique(y_val)
        common_classes = np.intersect1d(train_classes, val_classes)

        if len(common_classes) > 0:
            example_class = common_classes[0]

            # Get 3 training examples
            train_mask = y_train == example_class
            train_example_indices = np.where(train_mask)[0][:3]

            # Get 3 validation examples
            val_mask = y_val == example_class
            val_example_indices = np.where(val_mask)[0][:3]

            print(f"\nClass: {example_class}")
            print(f"\n{'TRAINING EXAMPLES:':<50} {'VALIDATION EXAMPLES:':<50}")
            print("=" * 100)

            max_examples = max(len(train_example_indices), len(val_example_indices))
            for i in range(max_examples):
                train_text = ""
                val_text = ""

                if i < len(train_example_indices):
                    idx = train_example_indices[i]
                    # Map back to original indices
                    orig_idx = train_indices[idx] if train_indices is not None else idx
                    train_text = alert_texts[orig_idx][:47] if len(alert_texts[orig_idx]) > 47 else alert_texts[orig_idx]

                if i < len(val_example_indices):
                    idx = val_example_indices[i]
                    # Map back to original indices
                    orig_idx = val_indices[idx] if val_indices is not None else len(X_train) + idx
                    val_text = alert_texts[orig_idx][:47] if len(alert_texts[orig_idx]) > 47 else alert_texts[orig_idx]

                print(f"{train_text:<50} {val_text:<50}")

            print("\n[Full texts if needed: run with --save-texts flag to output full alert text corpus]")

    print("\n" + "="*80 + "\n")


def train_triage(
    features_path: str | Path = "features.parquet",
    output_dir: str | Path = "models",
    report_dir: str | Path = "docs",
    diagnostics: bool = False,
) -> None:
    """Train logistic regression + isotonic calibration on features.

    Args:
        features_path: Path to features.parquet from build_features.py
        output_dir: Directory to save trained model
        report_dir: Directory to save report and curve
        diagnostics: Run diagnostic checks (class dist, ablation, reg sweep)
    """
    output_dir = Path(output_dir)
    report_dir = Path(report_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading features from {features_path}...")
    features_path = Path(features_path)
    if features_path.suffix == '.parquet':
        df = pd.read_parquet(features_path)
    else:
        df = pd.read_csv(features_path)

    # Extract metadata before dropping columns
    y = df['root_cause_service'].values
    case_ids = df['case_id'].values
    alert_silent = df['alert_silent'].values
    alert_texts = df['alert_text'].values if 'alert_text' in df.columns else None

    # Select only numeric columns (drop metadata + alert text)
    cols_to_drop = ['case_id', 'root_cause_service', 'alert_silent']
    if 'alert_text' in df.columns:
        cols_to_drop.append('alert_text')
    df_numeric = df.drop(columns=cols_to_drop)
    # Ensure only numeric columns remain (defensive check)
    numeric_cols = df_numeric.select_dtypes(include=[np.number]).columns.tolist()
    X = df_numeric[numeric_cols].values

    print(f"Feature matrix: {X.shape}")
    print(f"Labels: {y.shape} (unique classes: {len(np.unique(y))})")
    print(f"Silent alerts: {alert_silent.sum()}/{len(alert_silent)}")

    # Split into train/validation (80/20), also get indices for diagnostics
    train_indices, val_indices, X_train, X_val, y_train, y_val = train_test_split(
        np.arange(len(y)), X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Run diagnostics if requested (before main training)
    if diagnostics:
        run_diagnostics(X, y, X_train, X_val, y_train, y_val,
                       alert_texts=alert_texts,
                       case_ids=case_ids,
                       train_indices=train_indices,
                       val_indices=val_indices,
                       numeric_cols=numeric_cols)

    print(f"\nTrain set: {X_train.shape}")
    print(f"Validation set: {X_val.shape}")

    # Standardize features
    print("\nStandardizing features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    # Train logistic regression
    print("Training logistic regression...")
    lr_model = LogisticRegression(
        max_iter=1000,
        random_state=42,
        multi_class='multinomial',
        solver='lbfgs',
        class_weight='balanced'
    )
    lr_model.fit(X_train_scaled, y_train)

    train_score = lr_model.score(X_train_scaled, y_train)
    val_score = lr_model.score(X_val_scaled, y_val)
    print(f"  Train accuracy: {train_score:.3f}")
    print(f"  Validation accuracy: {val_score:.3f}")

    # Get prediction probabilities on validation set
    val_probs = lr_model.predict_proba(X_val_scaled)
    print(f"  Probability shape: {val_probs.shape}")

    # Fit isotonic calibration (for binary: use max probability)
    print("\nFitting isotonic calibration...")
    # Use max probability as the score to calibrate
    val_scores = val_probs.max(axis=1)
    val_is_correct = (lr_model.predict(X_val_scaled) == y_val).astype(int)

    isotonic = IsotonicRegression(out_of_bounds='clip')
    isotonic.fit(val_scores, val_is_correct)

    # Apply calibration
    val_calibrated_probs = isotonic.predict(val_scores)

    print(f"  Uncalibrated max prob - min: {val_scores.min():.3f}, max: {val_scores.max():.3f}")
    print(f"  Calibrated probs - min: {val_calibrated_probs.min():.3f}, max: {val_calibrated_probs.max():.3f}")

    # Sweep tau for precision target of 0.95
    print("\nSweeping tau for 95% precision target...")
    tau_values = np.linspace(0.1, 0.95, 50)
    precision_values = []
    recall_values = []
    abstain_rates = []

    for tau in tau_values:
        # Abstain if max calibrated prob < tau
        confident_mask = val_calibrated_probs >= tau
        num_confident = confident_mask.sum()

        if num_confident == 0:
            precision_values.append(0.0)
            recall_values.append(0.0)
            abstain_rates.append(1.0)
            continue

        # Among confident predictions, compute precision
        confident_preds = lr_model.predict(X_val_scaled[confident_mask])
        confident_labels = y_val[confident_mask]
        correct = (confident_preds == confident_labels).sum()
        precision = correct / num_confident if num_confident > 0 else 0.0

        # Recall = correct / total
        recall = correct / len(y_val)

        abstain_rate = (1 - confident_mask.sum() / len(confident_mask))

        precision_values.append(precision)
        recall_values.append(recall)
        abstain_rates.append(abstain_rate)

    precision_values = np.array(precision_values)
    recall_values = np.array(recall_values)
    abstain_rates = np.array(abstain_rates)

    # Find tau closest to 95% precision
    valid_mask = precision_values > 0
    if valid_mask.sum() > 0:
        target_idx = np.argmin(np.abs(precision_values[valid_mask] - 0.95))
        target_tau_idx = np.where(valid_mask)[0][target_idx]
        target_tau = tau_values[target_tau_idx]
        target_precision = precision_values[target_tau_idx]
    else:
        target_tau = 0.5
        target_precision = 0.0

    print(f"  Best tau for 95% precision: {target_tau:.3f}")
    print(f"  Actual precision at tau: {target_precision:.3f}")
    print(f"  Recall at tau: {recall_values[target_tau_idx]:.3f}")
    print(f"  Abstain rate at tau: {abstain_rates[target_tau_idx]:.3f}")

    # Save precision-vs-tau curve to CSV
    curve_df = pd.DataFrame({
        'tau': tau_values,
        'precision': precision_values,
        'recall': recall_values,
        'abstain_rate': abstain_rates,
    })
    curve_path = report_dir / 'a7_precision_vs_tau.csv'
    curve_df.to_csv(curve_path, index=False)
    print(f"\n✅ Precision-vs-tau curve saved to {curve_path}")

    # Generate plot if matplotlib available
    if plt is not None:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

        # Precision vs tau
        ax1.plot(tau_values, precision_values, 'b-', linewidth=2, label='Precision')
        ax1.axhline(y=0.95, color='g', linestyle='--', label='95% target')
        ax1.axvline(x=target_tau, color='r', linestyle='--', label=f'Selected tau={target_tau:.3f}')
        ax1.set_xlabel('Tau (confidence threshold)')
        ax1.set_ylabel('Precision')
        ax1.set_title('Precision vs Confidence Threshold')
        ax1.legend()
        ax1.grid(True, alpha=0.3)

        # Recall vs abstain rate
        ax2.plot(tau_values, recall_values, 'g-', linewidth=2, label='Recall')
        ax2.plot(tau_values, 1 - abstain_rates, 'b-', linewidth=2, label='Confident Rate')
        ax2.axvline(x=target_tau, color='r', linestyle='--', label=f'Selected tau={target_tau:.3f}')
        ax2.set_xlabel('Tau (confidence threshold)')
        ax2.set_ylabel('Rate')
        ax2.set_title('Recall and Confident Rate vs Threshold')
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        plt.tight_layout()
        plot_path = report_dir / 'a7_precision_vs_tau.png'
        plt.savefig(plot_path, dpi=100)
        print(f"Plot saved to {plot_path}")
        plt.close()

    # Save model and calibrator
    model_path = output_dir / 'triage_lr_model.joblib'
    scaler_path = output_dir / 'triage_scaler.joblib'
    isotonic_path = output_dir / 'triage_isotonic.joblib'

    joblib.dump(lr_model, model_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(isotonic, isotonic_path)

    print(f"\n✅ Model saved:")
    print(f"  LR model: {model_path}")
    print(f"  Scaler: {scaler_path}")
    print(f"  Isotonic: {isotonic_path}")

    # Generate report
    report_path = report_dir / 'a7_triage_training_report.md'
    report_content = f"""# A7 Triage Model Training Report

## Dataset
- Total cases: {len(y)}
- Training cases: {len(y_train)} ({len(y_train)/len(y)*100:.1f}%)
- Validation cases: {len(y_val)} ({len(y_val)/len(y)*100:.1f}%)
- Feature dimension: {X.shape[1]}
- Unique classes: {len(np.unique(y))}
- Silent alerts: {alert_silent.sum()} ({alert_silent.sum()/len(alert_silent)*100:.1f}%)

## Model Performance
- Train accuracy: {train_score:.3f}
- Validation accuracy: {val_score:.3f}

## Calibration
- Isotonic regression fitted on validation set
- Uncalibrated prob range: [{val_scores.min():.3f}, {val_scores.max():.3f}]
- Calibrated prob range: [{val_calibrated_probs.min():.3f}, {val_calibrated_probs.max():.3f}]

## Tau Selection (95% Precision Target)
- Selected tau: {target_tau:.3f}
- Precision at tau: {target_precision:.3f}
- Recall at tau: {recall_values[target_tau_idx]:.3f}
- Abstain rate at tau: {abstain_rates[target_tau_idx]:.3f}

## Output Files
- Curve data: `a7_precision_vs_tau.csv`
- Plot: `a7_precision_vs_tau.png` (if matplotlib available)
- LR model: `../models/triage_lr_model.joblib`
- Scaler: `../models/triage_scaler.joblib`
- Isotonic calibrator: `../models/triage_isotonic.joblib`
"""

    with open(report_path, 'w') as f:
        f.write(report_content)

    print(f"Report saved to {report_path}")


def main():
    parser = argparse.ArgumentParser(description="Train triage model on extracted features")
    parser.add_argument("--features", default="features.parquet", help="Features parquet file")
    parser.add_argument("--output-dir", default="models", help="Model output directory")
    parser.add_argument("--report-dir", default="docs", help="Report output directory")
    parser.add_argument("--diagnostics", action="store_true", help="Run diagnostic checks (class dist, ablation, regularization)")
    args = parser.parse_args()

    try:
        train_triage(args.features, args.output_dir, args.report_dir, diagnostics=args.diagnostics)
    except Exception as e:
        print(f"\n❌ Training failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
