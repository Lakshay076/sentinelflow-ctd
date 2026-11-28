"""
SentinelFlow-CTD — Supervised Classifier: Training Entrypoint
==============================================================

Run this script to execute the full Phase 1 pipeline:

  1. Load the CIC-IDS2017 dataset.
  2. Apply label mapping and cleaning.
  3. Split into training and test sets (per-label capture-order holdout).
  4. Fit the preprocessing pipeline on training data.
  5. Train Random Forest and Logistic Regression.
  6. Evaluate on the test set.
  7. Save all versioned artifacts.
  8. Save reports.

Usage
-----
  cd sentinelflow-ctd
  source .venv/bin/activate
  python -m supervised.run_training

  # With options:
  python -m supervised.run_training --data-dir data/cic_ids2017/raw/MachineLearningCSV
  python -m supervised.run_training --no-compare   # skip LR comparison
  python -m supervised.run_training --dry-run      # load only, no training

Output
------
  supervised/artifacts/<version>/
    model.joblib
    preprocessor.joblib
    label_encoder.joblib
    feature_names.json
    manifest.json
    evaluation_report.json
    comparison_model_lr.joblib   (if --compare)
  supervised/reports/
    dataset_report.json
    split_report.json
    cleaning_report.json
"""

import argparse
import gc
import json
import os
import sys

# Ensure project root is on the path when run as __main__
if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from supervised.dataset_loader import load_dataset, build_cleaning_report
from supervised.splitter import split_dataset, get_feature_columns, to_arrays
from supervised.preprocessing import transform
from supervised.train import train, load_artifacts
from supervised.evaluate import evaluate
from supervised.predict import classify_features

DEFAULT_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "cic_ids2017", "raw", "MachineLearningCSV",
)

DEFAULT_ARTIFACTS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "artifacts"
)

DEFAULT_REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "reports"
)


def main():
    parser = argparse.ArgumentParser(
        description="SentinelFlow-CTD: Supervised Classifier Training Pipeline"
    )
    parser.add_argument(
        "--data-dir",
        default=DEFAULT_DATA_DIR,
        help="Path to CIC-IDS2017 MachineLearningCSV directory",
    )
    parser.add_argument(
        "--artifacts-dir",
        default=DEFAULT_ARTIFACTS_DIR,
        help="Root directory for versioned model artifacts",
    )
    parser.add_argument(
        "--reports-dir",
        default=DEFAULT_REPORTS_DIR,
        help="Directory to save dataset and split reports",
    )
    parser.add_argument(
        "--no-compare",
        action="store_true",
        help="Skip LogisticRegression comparison (faster)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Load and report on the dataset only; do not train",
    )
    parser.add_argument(
        "--chunksize",
        type=int,
        default=100_000,
        help="Rows per chunk when reading CSV files (default 100000)",
    )
    args = parser.parse_args()

    os.makedirs(args.reports_dir, exist_ok=True)

    print("=" * 65)
    print("SentinelFlow-CTD — Supervised Classifier Training Pipeline")
    print("=" * 65)

    # ---------------------------------------------------------------- #
    # Step 1: Load dataset                                              #
    # ---------------------------------------------------------------- #
    print(f"\n[Step 1] Loading dataset from: {args.data_dir}")
    df, load_report = load_dataset(args.data_dir, chunksize=args.chunksize, verbose=True)

    # Save load report
    report_path = os.path.join(args.reports_dir, "dataset_report.json")
    with open(report_path, "w") as f:
        # Convert non-serializable values
        safe_report = _make_serializable(load_report)
        json.dump(safe_report, f, indent=2)
    print(f"  Dataset report saved: {report_path}")

    # ---------------------------------------------------------------- #
    # Step 2: Describe / cleaning report                                #
    # ---------------------------------------------------------------- #
    print("\n[Step 2] Computing cleaning statistics ...")
    cleaning = build_cleaning_report(df, load_report)
    cleaning_path = os.path.join(args.reports_dir, "cleaning_report.json")
    with open(cleaning_path, "w") as f:
        json.dump(_make_serializable(cleaning), f, indent=2)
    print(f"  Cleaning report saved: {cleaning_path}")

    print(f"\n  Rows raw                  : {cleaning['rows_raw']:,}")
    print(f"  Rows after cleaning       : {cleaning['rows_after_cleaning']:,}")
    print(f"  Duplicate rows removed    : {cleaning['duplicate_rows_removed']:,}")
    print(f"  Duplicate columns removed : {cleaning['duplicate_columns_removed']}")
    print(f"  Infinite values           : {cleaning['infinite_values_replaced_with_nan']:,}")
    print(f"  Invalid numeric values    : {cleaning['invalid_numeric_values']:,}")
    print(f"  Feature columns           : {cleaning['feature_count']}")
    print(f"  Constant columns kept     : {len(cleaning['constant_columns_kept'])}")
    print(f"\n  Category distribution:")
    category_counts = load_report["category_distribution"]
    total_rows = max(cleaning["rows_after_cleaning"], 1)
    for cat, cnt in sorted(category_counts.items(), key=lambda x: -x[1]):
        pct = 100 * cnt / total_rows
        print(f"    {cat:20s}: {cnt:>10,}  ({pct:5.1f}%)")

    print(f"\n  Original label mapping:")
    for entry in load_report["label_mapping"]["original_labels"]:
        mapped = entry.get("mapped_to") or "--- UNMAPPED ---"
        print(f"    {entry['label']:45s} -> {mapped:20s}  ({entry['count']:,} rows)")

    unmapped = load_report["label_mapping"]["unmapped_labels"]
    if unmapped:
        print(f"\n  ⚠ UNMAPPED LABELS ({len(unmapped)}):")
        for u in unmapped:
            print(f"    '{u['label']}': {u['count']:,} rows")
    else:
        print("\n  ✓ All labels successfully mapped.")

    if args.dry_run:
        print("\n[dry-run] Stopping here — no training performed.")
        return

    # ---------------------------------------------------------------- #
    # Step 3: Split                                                     #
    # ---------------------------------------------------------------- #
    print("\n[Step 3] Splitting dataset (per-label capture-order holdout) ...")
    df_train, df_test, split_report = split_dataset(df)
    # The combined frame is no longer needed. Dropping it keeps the
    # training step from holding two full copies of the dataset.
    del df
    gc.collect()

    split_path = os.path.join(args.reports_dir, "split_report.json")
    with open(split_path, "w") as f:
        json.dump(_make_serializable(split_report), f, indent=2)
    print(f"  Split report saved: {split_path}")
    print(f"  Train: {split_report['train_rows']:,} rows ({split_report['train_pct']}%)")
    print(f"  Test : {split_report['test_rows']:,} rows ({split_report['test_pct']}%)")
    print(
        "  Exact train copies removed from test: "
        f"{split_report['test_rows_removed_as_exact_train_copies']:,}"
    )
    print(f"  {split_report['description']}")

    # ---------------------------------------------------------------- #
    # Step 4–5: Train                                                   #
    # ---------------------------------------------------------------- #
    print("\n[Step 4–5] Training classifier ...")
    feature_cols = get_feature_columns(df_train)
    print(f"  Feature columns: {len(feature_cols)}")

    result = train(
        df_train=df_train,
        df_test=df_test,
        feature_cols=feature_cols,
        artifacts_dir=args.artifacts_dir,
        compare=not args.no_compare,
        verbose=True,
    )

    # ---------------------------------------------------------------- #
    # Step 6: Evaluate                                                  #
    # ---------------------------------------------------------------- #
    print("\n[Step 6] Evaluating on test set ...")

    # Re-prepare test arrays using the FITTED preprocessor
    X_test_raw, y_test_raw = to_arrays(df_test, feature_cols)

    # Align test labels to encoder's known classes
    known_mask = y_test_raw.isin(result.label_encoder.classes_)
    X_test_raw = X_test_raw[known_mask]
    y_test_raw = y_test_raw[known_mask]

    X_test_preprocessed = transform(result.preprocessor, X_test_raw.values)
    y_test_encoded = result.label_encoder.transform(y_test_raw)

    eval_report = evaluate(
        model=result.model,
        preprocessor=result.preprocessor,
        label_encoder=result.label_encoder,
        X_test=X_test_preprocessed,
        y_test_encoded=y_test_encoded,
        version_dir=result.artifacts_dir,
        comparison_model=result.comparison_model,
        feature_names=feature_cols,
        verbose=True,
    )

    # ---------------------------------------------------------------- #
    # Step 7: Verify artifacts can be reloaded                         #
    # ---------------------------------------------------------------- #
    print("\n[Step 7] Verifying artifact reload ...")
    loaded = load_artifacts(args.artifacts_dir, version=result.version)
    # Predict from the raw test rows so this also checks preprocessing reload.
    sample_raw = X_test_raw.iloc[:5]
    sample_results = classify_features(
        model=loaded["model"],
        preprocessor=loaded["preprocessor"],
        label_encoder=loaded["label_encoder"],
        X=sample_raw.values,
    )
    print("  Sample predictions from reloaded model:")
    for item in sample_results:
        print(
            f"    {item['predicted_threat']:20s}  "
            f"confidence={item['confidence']:.3f}  "
            f"status={item['classification_status']}"
        )
    print("  ✓ Artifact reload verified.")

    print("\n" + "=" * 65)
    print("Phase 1 Training Complete")
    print("=" * 65)
    print(f"  Version            : {result.version}")
    print(f"  Artifacts          : {result.artifacts_dir}")
    print(f"  Macro F1 (RF)      : {eval_report['random_forest']['macro_f1']:.4f}")
    print(f"  Balanced accuracy  : {eval_report['random_forest']['balanced_accuracy']:.4f}")
    if eval_report.get("logistic_regression"):
        print(f"  Macro F1 (LR)      : {eval_report['logistic_regression']['macro_f1']:.4f}")
    print("=" * 65)


def _make_serializable(obj):
    """Recursively convert numpy types to Python native types for JSON."""
    if isinstance(obj, dict):
        return {k: _make_serializable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_make_serializable(v) for v in obj]
    if hasattr(obj, "item"):      # numpy scalar
        return obj.item()
    if hasattr(obj, "tolist"):    # numpy array
        return obj.tolist()
    return obj


if __name__ == "__main__":
    main()
