"""
SentinelFlow-CTD — Supervised Classifier: Model Training
=========================================================

Trains a Random Forest multiclass classifier on the preprocessed
CIC-IDS2017 dataset, optionally compares it with a LogisticRegression
baseline, and saves all versioned artifacts.

Design decisions
----------------
- Random Forest is the primary classifier. It handles class imbalance via
  class_weight='balanced', is robust to unscaled features (but we scale
  anyway for consistency with future model comparisons), and provides
  per-class probability estimates used for the UNCLASSIFIED threshold.
- Logistic Regression is the comparison baseline. It is fast to train and
  provides a useful sanity check on feature linearity.
- All artifacts (model, preprocessor, label encoder, feature list, manifest)
  are saved together under a versioned directory (artifacts/v<N>/). A
  'latest' symlink is updated after each successful training run.
- Random seed 42 is used throughout for reproducibility.
- The test set is NEVER touched during training or hyperparameter selection.
- On the full CIC-IDS2017 training set, each tree uses a 100,000-row
  sample and a depth cap. That keeps the forest small enough to train
  on a workstation. The held-out test set is still scored in full.

Public API
----------
  train(df_train, df_test, feature_cols, artifacts_dir, compare=True)
    -> TrainingResult dataclass
"""

import gc
import json
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder

from supervised.dataset_loader import CATEGORY_COL, SOURCE_FILE_COL
from supervised.label_mapping import ORDERED_CATEGORIES
from supervised.preprocessing import build_pipeline, fit_pipeline, transform
from supervised.splitter import get_feature_columns, to_arrays

RANDOM_STATE = 42


# ------------------------------------------------------------------ #
# Training result container                                           #
# ------------------------------------------------------------------ #

@dataclass
class TrainingResult:
    """Everything produced by a training run."""
    version: str
    artifacts_dir: str
    feature_cols: List[str]
    label_encoder: LabelEncoder
    preprocessor: object          # fitted sklearn Pipeline
    model: object                 # fitted RandomForestClassifier
    comparison_model: Optional[object]   # fitted LogisticRegression or None
    train_rows: int
    test_rows: int
    training_time_s: float
    model_params: Dict
    comparison_model_params: Optional[Dict]


# ------------------------------------------------------------------ #
# Versioning helpers                                                  #
# ------------------------------------------------------------------ #

def _next_version(artifacts_dir: str) -> str:
    """Return the next version string (e.g. 'v3') based on existing dirs."""
    existing = [
        d for d in os.listdir(artifacts_dir)
        if os.path.isdir(os.path.join(artifacts_dir, d))
        and d.startswith("v")
        and d[1:].isdigit()
    ]
    if not existing:
        return "v1"
    max_v = max(int(d[1:]) for d in existing)
    return f"v{max_v + 1}"


def _update_latest_symlink(artifacts_dir: str, version: str):
    """Update 'latest' to point to the new version directory."""
    latest = os.path.join(artifacts_dir, "latest")
    if os.path.islink(latest) or os.path.exists(latest):
        os.remove(latest)
    os.symlink(version, latest)


# ------------------------------------------------------------------ #
# Main training function                                              #
# ------------------------------------------------------------------ #

def train(
    df_train: pd.DataFrame,
    df_test: pd.DataFrame,
    feature_cols: List[str],
    artifacts_dir: str,
    compare: bool = True,
    rf_params: Optional[Dict] = None,
    lr_params: Optional[Dict] = None,
    verbose: bool = True,
) -> TrainingResult:
    """
    Train the supervised threat classifier.

    Parameters
    ----------
    df_train      : training DataFrame (from splitter.split_dataset)
    df_test       : test DataFrame     (from splitter.split_dataset)
    feature_cols  : ordered list of feature column names (from splitter.get_feature_columns)
    artifacts_dir : root directory where versioned artifacts will be saved
    compare       : if True, also train a LogisticRegression for comparison
    rf_params     : optional dict of RandomForestClassifier kwargs (overrides defaults)
    lr_params     : optional dict of LogisticRegression kwargs (overrides defaults)
    verbose       : print progress

    Returns
    -------
    TrainingResult with all artifacts and metadata.
    """
    os.makedirs(artifacts_dir, exist_ok=True)
    version = _next_version(artifacts_dir)
    version_dir = os.path.join(artifacts_dir, version)
    os.makedirs(version_dir, exist_ok=True)

    if verbose:
        print(f"\n[train] Starting training — artifact version: {version}")
        print(f"  Artifacts will be saved to: {version_dir}")

    # ---- Extract arrays ------------------------------------------ #
    # No extra copy: the caller still holds df_train and df_test.
    X_train_raw, y_train_raw = to_arrays(df_train, feature_cols, copy=False)
    X_test_raw, y_test_raw = to_arrays(df_test, feature_cols, copy=False)

    if verbose:
        print(f"  Train rows: {len(X_train_raw):,}  |  Test rows: {len(X_test_raw):,}")

    # ---- Label encoding ------------------------------------------ #
    # Use the fixed ORDERED_CATEGORIES list so the encoding is deterministic
    # and stable across training runs even if a category is absent from one
    # day's data.
    le = LabelEncoder()
    # Fit on the canonical category list (not just what's in the training set)
    # so the integer mapping is always consistent.
    present_in_train = sorted(y_train_raw.unique())
    all_known = [c for c in ORDERED_CATEGORIES if c in present_in_train]
    # Also include any present-in-train categories not in ORDERED_CATEGORIES
    # (should not happen, but be safe).
    extra = [c for c in present_in_train if c not in ORDERED_CATEGORIES]
    le.fit(all_known + extra)

    y_train = le.transform(y_train_raw)
    # For the test set, only encode classes the encoder knows about.
    # Unknown test-set labels (should not occur) are excluded.
    test_known_mask = y_test_raw.isin(le.classes_)
    if not test_known_mask.all():
        unknown_in_test = y_test_raw[~test_known_mask].unique().tolist()
        if verbose:
            print(f"  WARNING: test set contains unknown categories: {unknown_in_test}")
        X_test_raw = X_test_raw[test_known_mask]
        y_test_raw = y_test_raw[test_known_mask]

    y_test = le.transform(y_test_raw)

    if verbose:
        print(f"  Label encoder classes: {list(le.classes_)}")

    # ---- Preprocessing ------------------------------------------- #
    # fit_pipeline returns the fitted pipeline, not the transformed matrix.
    # Transformations are applied afterwards, and only after the fit, so the
    # test set cannot influence medians or scaling.
    if verbose:
        print("  Fitting preprocessor on training data ...")

    preprocessor = build_pipeline()
    fit_pipeline(preprocessor, X_train_raw.to_numpy(copy=False))
    X_train = transform(preprocessor, X_train_raw.to_numpy(copy=False))
    # The test matrix is transformed later, during evaluation. Doing it
    # here would keep a second full copy alive through training.
    test_rows = int(len(X_test_raw))
    del X_train_raw, X_test_raw
    gc.collect()

    if verbose:
        print(f"  Preprocessor fitted. X_train shape: {X_train.shape}")

    # ---- Compute class weights ------------------------------------ #
    # We pass sample_weight to handle extreme imbalance. class_weight='balanced'
    # lets sklearn compute this automatically.
    # Full-depth trees on the whole CIC-IDS2017 training set (about 2 million
    # flows) use more memory than a laptop can spare. Above 100k training
    # rows, each tree sees a 100k-row sample and depth is capped. Small
    # datasets, including the unit tests, still train on every row.
    default_rf_params = {
        "n_estimators": 80,
        "max_depth": None,
        "min_samples_leaf": 2,
        "class_weight": "balanced_subsample",
        "n_jobs": -1,
        "random_state": RANDOM_STATE,
        "verbose": 0,
    }
    if len(y_train) > 100_000:
        default_rf_params["max_samples"] = 100_000
        default_rf_params["max_depth"] = 24
        default_rf_params["min_samples_leaf"] = 4
        # Each worker receives its own copy of the training matrix.
        # Two workers is the most that fits beside the dataset on 8 GB.
        default_rf_params["n_jobs"] = 2
    if rf_params:
        default_rf_params.update(rf_params)

    # ---- Train Random Forest ------------------------------------- #
    if verbose:
        print(f"  Training RandomForestClassifier (n_estimators={default_rf_params['n_estimators']}) ...")

    t0 = time.time()
    rf = RandomForestClassifier(**default_rf_params)
    rf.fit(X_train, y_train)
    rf_time = time.time() - t0

    if verbose:
        print(f"  RF training complete in {rf_time:.1f}s")

    # ---- Train comparison model ---------------------------------- #
    comparison_model = None
    comparison_params = None
    if compare:
        # scikit-learn 1.8+ removed the multi_class argument. Logistic
        # regression is multinomial for more than two classes by default.
        # n_jobs is omitted: since scikit-learn 1.8 it has no effect for
        # lbfgs and warns that it will be removed.
        default_lr_params = {
            "max_iter": 400,
            "class_weight": "balanced",
            "solver": "lbfgs",
            "random_state": RANDOM_STATE,
            "C": 1.0,
        }
        if lr_params:
            default_lr_params.update(lr_params)

        if verbose:
            print(f"  Training LogisticRegression (comparison) ...")

        t1 = time.time()
        lr = LogisticRegression(**default_lr_params)
        lr.fit(X_train, y_train)
        lr_time = time.time() - t1
        comparison_model = lr
        comparison_params = default_lr_params
        if verbose:
            print(f"  LR training complete in {lr_time:.1f}s")

    total_time = time.time() - t0

    # ---- Save artifacts ------------------------------------------ #
    _save_artifacts(
        version_dir=version_dir,
        version=version,
        rf=rf,
        preprocessor=preprocessor,
        label_encoder=le,
        feature_cols=feature_cols,
        rf_params=default_rf_params,
        comparison_model=comparison_model,
        comparison_params=comparison_params,
        train_rows=len(X_train),
        test_rows=test_rows,
        training_time_s=total_time,
    )

    _update_latest_symlink(artifacts_dir, version)

    if verbose:
        print(f"  Artifacts saved to: {version_dir}")
        print(f"  'latest' symlink updated -> {version}")

    return TrainingResult(
        version=version,
        artifacts_dir=version_dir,
        feature_cols=feature_cols,
        label_encoder=le,
        preprocessor=preprocessor,
        model=rf,
        comparison_model=comparison_model,
        train_rows=len(X_train),
        test_rows=test_rows,
        training_time_s=total_time,
        model_params=default_rf_params,
        comparison_model_params=comparison_params,
    )


# ------------------------------------------------------------------ #
# Artifact saving                                                     #
# ------------------------------------------------------------------ #

def _save_artifacts(
    version_dir: str,
    version: str,
    rf,
    preprocessor,
    label_encoder: LabelEncoder,
    feature_cols: List[str],
    rf_params: Dict,
    comparison_model,
    comparison_params: Optional[Dict],
    train_rows: int,
    test_rows: int,
    training_time_s: float,
):
    """Save all versioned artifacts to version_dir."""

    # Model
    joblib.dump(rf, os.path.join(version_dir, "model.joblib"))

    # Preprocessor
    joblib.dump(preprocessor, os.path.join(version_dir, "preprocessor.joblib"))

    # Label encoder
    joblib.dump(label_encoder, os.path.join(version_dir, "label_encoder.joblib"))

    # Feature list (ordered)
    with open(os.path.join(version_dir, "feature_names.json"), "w") as f:
        json.dump({"features": feature_cols, "count": len(feature_cols)}, f, indent=2)

    # Comparison model (if present)
    if comparison_model is not None:
        joblib.dump(
            comparison_model,
            os.path.join(version_dir, "comparison_model_lr.joblib"),
        )

    # Training manifest
    rf_params_serializable = {
        k: v for k, v in rf_params.items() if isinstance(v, (str, int, float, bool, type(None)))
    }
    manifest = {
        "version": version,
        "schema_version": "1.0",
        "model_type": "RandomForestClassifier",
        "comparison_model_type": "LogisticRegression" if comparison_model else None,
        "dataset": "CIC-IDS2017",
        "feature_count": len(feature_cols),
        "label_classes": list(label_encoder.classes_),
        "train_rows": train_rows,
        "test_rows": test_rows,
        "training_time_s": round(training_time_s, 2),
        "rf_params": rf_params_serializable,
        "comparison_params": {
            k: v for k, v in (comparison_params or {}).items()
            if isinstance(v, (str, int, float, bool, type(None)))
        },
        "preprocessing": "SimpleImputer(median) + RobustScaler",
        "class_imbalance_handling": (
            "RandomForest class_weight='balanced_subsample'; "
            "LogisticRegression class_weight='balanced'. No oversampling."
        ),
        "split_strategy": "per_label_capture_order_holdout",
        "training_notes": (
            "Preprocessor is fit on training rows only. "
            "Features are float32. When the training set is larger than "
            "100,000 rows, each random forest tree is grown on a 100,000-row "
            "sample with max_depth 24, using two workers, so the model fits "
            "in 8 GB of memory. Evaluation still uses the full held-out test "
            "set. Logistic regression is the linear comparison model and "
            "sees every training row."
        ),
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    with open(os.path.join(version_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)


# ------------------------------------------------------------------ #
# Artifact loading                                                    #
# ------------------------------------------------------------------ #

def load_artifacts(artifacts_dir: str, version: str = "latest") -> Dict:
    """
    Load a versioned set of training artifacts from disk.

    Parameters
    ----------
    artifacts_dir : root artifacts directory
    version       : version string (e.g. 'v1') or 'latest'

    Returns
    -------
    dict with keys: model, preprocessor, label_encoder, feature_names,
                    manifest, comparison_model (or None)
    """
    if version == "latest":
        latest_link = os.path.join(artifacts_dir, "latest")
        if os.path.islink(latest_link):
            version = os.readlink(latest_link)
        else:
            # Fall back: pick the highest numbered version
            versions = sorted(
                d for d in os.listdir(artifacts_dir)
                if os.path.isdir(os.path.join(artifacts_dir, d))
                and d.startswith("v") and d[1:].isdigit()
            )
            if not versions:
                raise FileNotFoundError(f"No versioned artifacts found in {artifacts_dir}")
            version = versions[-1]

    version_dir = os.path.join(artifacts_dir, version)
    if not os.path.isdir(version_dir):
        raise FileNotFoundError(f"Artifact version directory not found: {version_dir}")

    model_path = os.path.join(version_dir, "model.joblib")
    preprocessor_path = os.path.join(version_dir, "preprocessor.joblib")
    le_path = os.path.join(version_dir, "label_encoder.joblib")
    features_path = os.path.join(version_dir, "feature_names.json")
    manifest_path = os.path.join(version_dir, "manifest.json")
    comparison_path = os.path.join(version_dir, "comparison_model_lr.joblib")

    for required in [model_path, preprocessor_path, le_path, features_path, manifest_path]:
        if not os.path.exists(required):
            raise FileNotFoundError(f"Required artifact not found: {required}")

    model = joblib.load(model_path)
    preprocessor = joblib.load(preprocessor_path)
    label_encoder = joblib.load(le_path)

    with open(features_path) as f:
        feature_data = json.load(f)
    with open(manifest_path) as f:
        manifest = json.load(f)

    comparison_model = None
    if os.path.exists(comparison_path):
        comparison_model = joblib.load(comparison_path)

    return {
        "version": version,
        "version_dir": version_dir,
        "model": model,
        "preprocessor": preprocessor,
        "label_encoder": label_encoder,
        "feature_names": feature_data["features"],
        "manifest": manifest,
        "comparison_model": comparison_model,
    }
