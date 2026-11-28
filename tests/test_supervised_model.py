"""
SentinelFlow-CTD — Tests: Supervised Classifier Model
======================================================

Tests for:
  - Model training (small synthetic data, confirms no crash)
  - Artifact save and reload
  - Evaluation metric structure
  - Simple prediction on unseen test samples

These tests run against a tiny synthetic dataset to be fast.
They do NOT use the real CIC-IDS2017 data.
"""

import json
import os
import sys
import tempfile

import numpy as np
import pandas as pd
import pytest
from sklearn.preprocessing import LabelEncoder

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from supervised.dataset_loader import CATEGORY_COL, SOURCE_FILE_COL, ORIGINAL_LABEL_COL
from supervised.label_mapping import ORDERED_CATEGORIES, map_label
from supervised.splitter import get_feature_columns, to_arrays
from supervised.preprocessing import build_pipeline, fit_pipeline, transform
from supervised.train import train, load_artifacts
from supervised.evaluate import evaluate


# ================================================================== #
# Helpers                                                             #
# ================================================================== #

FEATURE_COLS = [f"feat_{i}" for i in range(10)]

TRAIN_FILE = "Monday-WorkingHours.pcap_ISCX.csv"
TEST_FILE = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"


def _make_synthetic_df(n_per_class: int = 50, source_file: str = TRAIN_FILE):
    """Create a small synthetic DataFrame with realistic column names."""
    rng = np.random.default_rng(99)
    rows = []
    categories = ["BENIGN", "DOS_DDOS", "RECONNAISSANCE", "BRUTE_FORCE"]
    for cat in categories:
        for _ in range(n_per_class):
            row = {col: rng.uniform(0, 100) for col in FEATURE_COLS}
            row[ORIGINAL_LABEL_COL] = cat     # original label = category for synthetic data
            row[CATEGORY_COL] = cat
            row[SOURCE_FILE_COL] = source_file
            rows.append(row)
    return pd.DataFrame(rows)


def _build_split():
    df_train = _make_synthetic_df(n_per_class=60, source_file=TRAIN_FILE)
    df_test = _make_synthetic_df(n_per_class=20, source_file=TEST_FILE)
    return df_train, df_test, FEATURE_COLS


# ================================================================== #
# Training Tests                                                      #
# ================================================================== #

class TestTraining:

    def test_train_runs_without_error(self, tmp_path):
        df_train, df_test, feature_cols = _build_split()
        result = train(
            df_train=df_train,
            df_test=df_test,
            feature_cols=feature_cols,
            artifacts_dir=str(tmp_path),
            compare=True,
            verbose=False,
        )
        assert result.model is not None
        assert result.comparison_model is not None
        assert result.train_rows == len(df_train)
        assert result.test_rows == len(df_test)

    def test_version_directory_created(self, tmp_path):
        df_train, df_test, feature_cols = _build_split()
        result = train(
            df_train, df_test, feature_cols, str(tmp_path), compare=False, verbose=False
        )
        assert os.path.isdir(result.artifacts_dir)

    def test_all_required_artifacts_saved(self, tmp_path):
        df_train, df_test, feature_cols = _build_split()
        result = train(
            df_train, df_test, feature_cols, str(tmp_path), compare=False, verbose=False
        )
        required = [
            "model.joblib",
            "preprocessor.joblib",
            "label_encoder.joblib",
            "feature_names.json",
            "manifest.json",
        ]
        for fname in required:
            full_path = os.path.join(result.artifacts_dir, fname)
            assert os.path.exists(full_path), f"Missing artifact: {fname}"

    def test_manifest_contains_required_fields(self, tmp_path):
        df_train, df_test, feature_cols = _build_split()
        result = train(
            df_train, df_test, feature_cols, str(tmp_path), compare=False, verbose=False
        )
        manifest_path = os.path.join(result.artifacts_dir, "manifest.json")
        with open(manifest_path) as f:
            manifest = json.load(f)
        for key in ["version", "model_type", "feature_count", "label_classes",
                    "train_rows", "test_rows", "split_strategy", "timestamp_utc"]:
            assert key in manifest, f"Missing key in manifest: {key}"

    def test_latest_symlink_created(self, tmp_path):
        df_train, df_test, feature_cols = _build_split()
        train(df_train, df_test, feature_cols, str(tmp_path), compare=False, verbose=False)
        latest = os.path.join(str(tmp_path), "latest")
        assert os.path.islink(latest) or os.path.isdir(latest)

    def test_versions_increment(self, tmp_path):
        df_train, df_test, feature_cols = _build_split()
        r1 = train(df_train, df_test, feature_cols, str(tmp_path), compare=False, verbose=False)
        r2 = train(df_train, df_test, feature_cols, str(tmp_path), compare=False, verbose=False)
        assert r1.version != r2.version
        v1_num = int(r1.version[1:])
        v2_num = int(r2.version[1:])
        assert v2_num == v1_num + 1

    def test_no_compare_skips_lr(self, tmp_path):
        df_train, df_test, feature_cols = _build_split()
        result = train(
            df_train, df_test, feature_cols, str(tmp_path), compare=False, verbose=False
        )
        assert result.comparison_model is None
        assert not os.path.exists(
            os.path.join(result.artifacts_dir, "comparison_model_lr.joblib")
        )


# ================================================================== #
# Artifact Reload Tests                                               #
# ================================================================== #

class TestArtifactReload:

    def test_reload_produces_same_predictions(self, tmp_path):
        df_train, df_test, feature_cols = _build_split()
        result = train(
            df_train, df_test, feature_cols, str(tmp_path), compare=False, verbose=False
        )

        # Prepare test features with the FITTED preprocessor
        X_test_raw, y_test_raw = to_arrays(df_test, feature_cols)
        known_mask = y_test_raw.isin(result.label_encoder.classes_)
        X_test_raw = X_test_raw[known_mask]
        X_test = transform(result.preprocessor, X_test_raw.values)

        original_preds = result.model.predict(X_test)

        # Reload artifacts and predict again
        loaded = load_artifacts(str(tmp_path), version=result.version)
        reloaded_preds = loaded["model"].predict(X_test)

        np.testing.assert_array_equal(
            original_preds, reloaded_preds,
            err_msg="Reloaded model produces different predictions"
        )

    def test_reload_feature_names_match(self, tmp_path):
        df_train, df_test, feature_cols = _build_split()
        result = train(
            df_train, df_test, feature_cols, str(tmp_path), compare=False, verbose=False
        )
        loaded = load_artifacts(str(tmp_path), version=result.version)
        assert loaded["feature_names"] == feature_cols

    def test_reload_label_encoder_matches(self, tmp_path):
        df_train, df_test, feature_cols = _build_split()
        result = train(
            df_train, df_test, feature_cols, str(tmp_path), compare=False, verbose=False
        )
        loaded = load_artifacts(str(tmp_path), version=result.version)
        assert list(loaded["label_encoder"].classes_) == list(result.label_encoder.classes_)

    def test_load_latest_works(self, tmp_path):
        df_train, df_test, feature_cols = _build_split()
        result = train(
            df_train, df_test, feature_cols, str(tmp_path), compare=False, verbose=False
        )
        loaded = load_artifacts(str(tmp_path), version="latest")
        assert loaded["version"] == result.version


# ================================================================== #
# Evaluation Tests                                                    #
# ================================================================== #

class TestEvaluation:

    def _run_eval(self, tmp_path):
        df_train, df_test, feature_cols = _build_split()
        result = train(
            df_train, df_test, feature_cols, str(tmp_path), compare=True, verbose=False
        )
        X_test_raw, y_test_raw = to_arrays(df_test, feature_cols)
        known_mask = y_test_raw.isin(result.label_encoder.classes_)
        X_test_raw = X_test_raw[known_mask]
        y_test_raw = y_test_raw[known_mask]
        X_test = transform(result.preprocessor, X_test_raw.values)
        y_test = result.label_encoder.transform(y_test_raw)
        report = evaluate(
            model=result.model,
            preprocessor=result.preprocessor,
            label_encoder=result.label_encoder,
            X_test=X_test,
            y_test_encoded=y_test,
            version_dir=result.artifacts_dir,
            comparison_model=result.comparison_model,
            feature_names=feature_cols,
            verbose=False,
        )
        return report, result

    def test_evaluation_report_contains_required_metrics(self, tmp_path):
        report, _ = self._run_eval(tmp_path)
        rf = report["random_forest"]
        for key in ["accuracy", "balanced_accuracy", "macro_f1", "weighted_f1",
                    "macro_precision", "macro_recall", "per_class_report",
                    "confusion_matrix", "confusion_matrix_normalised", "weak_classes"]:
            assert key in rf, f"Missing metric in report: {key}"

    def test_metrics_are_in_valid_range(self, tmp_path):
        report, _ = self._run_eval(tmp_path)
        rf = report["random_forest"]
        for metric in ["accuracy", "balanced_accuracy", "macro_f1",
                       "weighted_f1", "macro_precision", "macro_recall"]:
            val = rf[metric]
            assert 0.0 <= val <= 1.0, f"Metric {metric} out of range: {val}"

    def test_comparison_model_metrics_present(self, tmp_path):
        report, _ = self._run_eval(tmp_path)
        assert report["logistic_regression"] is not None
        lr = report["logistic_regression"]
        assert "macro_f1" in lr
        assert 0.0 <= lr["macro_f1"] <= 1.0

    def test_evaluation_report_saved_to_disk(self, tmp_path):
        report, result = self._run_eval(tmp_path)
        report_path = os.path.join(result.artifacts_dir, "evaluation_report.json")
        assert os.path.exists(report_path)
        with open(report_path) as f:
            loaded_report = json.load(f)
        assert "random_forest" in loaded_report

    def test_confusion_matrix_shape(self, tmp_path):
        report, result = self._run_eval(tmp_path)
        rf = report["random_forest"]
        n_classes = len(result.label_encoder.classes_)
        cm = rf["confusion_matrix"]
        assert len(cm) == n_classes
        assert all(len(row) == n_classes for row in cm)

    def test_feature_importances_saved(self, tmp_path):
        report, _ = self._run_eval(tmp_path)
        fi = report.get("top_30_feature_importances")
        assert fi is not None
        assert len(fi) > 0
        assert "feature" in fi[0]
        assert "importance" in fi[0]
        # Importances sum to approximately 1
        total = sum(x["importance"] for x in fi)
        assert 0.5 <= total <= 1.01  # may be < 1.0 if truncated to top 30


# ================================================================== #
# Prediction on Unseen Samples                                        #
# ================================================================== #

class TestPredictionOnUnseenSamples:

    def test_predict_returns_known_category(self, tmp_path):
        df_train, df_test, feature_cols = _build_split()
        result = train(
            df_train, df_test, feature_cols, str(tmp_path), compare=False, verbose=False
        )

        # Create 5 genuinely unseen samples (different seed)
        rng = np.random.default_rng(777)
        X_unseen = rng.uniform(0, 100, size=(5, len(feature_cols)))

        X_preprocessed = transform(result.preprocessor, X_unseen)
        raw_preds = result.model.predict(X_preprocessed)
        preds = result.label_encoder.inverse_transform(raw_preds)

        for pred in preds:
            assert pred in result.label_encoder.classes_, (
                f"Model predicted unknown category: {pred}"
            )

    def test_predict_proba_returns_valid_probabilities(self, tmp_path):
        df_train, df_test, feature_cols = _build_split()
        result = train(
            df_train, df_test, feature_cols, str(tmp_path), compare=False, verbose=False
        )

        rng = np.random.default_rng(555)
        X_unseen = rng.uniform(0, 100, size=(5, len(feature_cols)))
        X_preprocessed = transform(result.preprocessor, X_unseen)

        probs = result.model.predict_proba(X_preprocessed)
        assert probs.shape[0] == 5
        assert probs.shape[1] == len(result.label_encoder.classes_)
        # Each row must sum to approximately 1.0
        row_sums = probs.sum(axis=1)
        np.testing.assert_allclose(row_sums, 1.0, atol=1e-5)

    def test_confidence_threshold_filtering(self, tmp_path):
        """A threshold no probability can reach marks every row UNCLASSIFIED."""
        from supervised.label_mapping import UNKNOWN_CATEGORY
        from supervised.predict import classify_features

        df_train, df_test, feature_cols = _build_split()
        result = train(
            df_train, df_test, feature_cols, str(tmp_path), compare=False, verbose=False
        )

        rng = np.random.default_rng(42)
        X_unseen = rng.uniform(0, 100, size=(10, len(feature_cols)))
        classified = classify_features(
            model=result.model,
            preprocessor=result.preprocessor,
            label_encoder=result.label_encoder,
            X=X_unseen,
            threshold=1.01,
        )

        assert len(classified) == 10
        for item in classified:
            assert item["predicted_threat"] == UNKNOWN_CATEGORY
            assert item["classification_status"] == "unclassified"
            assert item["model_prediction"] in result.label_encoder.classes_
            assert 0.0 <= item["confidence"] <= 1.0
            assert item["alternative_predictions"]
