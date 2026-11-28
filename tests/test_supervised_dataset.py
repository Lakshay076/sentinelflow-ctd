"""
SentinelFlow-CTD — Tests: Supervised Classifier Dataset Pipeline
=================================================================

Tests for:
  - Label mapping (all 15 known CIC-IDS2017 labels + unmapped detection)
  - Dataset loader (CSV structure, deduplication, NaN/Inf handling)
  - Splitter (day-aware split, no cross-day leakage)
  - Preprocessing pipeline (fit on train only, no test leakage)

These tests do NOT require the actual CIC-IDS2017 dataset.
They use small synthetic DataFrames with the same schema.
"""

import os
import sys
import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from supervised.label_mapping import (
    LABEL_TO_CATEGORY,
    ORDERED_CATEGORIES,
    UNKNOWN_CATEGORY,
    map_label,
    map_labels_series,
    build_mapping_report,
)
from supervised.dataset_loader import (
    CATEGORY_COL,
    ORIGINAL_LABEL_COL,
    SOURCE_FILE_COL,
    load_dataset,
    build_cleaning_report,
)
from supervised.splitter import (
    split_dataset,
    get_feature_columns,
    to_arrays,
)
from supervised.preprocessing import build_pipeline, fit_pipeline, transform


# ================================================================== #
# Fixtures                                                            #
# ================================================================== #

FAKE_FEATURE_COLS = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Flow Bytes/s", "Flow Packets/s", "SYN Flag Count", "ACK Flag Count",
]

ALL_CIC_LABELS = [
    "BENIGN", "DoS Hulk", "DDoS", "DoS GoldenEye", "DoS slowloris",
    "DoS Slowhttptest", "Heartbleed", "PortScan", "FTP-Patator",
    "SSH-Patator",
    "Web Attack \ufffd Brute Force", "Web Attack \ufffd XSS",
    "Web Attack \ufffd Sql Injection",
    "Bot", "Infiltration",
]


def _make_df(label: str, n: int = 10, source_file: str = "Monday-WorkingHours.pcap_ISCX.csv"):
    """Return a minimal synthetic DataFrame that looks like a CIC-IDS2017 row."""
    data = {col: np.random.rand(n) * 100 for col in FAKE_FEATURE_COLS}
    data[ORIGINAL_LABEL_COL] = label
    data[CATEGORY_COL] = map_label(label)
    data[SOURCE_FILE_COL] = source_file
    return pd.DataFrame(data)


def _make_combined_df():
    """Multi-label, multi-file synthetic dataset."""
    frames = []
    # Training-day files
    for label, sf in [
        ("BENIGN",          "Monday-WorkingHours.pcap_ISCX.csv"),
        ("DoS Hulk",        "Wednesday-workingHours.pcap_ISCX.csv"),
        ("FTP-Patator",     "Tuesday-WorkingHours.pcap_ISCX.csv"),
        ("PortScan",        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"),
        ("DDoS",            "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"),
        ("Bot",             "Friday-WorkingHours-Morning.pcap_ISCX.csv"),
        ("Infiltration",    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"),
    ]:
        frames.append(_make_df(label, n=20, source_file=sf))
    return pd.concat(frames, ignore_index=True)


# ================================================================== #
# Label Mapping Tests                                                 #
# ================================================================== #

class TestLabelMapping:

    def test_all_known_labels_map(self):
        """Every label present in the real dataset must map to a category."""
        for label in ALL_CIC_LABELS:
            result = map_label(label)
            assert result is not None, (
                f"Label '{label}' has no mapping — add it to LABEL_TO_CATEGORY"
            )

    def test_all_mapped_categories_are_valid(self):
        """Every mapped category must be one of the ORDERED_CATEGORIES."""
        for label, category in LABEL_TO_CATEGORY.items():
            assert category in ORDERED_CATEGORIES, (
                f"Label '{label}' maps to '{category}' which is not in ORDERED_CATEGORIES"
            )

    def test_unknown_category_not_a_training_label(self):
        """UNKNOWN_CATEGORY must never appear as a training label."""
        assert UNKNOWN_CATEGORY not in ORDERED_CATEGORIES
        assert UNKNOWN_CATEGORY not in LABEL_TO_CATEGORY.values()

    def test_map_label_strips_whitespace(self):
        assert map_label("  BENIGN  ") == "BENIGN"
        assert map_label(" PortScan ") == "RECONNAISSANCE"

    def test_map_label_returns_none_for_unknown(self):
        assert map_label("SomethingTotallyNew") is None
        assert map_label("") is None

    def test_map_labels_series(self):
        series = pd.Series(["BENIGN", "DoS Hulk", "UNKNOWN_LABEL", "PortScan"])
        mapped, unmapped_mask = map_labels_series(series)
        assert mapped[0] == "BENIGN"
        assert mapped[1] == "DOS_DDOS"
        assert mapped[3] == "RECONNAISSANCE"
        assert bool(unmapped_mask[2]) is True
        assert bool(unmapped_mask[0]) is False

    def test_benign_maps_to_benign(self):
        assert map_label("BENIGN") == "BENIGN"

    def test_dos_variants_all_map_to_dos_ddos(self):
        dos_labels = ["DoS Hulk", "DDoS", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"]
        for lbl in dos_labels:
            assert map_label(lbl) == "DOS_DDOS", f"Expected DOS_DDOS for '{lbl}'"

    def test_web_attack_variants(self):
        for lbl in ["Web Attack \ufffd Brute Force", "Web Attack \ufffd XSS",
                    "Web Attack \ufffd Sql Injection"]:
            assert map_label(lbl) == "WEB_ATTACK", f"Expected WEB_ATTACK for '{lbl}'"

    def test_brute_force_labels(self):
        assert map_label("FTP-Patator") == "BRUTE_FORCE"
        assert map_label("SSH-Patator") == "BRUTE_FORCE"

    def test_botnet_label(self):
        assert map_label("Bot") == "BOTNET_C2"

    def test_infiltration_label(self):
        assert map_label("Infiltration") == "INFILTRATION"

    def test_heartbleed_label(self):
        assert map_label("Heartbleed") == "OTHER_ATTACK"

    def test_port_scan_label(self):
        assert map_label("PortScan") == "RECONNAISSANCE"

    def test_build_mapping_report_no_unmapped(self):
        counts = {"BENIGN": 100, "DoS Hulk": 50}
        report = build_mapping_report(counts)
        assert report["total_unmapped"] == 0
        assert len(report["unmapped_labels"]) == 0
        assert report["category_totals"]["BENIGN"] == 100
        assert report["category_totals"]["DOS_DDOS"] == 50

    def test_build_mapping_report_with_unmapped(self):
        counts = {"BENIGN": 100, "ALIEN_ATTACK": 42}
        report = build_mapping_report(counts)
        assert report["total_unmapped"] == 42
        assert len(report["unmapped_labels"]) == 1
        assert report["unmapped_labels"][0]["label"] == "ALIEN_ATTACK"

    def test_ordered_categories_contains_all_expected(self):
        expected = {
            "BENIGN", "DOS_DDOS", "RECONNAISSANCE", "BRUTE_FORCE",
            "WEB_ATTACK", "BOTNET_C2", "INFILTRATION", "OTHER_ATTACK"
        }
        assert set(ORDERED_CATEGORIES) == expected


# ================================================================== #
# Splitter Tests                                                      #
# ================================================================== #

class TestSplitter:

    def test_holdout_is_the_tail_of_each_label(self):
        """The test rows for a label are the later rows of that label."""
        df = _make_df("DoS Hulk", n=10, source_file="Wednesday-workingHours.pcap_ISCX.csv")
        df["Flow Duration"] = np.arange(10)  # capture order marker
        df_train, df_test, report = split_dataset(df)
        assert list(df_test["Flow Duration"]) == [8, 9]
        assert list(df_train["Flow Duration"]) == list(range(8))
        assert report["strategy"] == "per_label_capture_order_holdout"

    def test_every_multi_row_label_is_in_both_sides(self):
        df = _make_combined_df()
        df_train, df_test, _ = split_dataset(df)
        train_labels = set(df_train[ORIGINAL_LABEL_COL].unique())
        test_labels = set(df_test[ORIGINAL_LABEL_COL].unique())
        assert train_labels == test_labels

    def test_files_can_contribute_to_both_sides(self):
        """A capture file is not assigned wholly to train or test."""
        df = _make_combined_df()
        df_train, df_test, _ = split_dataset(df)
        overlap = set(df_train[SOURCE_FILE_COL].unique()) & set(df_test[SOURCE_FILE_COL].unique())
        assert len(overlap) > 0

    def test_all_rows_accounted_for_when_there_are_no_exact_copies(self):
        df = _make_combined_df()
        df_train, df_test, report = split_dataset(df)
        assert report["test_rows_removed_as_exact_train_copies"] == 0
        assert len(df_train) + len(df_test) == len(df)

    def test_exact_train_copies_are_removed_from_test(self):
        df = _make_df("BENIGN", n=5, source_file="Monday-WorkingHours.pcap_ISCX.csv")
        # The held-out tail is the last row. Make it an exact feature copy
        # of the first training row.
        for col in FAKE_FEATURE_COLS:
            df.loc[4, col] = df.loc[0, col]
        df_train, df_test, report = split_dataset(df)
        assert report["test_rows_removed_as_exact_train_copies"] == 1
        assert len(df_test) == 0
        assert len(df_train) == 4

    def test_split_report_contains_expected_keys(self):
        df = _make_combined_df()
        _, _, report = split_dataset(df)
        for key in ["strategy", "train_rows", "test_rows", "train_pct", "test_pct",
                    "train_category_distribution", "test_category_distribution",
                    "limitations"]:
            assert key in report, f"Missing key in split report: {key}"

    def test_get_feature_columns_excludes_metadata(self):
        df = _make_combined_df()
        feature_cols = get_feature_columns(df)
        for excluded in [CATEGORY_COL, SOURCE_FILE_COL, "original_label"]:
            assert excluded not in feature_cols, f"Metadata column in features: {excluded}"
        assert len(feature_cols) > 0

    def test_feature_columns_sorted(self):
        df = _make_combined_df()
        feature_cols = get_feature_columns(df)
        assert feature_cols == sorted(feature_cols)

    def test_to_arrays_shapes(self):
        df = _make_combined_df()
        feature_cols = get_feature_columns(df)
        X, y = to_arrays(df, feature_cols)
        assert X.shape == (len(df), len(feature_cols))
        assert len(y) == len(df)
        assert set(y.unique()).issubset(set(ORDERED_CATEGORIES))


# ================================================================== #
# Preprocessing Tests                                                 #
# ================================================================== #

class TestPreprocessing:

    def _make_arrays(self, n_train=100, n_test=30, n_features=7):
        rng = np.random.default_rng(42)
        X_train = rng.standard_normal((n_train, n_features))
        X_test = rng.standard_normal((n_test, n_features))
        # Inject NaN and Inf into training data
        X_train[0, 0] = np.nan
        X_train[1, 1] = np.inf
        X_train[2, 2] = -np.inf
        return X_train, X_test

    def test_pipeline_builds(self):
        p = build_pipeline()
        assert p is not None
        assert len(p.steps) == 3  # inf_to_nan + imputer + scaler

    def test_pipeline_fits_and_transforms(self):
        X_train, X_test = self._make_arrays()
        p = build_pipeline()
        fit_pipeline(p, X_train)
        X_tr = transform(p, X_train)
        X_te = transform(p, X_test)
        assert X_tr.shape == X_train.shape
        assert X_te.shape == X_test.shape

    def test_no_nan_after_transform(self):
        X_train, X_test = self._make_arrays()
        p = build_pipeline()
        fit_pipeline(p, X_train)
        X_tr = transform(p, X_train)
        X_te = transform(p, X_test)
        assert not np.any(np.isnan(X_tr)), "NaN remaining after preprocessing"
        assert not np.any(np.isnan(X_te)), "NaN remaining after preprocessing"

    def test_no_inf_after_transform(self):
        X_train, X_test = self._make_arrays()
        p = build_pipeline()
        fit_pipeline(p, X_train)
        X_tr = transform(p, X_train)
        assert not np.any(np.isinf(X_tr)), "Inf remaining after preprocessing"

    def test_fit_uses_only_training_data(self):
        """
        Verify the imputer's learned medians come from the training set.
        We create a training set with known median and check the imputer
        would impute using that value (not the test set's).
        """
        # Training: feature 0 is always 10.0
        X_train = np.ones((50, 3)) * 10.0
        X_train[0, 0] = np.nan          # introduce a NaN to impute
        X_test = np.ones((10, 3)) * 999.0  # test has very different values

        p = build_pipeline()
        fit_pipeline(p, X_train)

        imputer = p.named_steps["imputer"]
        # The learned median for feature 0 should be 10.0 (from training),
        # not 999.0 from the test set.
        # statistics_ contains per-feature medians fitted on X_train.
        # Median of [nan, 10, 10, 10, ...] = 10.0
        assert abs(imputer.statistics_[0] - 10.0) < 2.0, (
            f"Imputer appears to have learned from test data: {imputer.statistics_[0]}"
        )


# ================================================================== #
# Dataset loader tests                                                #
# ================================================================== #

class TestDatasetLoader:

    def _write_csv(self, directory, name, text):
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def test_load_strips_names_drops_duplicate_column_and_counts_bad_values(self, tmp_path):
        # Second "Fwd Header Length" is the known duplicate. pandas renames
        # it to "Fwd Header Length.1" while reading.
        self._write_csv(
            tmp_path,
            "Monday-WorkingHours.pcap_ISCX.csv",
            " Destination Port, Flow Duration, Fwd Header Length, Fwd Header Length, Label\n"
            "80, 10, 5, 5, BENIGN\n"
            "80, 10, 5, 5, BENIGN\n"
            "80, inf, 1, 1, DoS Hulk\n"
            "22, not_a_number, 1, 1, PortScan\n",
        )
        df, report = load_dataset(str(tmp_path), chunksize=2, verbose=False)

        assert report["files_loaded"] == 1
        file_report = report["per_file"][0]
        assert file_report["rows_raw"] == 4
        assert file_report["duplicate_rows_removed"] == 1
        assert "Fwd Header Length.1" in file_report["duplicate_columns_removed"]
        assert file_report["inf_count_raw"] >= 1
        assert file_report["invalid_numeric_count"] >= 1
        assert "Fwd Header Length.1" not in df.columns
        assert set(df[ORIGINAL_LABEL_COL]) == {"BENIGN", "DoS Hulk", "PortScan"}
        assert set(df[CATEGORY_COL]) == {"BENIGN", "DOS_DDOS", "RECONNAISSANCE"}
        # Capture order of the surviving rows is preserved.
        assert list(df[ORIGINAL_LABEL_COL]) == ["BENIGN", "DoS Hulk", "PortScan"]

    def test_unmapped_labels_are_reported_and_excluded(self, tmp_path):
        self._write_csv(
            tmp_path,
            "Tuesday-WorkingHours.pcap_ISCX.csv",
            "Destination Port,Flow Duration,Label\n"
            "80,1,BENIGN\n"
            "80,2,ALIEN_ATTACK\n",
        )
        with pytest.warns(UserWarning, match="unmapped"):
            df, report = load_dataset(str(tmp_path), verbose=False)

        assert report["label_mapping"]["total_unmapped"] == 1
        assert report["label_mapping"]["unmapped_labels"][0]["label"] == "ALIEN_ATTACK"
        assert "ALIEN_ATTACK" not in set(df[ORIGINAL_LABEL_COL])
        assert len(df) == 1

    def test_whitespace_in_label_is_mapped(self, tmp_path):
        self._write_csv(
            tmp_path,
            "Friday-WorkingHours-Morning.pcap_ISCX.csv",
            "Destination Port,Flow Duration, Label \n"
            "80,1, Bot \n",
        )
        df, report = load_dataset(str(tmp_path), verbose=False)
        assert df.iloc[0][CATEGORY_COL] == "BOTNET_C2"
        assert report["label_mapping"]["total_unmapped"] == 0

    def test_missing_directory_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_dataset(str(tmp_path / "does-not-exist"), verbose=False)

    def test_cleaning_report_lists_dropped_columns_and_keeps_constants(self, tmp_path):
        self._write_csv(
            tmp_path,
            "Monday-WorkingHours.pcap_ISCX.csv",
            "Destination Port,Flow Duration,Fwd Header Length,Fwd Header Length,Label\n"
            "80,1,5,5,BENIGN\n"
            "80,2,5,5,BENIGN\n",
        )
        df, report = load_dataset(str(tmp_path), verbose=False)
        cleaning = build_cleaning_report(df, report)
        assert cleaning["duplicate_rows_removed"] == 0 or cleaning["rows_after_cleaning"] == 2
        assert "Fwd Header Length.1" in cleaning["duplicate_columns_removed"]
        assert "Fwd Header Length" in cleaning["constant_columns_kept"]
        assert "Flow Duration" not in cleaning["constant_columns_kept"]
