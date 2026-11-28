"""
SentinelFlow-CTD — Supervised Classifier: Dataset Loader
=========================================================

Loads, inspects, and cleans all eight CIC-IDS2017 CSV files.

Design decisions
----------------
- Each file is read in chunks to avoid loading multi-GB data into memory at
  once. A configurable chunk size keeps peak RAM predictable.
- Column names have leading/trailing whitespace stripped (CIC-IDS2017 is
  notorious for column names like ' Label').
- The original label column is preserved as 'original_label' for traceability.
  The mapped category is stored in 'threat_category'.
- Duplicate rows are reported and removed. Duplicate columns are reported
  and deduplicated.
- NaN, +Inf, and -Inf are detected and handled (replace with per-column
  medians computed from training data only — that happens in preprocessing.py).
- Timestamps, IP addresses, and flow IDs are NOT present in CIC-IDS2017 CSVs
  (CICFlowMeter strips them). No identifier removal is needed.
- 'Fwd Header Length.1' is a known exact duplicate of 'Fwd Header Length' in
  this dataset. It is removed with documentation.

The public API is:
  load_dataset(data_dir)         -> (DataFrame, report_dict)
  describe_dataset(df)           -> dict of descriptive statistics
"""

import gc
import os
import warnings
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from supervised.label_mapping import map_labels_series, build_mapping_report

# ------------------------------------------------------------------ #
# Constants                                                           #
# ------------------------------------------------------------------ #

# Columns that are known non-feature identifiers in CIC-IDS2017.
# These do NOT appear in the CSV files themselves (CICFlowMeter strips them)
# but are listed here for future-proofing in case a different export variant
# is used.
NON_FEATURE_COLUMNS = {
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp",
    "Src IP",
    "Dst IP",
    "Src Port",
    "Dst Port",
    "Source Port",   # Destination Port IS kept — it's a network feature
}

# This CIC-IDS2017 export stores "Fwd Header Length" twice. pandas renames
# the second copy to "Fwd Header Length.1" on read. The two columns are the
# same measurement, so the second copy is removed and reported.
KNOWN_DUPLICATE_COLUMNS = {"Fwd Header Length.1"}

# Column holding the class labels in the raw CSVs.
RAW_LABEL_COLUMN = "Label"

# Column names we produce.
ORIGINAL_LABEL_COL = "original_label"
CATEGORY_COL = "threat_category"

# File from which each row originated (for day-aware splitting).
SOURCE_FILE_COL = "source_file"

# ------------------------------------------------------------------ #
# File discovery                                                      #
# ------------------------------------------------------------------ #

def discover_csv_files(data_dir: str) -> List[str]:
    """
    Return sorted list of absolute paths to all CSV files in data_dir.
    Raises FileNotFoundError if the directory does not exist.
    """
    if not os.path.isdir(data_dir):
        raise FileNotFoundError(
            f"Dataset directory not found: {data_dir}\n"
            "Please extract MachineLearningCSV.zip to data/cic_ids2017/raw/MachineLearningCSV/"
        )
    paths = sorted(
        os.path.join(data_dir, f)
        for f in os.listdir(data_dir)
        if f.lower().endswith(".csv")
    )
    if not paths:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")
    return paths


# ------------------------------------------------------------------ #
# Per-file loading                                                    #
# ------------------------------------------------------------------ #

def _clean_chunk_columns(chunk: pd.DataFrame) -> Tuple[pd.DataFrame, List[str], List[str]]:
    """
    Strip column names, drop identifier columns and duplicate columns.

    Returns the cleaned chunk plus the names that were removed.
    """
    chunk = chunk.copy()
    chunk.columns = [str(c).strip() for c in chunk.columns]

    duplicate_columns = []
    known = [c for c in chunk.columns if c in KNOWN_DUPLICATE_COLUMNS]
    if known:
        chunk = chunk.drop(columns=known)
        duplicate_columns.extend(known)

    if chunk.columns.duplicated().any():
        extra = [
            name for name, is_dup in zip(chunk.columns, chunk.columns.duplicated())
            if is_dup
        ]
        chunk = chunk.loc[:, ~chunk.columns.duplicated(keep="first")]
        duplicate_columns.extend(extra)

    non_features = [c for c in chunk.columns if c in NON_FEATURE_COLUMNS]
    if non_features:
        chunk = chunk.drop(columns=non_features)

    return chunk, duplicate_columns, non_features


def _load_single_csv(
    path: str,
    chunksize: int = 100_000,
) -> Tuple[pd.DataFrame, Dict]:
    """
    Load one CSV file in chunks, clean column names, and return the
    combined DataFrame plus a per-file report dict.

    Each chunk is converted to numeric columns before it is stored, so
    the whole file is not held in memory as text.
    """
    file_report: Dict = {
        "filename": os.path.basename(path),
        "path": path,
        "rows_raw": 0,
        "columns_raw": 0,
        "duplicate_rows_removed": 0,
        "duplicate_columns_removed": [],
        "non_feature_columns_removed": [],
        "nan_count_raw": 0,
        "inf_count_raw": 0,
        "invalid_numeric_count": 0,
        "label_counts": {},
        "unmapped_labels": [],
        "rows_after_cleaning": 0,
    }

    cleaned_chunks = []
    label_counts: Dict[str, int] = {}
    columns_seen = False

    for chunk in pd.read_csv(
        path,
        chunksize=chunksize,
        encoding="utf-8",
        encoding_errors="replace",
        low_memory=False,
    ):
        if not columns_seen:
            file_report["columns_raw"] = int(chunk.shape[1])
            columns_seen = True

        file_report["rows_raw"] += int(len(chunk))
        chunk, dup_cols, id_cols = _clean_chunk_columns(chunk)
        for name in dup_cols:
            if name not in file_report["duplicate_columns_removed"]:
                file_report["duplicate_columns_removed"].append(name)
        for name in id_cols:
            if name not in file_report["non_feature_columns_removed"]:
                file_report["non_feature_columns_removed"].append(name)

        if RAW_LABEL_COLUMN not in chunk.columns:
            raise ValueError(
                f"Label column '{RAW_LABEL_COLUMN}' not found in {path}. "
                f"Available columns: {list(chunk.columns)}"
            )

        labels = chunk[RAW_LABEL_COLUMN].astype(str).str.strip()
        for label, count in labels.value_counts().items():
            label_counts[str(label)] = label_counts.get(str(label), 0) + int(count)

        feature_cols = [c for c in chunk.columns if c != RAW_LABEL_COLUMN]
        numeric = chunk.loc[:, feature_cols].copy()
        # CIC-IDS2017 writes infinite rates as the text "Infinity". A value
        # can also arrive with surrounding spaces (" inf"). Strip text
        # cells before parsing so those are counted as infinities, not as
        # invalid numbers. Columns pandas already parsed stay numeric.
        text_cols = list(numeric.select_dtypes(include=["object", "string"]).columns)
        for col in text_cols:
            stripped = numeric[col].astype("string").str.strip()
            present = (
                stripped.notna()
                & stripped.ne("")
                & ~stripped.str.lower().isin(["nan", "none", "<na>"])
            )
            parsed = pd.to_numeric(stripped, errors="coerce")
            file_report["invalid_numeric_count"] += int((parsed.isna() & present).sum())
            numeric[col] = parsed

        values = numeric.to_numpy(dtype=np.float64, na_value=np.nan)
        file_report["inf_count_raw"] += int(np.isinf(values).sum())
        file_report["nan_count_raw"] += int(np.isnan(values).sum())
        numeric = numeric.mask(~np.isfinite(values))
        # float32 keeps the full table near 1 GB instead of about 2 GB.
        # Counts above about 16 million are not exact in float32. A flow
        # duration of that size can be off by a few microseconds, which
        # does not change the shape of these features for a tree model.
        numeric = numeric.astype(np.float32)

        numeric[ORIGINAL_LABEL_COL] = labels.to_numpy()
        numeric[SOURCE_FILE_COL] = os.path.basename(path)
        cleaned_chunks.append(numeric)

    if not cleaned_chunks:
        raise ValueError(f"CSV file is empty: {path}")

    df = pd.concat(cleaned_chunks, ignore_index=True)
    file_report["label_counts"] = label_counts

    mapped, unmapped_mask = map_labels_series(df[ORIGINAL_LABEL_COL])
    df[CATEGORY_COL] = mapped
    unmapped_labels_list = sorted(
        df.loc[unmapped_mask, ORIGINAL_LABEL_COL].unique().tolist()
    )
    file_report["unmapped_labels"] = unmapped_labels_list

    if unmapped_mask.any():
        warnings.warn(
            f"[{os.path.basename(path)}] {int(unmapped_mask.sum())} rows with unmapped labels "
            f"will be excluded: {unmapped_labels_list}"
        )
        df = df.loc[~unmapped_mask].copy()

    # Duplicate flows inside one capture are removed. The first copy, which
    # is the earlier row in the file, is kept so capture order still holds
    # for the time-ordered train/test split.
    feature_cols = [
        c for c in df.columns
        if c not in {ORIGINAL_LABEL_COL, CATEGORY_COL, SOURCE_FILE_COL}
    ]
    n_before = len(df)
    df = df.drop_duplicates(subset=feature_cols + [CATEGORY_COL], keep="first")
    file_report["duplicate_rows_removed"] = n_before - len(df)
    file_report["rows_after_cleaning"] = len(df)
    return df.reset_index(drop=True), file_report


# ------------------------------------------------------------------ #
# Full dataset loading                                                #
# ------------------------------------------------------------------ #

def load_dataset(
    data_dir: str,
    chunksize: int = 100_000,
    verbose: bool = True,
) -> Tuple[pd.DataFrame, Dict]:
    """
    Load and clean all CIC-IDS2017 CSV files in data_dir.

    Parameters
    ----------
    data_dir : str
        Path to the directory containing the ISCX CSV files.
    chunksize : int
        Number of rows per chunk when reading large files. Default 100k.
    verbose : bool
        Print per-file progress to stdout.

    Returns
    -------
    df : pd.DataFrame
        Combined, cleaned dataset with columns:
          [feature_cols..., 'original_label', 'threat_category', 'source_file']
    report : dict
        Full loading and cleaning report.
    """
    csv_paths = discover_csv_files(data_dir)

    if verbose:
        print(f"[dataset_loader] Found {len(csv_paths)} CSV files in {data_dir}")

    per_file_reports = []
    combined = None

    for path in csv_paths:
        if verbose:
            print(f"  Loading: {os.path.basename(path)} ...", end=" ", flush=True)

        df_file, file_report = _load_single_csv(path, chunksize=chunksize)
        per_file_reports.append(file_report)
        if combined is None:
            combined = df_file
        else:
            combined = pd.concat([combined, df_file], ignore_index=True)
            del df_file

        if verbose:
            print(
                f"{file_report['rows_after_cleaning']:,} rows | "
                f"{file_report['duplicate_rows_removed']:,} dups removed | "
                f"{file_report['nan_count_raw']} NaNs | "
                f"{file_report['inf_count_raw']} Infs"
            )

    gc.collect()

    # ---- Aggregate label counts across all files ----------------- #
    all_label_counts: Dict[str, int] = {}
    for r in per_file_reports:
        for lbl, cnt in r["label_counts"].items():
            all_label_counts[lbl] = all_label_counts.get(lbl, 0) + cnt

    mapping_report = build_mapping_report(all_label_counts)

    # ---- Overall NaN summary on the combined dataset ------------- #
    feature_cols = [
        c for c in combined.columns
        if c not in {ORIGINAL_LABEL_COL, CATEGORY_COL, SOURCE_FILE_COL}
    ]
    total_nan = int(combined[feature_cols].isna().sum().sum())
    total_rows = len(combined)

    report = {
        "files_loaded": len(csv_paths),
        "file_names": [os.path.basename(p) for p in csv_paths],
        "per_file": per_file_reports,
        "total_rows_after_cleaning": total_rows,
        "total_feature_columns": len(feature_cols),
        "feature_columns": feature_cols,
        "total_nan_remaining": total_nan,
        "label_mapping": mapping_report,
        "category_distribution": combined[CATEGORY_COL].value_counts().to_dict(),
        "source_file_distribution": combined[SOURCE_FILE_COL].value_counts().to_dict(),
    }

    if verbose:
        print(f"[dataset_loader] Done. Combined shape: {combined.shape}")
        print(f"  Category distribution:")
        for cat, cnt in sorted(
            report["category_distribution"].items(), key=lambda x: -x[1]
        ):
            print(f"    {cat:20s}: {cnt:>10,}")
        if total_nan > 0:
            print(f"  Remaining NaNs: {total_nan:,} (will be imputed in preprocessing)")

    return combined, report


# ------------------------------------------------------------------ #
# Descriptive statistics helper                                       #
# ------------------------------------------------------------------ #

def build_cleaning_report(df: pd.DataFrame, load_report: Dict) -> Dict:
    """
    Summarise what cleaning changed, without dropping extra features.

    Constant columns are reported and kept. A column that is constant in
    this dataset can still vary on live traffic, so it is not removed here.
    """
    feature_cols = [
        c for c in df.columns
        if c not in {ORIGINAL_LABEL_COL, CATEGORY_COL, SOURCE_FILE_COL}
    ]
    nan_counts = df[feature_cols].isna().sum()
    nunique = df[feature_cols].nunique(dropna=True)
    per_file = load_report.get("per_file", [])

    return {
        "files_loaded": load_report.get("files_loaded"),
        "rows_raw": int(sum(r.get("rows_raw", 0) for r in per_file)),
        "rows_after_cleaning": int(len(df)),
        "duplicate_rows_removed": int(
            sum(r.get("duplicate_rows_removed", 0) for r in per_file)
        ),
        "duplicate_columns_removed": sorted({
            col
            for r in per_file
            for col in r.get("duplicate_columns_removed", [])
        }),
        "non_feature_columns_removed": sorted({
            col
            for r in per_file
            for col in r.get("non_feature_columns_removed", [])
        }),
        "nan_values_before_imputation": int(sum(r.get("nan_count_raw", 0) for r in per_file)),
        "infinite_values_replaced_with_nan": int(
            sum(r.get("inf_count_raw", 0) for r in per_file)
        ),
        "invalid_numeric_values": int(
            sum(r.get("invalid_numeric_count", 0) for r in per_file)
        ),
        "nan_remaining_by_column": {
            col: int(count) for col, count in nan_counts.items() if int(count) > 0
        },
        "constant_columns_kept": [
            col for col in feature_cols if int(nunique[col]) <= 1
        ],
        "feature_count": len(feature_cols),
        "notes": [
            "Infinite values, including the text 'Infinity', are replaced with missing values. Medians are computed later, from training rows only.",
            "Invalid numeric text is included in the NaN count as well as in invalid_numeric_values.",
            "Duplicate 'Fwd Header Length.1' is the second copy of 'Fwd Header Length' and is removed.",
            "Destination Port is kept. This CSV export has no IP address, timestamp, or flow-id column.",
            "Constant columns are listed and kept.",
            "Feature values are stored as float32 so the full dataset can be trained on an 8 GB machine.",
            "Rows whose original label has no mapping are excluded only after they are listed in the dataset report.",
        ],
    }


def describe_dataset(df: pd.DataFrame) -> Dict:
    """
    Return descriptive statistics for the combined dataset.
    Useful for the cleaning report and debugging.
    """
    feature_cols = [
        c for c in df.columns
        if c not in {ORIGINAL_LABEL_COL, CATEGORY_COL, SOURCE_FILE_COL}
    ]
    numeric_df = df[feature_cols].select_dtypes(include=[np.number])

    return {
        "shape": df.shape,
        "feature_count": len(feature_cols),
        "category_counts": df[CATEGORY_COL].value_counts().to_dict(),
        "original_label_counts": df[ORIGINAL_LABEL_COL].value_counts().to_dict(),
        "source_file_counts": df[SOURCE_FILE_COL].value_counts().to_dict(),
        "nan_per_column": df[feature_cols].isna().sum().to_dict(),
        "total_nan": int(df[feature_cols].isna().sum().sum()),
        "numeric_summary": numeric_df.describe().to_dict(),
    }
