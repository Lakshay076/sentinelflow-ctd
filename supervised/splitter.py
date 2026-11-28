"""
SentinelFlow-CTD — Supervised Classifier: Train/Test Splitting
===============================================================

Hold out the last 20% of each original label inside each capture file.

Why this strategy
-----------------
CIC-IDS2017 was captured over five days, and each attack label is
concentrated in one file:

  Monday     BENIGN only
  Tuesday    FTP-Patator, then SSH-Patator
  Wednesday  DoS variants, then Heartbleed
  Thursday   web attacks in the morning, infiltration in the afternoon
  Friday     Bot in the morning, DDoS and PortScan in the afternoon

A purely random row split would put nearly identical neighbouring flows
into both train and test, which inflates the scores.

Holding out an entire day does not work either. Heartbleed, for example,
is 11 rows inside Wednesday. Putting Wednesday in the test set removes
Heartbleed from training. Putting Wednesday in the training set means
Heartbleed is never evaluated. The same problem applies to web attacks,
FTP/SSH brute force, and infiltration: each lives in only one file.

Inside each file the rows are in capture order, and each attack is a
contiguous burst. For every (capture file, original label) group we
therefore keep the earlier rows for training and hold out the final 20%
for testing. That is a time-ordered split within each attack burst, and
it gives every label that has at least two rows a held-out sample.

After the split, any test row whose feature values exactly match a
training row is removed from the test set and counted in the report.
Those copies would not be a fair test.

Limitations
-----------
1. The held-out rows come from the same attack tool and the same day as
   the training rows, so scores are likely higher than they would be on
   a later, different capture.
2. Heartbleed (11 rows), SQL injection (21 rows) and infiltration
   (36 rows) contribute only a handful of test rows. Their recall will
   move a lot if a few predictions change.
3. This is not a cross-day test. Friday traffic is partly in training
   and partly in testing.
4. Near-duplicate flows that are not exact copies can still sit on both
   sides of the cut.

Class imbalance
---------------
BENIGN is about 80% of the rows. The classifier uses class weights.
No oversampling is applied, and nothing is resampled before this split.
"""

from typing import Dict, List, Tuple

import pandas as pd

from supervised.dataset_loader import (
    CATEGORY_COL,
    ORIGINAL_LABEL_COL,
    SOURCE_FILE_COL,
)

# Fraction of each (file, original label) group held out as test.
# The holdout is the tail of the group, which is the later part of the
# capture for that label.
HOLDOUT_FRACTION = 0.20


def split_dataset(
    df: pd.DataFrame,
    holdout_fraction: float = HOLDOUT_FRACTION,
) -> Tuple[pd.DataFrame, pd.DataFrame, Dict]:
    """
    Split one combined dataset into training and test frames.

    Parameters
    ----------
    df : pd.DataFrame
        Output of dataset_loader.load_dataset(). Must still be in capture
        order within each source file.
    holdout_fraction : float
        Tail fraction of each (source file, original label) group to hold
        out. Default 0.20.

    Returns
    -------
    df_train, df_test, split_report
    """
    required = {SOURCE_FILE_COL, ORIGINAL_LABEL_COL, CATEGORY_COL}
    missing = required.difference(df.columns)
    if missing:
        raise ValueError(
            f"Missing columns {sorted(missing)}. "
            "Run dataset_loader.load_dataset() first."
        )
    if not 0 < holdout_fraction < 1:
        raise ValueError("holdout_fraction must be between 0 and 1")

    train_parts = []
    test_parts = []
    group_rows = []

    grouped = df.groupby([SOURCE_FILE_COL, ORIGINAL_LABEL_COL], sort=False)
    for (source_file, original_label), group in grouped:
        n = len(group)
        if n < 2:
            n_test = 0
            train_parts.append(group)
        else:
            n_test = int(round(n * holdout_fraction))
            n_test = max(1, n_test)
            n_test = min(n_test, n - 1)
            cut = n - n_test
            train_parts.append(group.iloc[:cut])
            test_parts.append(group.iloc[cut:])

        group_rows.append({
            "source_file": source_file,
            "original_label": original_label,
            "rows": n,
            "train_rows": n - n_test,
            "test_rows": n_test,
        })

    df_train = (
        pd.concat(train_parts, ignore_index=True) if train_parts else df.iloc[0:0].copy()
    )
    df_test = (
        pd.concat(test_parts, ignore_index=True) if test_parts else df.iloc[0:0].copy()
    )

    feature_cols = get_feature_columns(df)
    leaked_rows = 0
    if len(df_train) and len(df_test) and feature_cols:
        train_hash = pd.util.hash_pandas_object(
            df_train[feature_cols], index=False
        )
        test_hash = pd.util.hash_pandas_object(
            df_test[feature_cols], index=False
        )
        leak_mask = test_hash.isin(set(train_hash.to_numpy()))
        leaked_rows = int(leak_mask.sum())
        if leaked_rows:
            df_test = df_test.loc[~leak_mask.to_numpy()].reset_index(drop=True)

    split_report = {
        "strategy": "per_label_capture_order_holdout",
        "holdout_fraction": holdout_fraction,
        "description": (
            "Within each capture file, the last "
            f"{holdout_fraction:.0%} of each original label is held out. "
            "Rows stay in capture order, so the holdout is the later part "
            "of that label's burst. Exact feature copies of training rows "
            "are then removed from the test set."
        ),
        "why_not_random": (
            "Neighbouring flows in a capture are often near-duplicates. "
            "A random split would score the model on copies of rows it "
            "just trained on."
        ),
        "why_not_whole_day": (
            "Each attack label occurs in only one capture file. Holding "
            "out a whole day would either remove that attack from training "
            "or leave it with no test rows. Heartbleed is the clearest "
            "case: all 11 rows are in the Wednesday file."
        ),
        "group_splits": group_rows,
        "train_rows": len(df_train),
        "test_rows": len(df_test),
        "test_rows_removed_as_exact_train_copies": leaked_rows,
        "train_pct": round(100 * len(df_train) / max(len(df), 1), 1),
        "test_pct": round(100 * len(df_test) / max(len(df), 1), 1),
        "train_files": sorted(df_train[SOURCE_FILE_COL].unique().tolist()) if len(df_train) else [],
        "test_files": sorted(df_test[SOURCE_FILE_COL].unique().tolist()) if len(df_test) else [],
        "train_category_distribution": (
            df_train[CATEGORY_COL].value_counts().to_dict() if len(df_train) else {}
        ),
        "test_category_distribution": (
            df_test[CATEGORY_COL].value_counts().to_dict() if len(df_test) else {}
        ),
        "limitations": [
            "Held-out rows come from the same day and the same attack tool as the training rows, so this is easier than a cross-day test.",
            "Heartbleed, SQL injection and infiltration have very few test rows, so their recall is noisy.",
            "Flows that are similar but not exact copies can still appear on both sides of the cut.",
            "No oversampling is applied before or after this split. Class imbalance is handled with class weights during training.",
        ],
    }
    return df_train, df_test, split_report


def get_feature_columns(df: pd.DataFrame) -> List[str]:
    """
    Feature column names, excluding metadata.

    Alphabetical order is deliberate. The saved feature list uses this
    same order, so a later inference call cannot silently shuffle columns.
    """
    exclude = {CATEGORY_COL, SOURCE_FILE_COL, ORIGINAL_LABEL_COL}
    return sorted(c for c in df.columns if c not in exclude)


def to_arrays(
    df: pd.DataFrame,
    feature_cols: List[str],
    copy: bool = True,
) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Return the feature frame and the threat-category labels.

    The feature frame is not preprocessed here. Medians and scaling are
    fit on the training frame only, in the training step.

    copy=False reuses the caller's columns. Training uses that so the
    full CIC-IDS2017 table is not duplicated before the model is fit.
    """
    X = df[feature_cols]
    y = df[CATEGORY_COL]
    if copy:
        X = X.copy()
        y = y.copy()
    return X, y
