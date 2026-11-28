"""
SentinelFlow-CTD — Supervised Classifier: Preprocessing Pipeline
=================================================================

Builds and fits the scikit-learn preprocessing pipeline used to transform
raw CIC-IDS2017 feature vectors before training and inference.

Design decisions
----------------
- All transformations (imputation medians, scaling parameters) are FIT on
  training data ONLY and then APPLIED to both train and test sets.
  This prevents any leakage from test data into the model.
- NaN / Inf values are median-imputed. The medians are saved as part of
  the versioned artifact so inference uses exactly the same values.
- Features are scaled with RobustScaler rather than StandardScaler because
  CIC-IDS2017 contains many highly skewed, heavy-tailed distributions and
  extreme outliers. RobustScaler uses median and IQR, making it less
  sensitive to those outliers than mean/std scaling.
- Inf/-Inf are replaced with NaN before imputation. scikit-learn ≥ 1.0
  SimpleImputer does not accept infinite values directly — the dataset loader
  already handles this for CSV data, but we apply it again here defensively.
- The feature list and their ordering are saved as a versioned artifact
  (feature_names.json) so the classifier is never called with a
  differently-ordered vector.

Public API
----------
  build_pipeline()                     -> sklearn Pipeline (not yet fitted)
  fit_pipeline(pipeline, X_train)      -> fitted pipeline
  transform(pipeline, X)               -> np.ndarray
"""

import numpy as np
from sklearn.pipeline import Pipeline, FunctionTransformer
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import RobustScaler


def _replace_inf(X):
    """Replace +Inf and -Inf with NaN so SimpleImputer can handle them.

    The input dtype is kept. Training uses float32 so the full CIC-IDS2017
    matrix stays small enough to fit in memory. A float64 matrix, such as
    the unit-test data, stays float64.
    """
    X = np.asarray(X)
    if not np.issubdtype(X.dtype, np.floating):
        X = np.asarray(X, dtype=np.float64)
    else:
        X = np.array(X, dtype=X.dtype, copy=True)
    X[~np.isfinite(X)] = np.nan
    return X


def build_pipeline() -> Pipeline:
    """
    Return a new (unfitted) preprocessing Pipeline:

      Step 1 — InfToNaN (FunctionTransformer)
        Replaces +Inf and -Inf with NaN. scikit-learn's SimpleImputer
        rejects infinite values, so this guard runs first.

      Step 2 — SimpleImputer(strategy='median')
        Replaces NaN values with the per-column median computed from
        training data.

      Step 3 — RobustScaler()
        Scales each feature using median and IQR. More robust to the
        heavy-tailed distributions common in network flow statistics
        than StandardScaler.
    """
    return Pipeline([
        ("inf_to_nan", FunctionTransformer(_replace_inf, validate=False)),
        ("imputer",    SimpleImputer(strategy="median")),
        ("scaler",     RobustScaler()),
    ])


def fit_pipeline(pipeline: Pipeline, X_train: np.ndarray) -> Pipeline:
    """
    Fit the pipeline on training data and return it.

    Parameters
    ----------
    pipeline : sklearn Pipeline (from build_pipeline())
    X_train  : np.ndarray of shape (n_samples, n_features) — training features only

    Returns
    -------
    Fitted pipeline (same object, mutated in-place).
    """
    pipeline.fit(X_train)
    return pipeline


def transform(pipeline: Pipeline, X: np.ndarray) -> np.ndarray:
    """
    Apply the FITTED pipeline to a feature array.

    Parameters
    ----------
    pipeline : fitted sklearn Pipeline
    X        : np.ndarray of shape (n_samples, n_features)

    Returns
    -------
    np.ndarray of shape (n_samples, n_features) — transformed features
    """
    return pipeline.transform(X)
