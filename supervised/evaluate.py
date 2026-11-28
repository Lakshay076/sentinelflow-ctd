"""
SentinelFlow-CTD — Supervised Classifier: Evaluation
======================================================

Computes and saves all evaluation metrics for a trained classifier.

Metrics computed
----------------
  - Accuracy
  - Balanced accuracy           (accounts for class imbalance)
  - Macro F1-score              (treats all classes equally — most important)
  - Weighted F1-score           (weighted by support)
  - Macro precision / recall
  - Per-class classification report (precision, recall, F1, support)
  - Confusion matrix            (absolute counts + normalised)
  - Feature importances         (Random Forest only)

Decision: macro F1 is the primary headline metric because:
  - Macro F1 gives equal weight to every class regardless of its frequency.
  - Infiltration (36 rows) and Heartbleed (11 rows) will contribute equally to
    the macro score as BENIGN (2.3M rows). This makes failures on rare classes
    visible rather than buried in a high weighted average.

All metrics are saved to evaluation_report.json alongside the model artifacts.
"""

import json
import os
from typing import Dict, List, Optional

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import LabelEncoder


def evaluate(
    model,
    preprocessor,
    label_encoder: LabelEncoder,
    X_test,
    y_test_encoded: np.ndarray,
    version_dir: str,
    comparison_model=None,
    feature_names: Optional[List[str]] = None,
    verbose: bool = True,
) -> Dict:
    """
    Evaluate the trained model on the test set and save results.

    Parameters
    ----------
    model           : fitted RandomForestClassifier
    preprocessor    : fitted preprocessing Pipeline (already applied to X_test)
    label_encoder   : fitted LabelEncoder
    X_test          : np.ndarray — PREPROCESSED test features (output of transform())
    y_test_encoded  : np.ndarray — integer-encoded test labels
    version_dir     : directory to write evaluation_report.json
    comparison_model: optional fitted LogisticRegression for comparison
    feature_names   : list of feature column names (for importance table)
    verbose         : print summary to stdout

    Returns
    -------
    report : dict containing all computed metrics
    """
    class_names = list(label_encoder.classes_)

    # ---- Primary model predictions ------------------------------- #
    y_pred = model.predict(X_test)
    y_prob = None
    try:
        y_prob = model.predict_proba(X_test)
    except AttributeError:
        pass

    rf_metrics = _compute_metrics(
        y_true=y_test_encoded,
        y_pred=y_pred,
        class_names=class_names,
        label_encoder=label_encoder,
    )

    # ---- Comparison model predictions ---------------------------- #
    comparison_metrics = None
    if comparison_model is not None:
        y_pred_lr = comparison_model.predict(X_test)
        comparison_metrics = _compute_metrics(
            y_true=y_test_encoded,
            y_pred=y_pred_lr,
            class_names=class_names,
            label_encoder=label_encoder,
        )

    # ---- Feature importances (RF only) --------------------------- #
    feature_importances = None
    if feature_names and hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        fi_sorted = sorted(
            zip(feature_names, importances),
            key=lambda x: -x[1],
        )
        feature_importances = [
            {"feature": name, "importance": round(float(imp), 6)}
            for name, imp in fi_sorted[:30]  # top 30
        ]

    # ---- Build report -------------------------------------------- #
    report = {
        "primary_model": "RandomForestClassifier",
        "comparison_model": "LogisticRegression" if comparison_model else None,
        "test_rows": int(len(y_test_encoded)),
        "class_names": class_names,
        "random_forest": rf_metrics,
        "logistic_regression": comparison_metrics,
        "top_30_feature_importances": feature_importances,
    }

    # ---- Save report --------------------------------------------- #
    report_path = os.path.join(version_dir, "evaluation_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    if verbose:
        _print_summary(rf_metrics, comparison_metrics, class_names, version_dir)

    return report


def _compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: List[str],
    label_encoder: LabelEncoder,
) -> Dict:
    """Compute the full metrics dict for one model."""
    acc = float(accuracy_score(y_true, y_pred))
    bal_acc = float(balanced_accuracy_score(y_true, y_pred))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))
    macro_prec = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
    macro_rec = float(recall_score(y_true, y_pred, average="macro", zero_division=0))

    # Per-class classification report
    report_dict = classification_report(
        y_true, y_pred,
        target_names=class_names,
        output_dict=True,
        zero_division=0,
    )

    # Confusion matrix — both raw counts and row-normalised
    cm = confusion_matrix(y_true, y_pred)
    cm_norm = confusion_matrix(y_true, y_pred, normalize="true")

    # Identify weak classes (recall < 0.5 or support < 20)
    weak_classes = []
    for cls in class_names:
        cls_metrics = report_dict.get(cls, {})
        support = int(cls_metrics.get("support", 0))
        recall = float(cls_metrics.get("recall", 0.0))
        if recall < 0.50 or support < 20:
            weak_classes.append({
                "class": cls,
                "recall": round(recall, 4),
                "support": support,
                "reason": (
                    "low recall" if recall < 0.50 else "very few test samples"
                ),
            })

    return {
        "accuracy": round(acc, 6),
        "balanced_accuracy": round(bal_acc, 6),
        "macro_f1": round(macro_f1, 6),
        "weighted_f1": round(weighted_f1, 6),
        "macro_precision": round(macro_prec, 6),
        "macro_recall": round(macro_rec, 6),
        "per_class_report": {
            cls: {
                "precision": round(float(v.get("precision", 0)), 4),
                "recall": round(float(v.get("recall", 0)), 4),
                "f1_score": round(float(v.get("f1-score", 0)), 4),
                "support": int(v.get("support", 0)),
            }
            for cls, v in report_dict.items()
            if isinstance(v, dict) and cls in class_names
        },
        "confusion_matrix": cm.tolist(),
        "confusion_matrix_normalised": [
            [round(float(x), 4) for x in row] for row in cm_norm.tolist()
        ],
        "class_names_for_cm": class_names,
        "weak_classes": weak_classes,
    }


def _print_summary(rf_metrics, comparison_metrics, class_names, version_dir):
    """Print a readable summary to stdout."""
    print("\n" + "=" * 65)
    print("EVALUATION RESULTS")
    print("=" * 65)

    print("\n── Random Forest ──────────────────────────────────────────")
    print(f"  Accuracy           : {rf_metrics['accuracy']:.4f}")
    print(f"  Balanced accuracy  : {rf_metrics['balanced_accuracy']:.4f}")
    print(f"  Macro F1-score     : {rf_metrics['macro_f1']:.4f}  ← primary metric")
    print(f"  Weighted F1-score  : {rf_metrics['weighted_f1']:.4f}")
    print(f"  Macro precision    : {rf_metrics['macro_precision']:.4f}")
    print(f"  Macro recall       : {rf_metrics['macro_recall']:.4f}")

    print("\n  Per-class metrics:")
    for cls in class_names:
        m = rf_metrics["per_class_report"].get(cls)
        if m:
            print(
                f"    {cls:20s}  P={m['precision']:.3f}  "
                f"R={m['recall']:.3f}  F1={m['f1_score']:.3f}  "
                f"support={m['support']:,}"
            )

    if rf_metrics["weak_classes"]:
        print("\n  ⚠ Weak classes (recall < 0.5 or low support):")
        for w in rf_metrics["weak_classes"]:
            print(f"    {w['class']:20s}  recall={w['recall']:.3f}  support={w['support']}  ({w['reason']})")

    if comparison_metrics:
        print("\n── Logistic Regression (comparison) ───────────────────────")
        print(f"  Accuracy           : {comparison_metrics['accuracy']:.4f}")
        print(f"  Balanced accuracy  : {comparison_metrics['balanced_accuracy']:.4f}")
        print(f"  Macro F1-score     : {comparison_metrics['macro_f1']:.4f}")
        print(f"  Weighted F1-score  : {comparison_metrics['weighted_f1']:.4f}")

    print(f"\n  Full report saved to: {os.path.join(version_dir, 'evaluation_report.json')}")
    print("=" * 65)
