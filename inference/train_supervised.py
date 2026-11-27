import argparse
import json
import math
import os
from collections import Counter
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from inference.supervised_schema import (
    SUPERVISED_CLASSES,
    SUPERVISED_FEATURE_NAMES,
    supervised_features_to_vector,
)


DEFAULT_MODEL_PATH = Path(__file__).with_name("supervised_model.joblib")
DEFAULT_METADATA_PATH = Path(__file__).with_name("supervised_metadata.json")
CONFIDENCE_THRESHOLD = 0.75
DEFAULT_RANDOM_STATE = 42

CLASS_IDS_BY_NAME = {
    class_name: class_id
    for class_id, class_name in SUPERVISED_CLASSES.items()
}


def _normalize_label(value, row_number=None):
    label = str(value).strip().upper()
    if label in CLASS_IDS_BY_NAME:
        return CLASS_IDS_BY_NAME[label]

    try:
        numeric_label = float(label)
    except ValueError:
        numeric_label = math.nan

    if math.isfinite(numeric_label) and numeric_label.is_integer():
        class_id = int(numeric_label)
        if class_id in SUPERVISED_CLASSES:
            return class_id

    location = f" at row {row_number}" if row_number is not None else ""
    raise ValueError(
        f"Unknown supervised label{location}: {value!r}. "
        f"Use one of {list(SUPERVISED_CLASSES.values())} or class IDs "
        f"{list(SUPERVISED_CLASSES)}."
    )


def _select_label_column(columns, requested_column):
    if requested_column is not None:
        for column in columns:
            if str(column).lower() == requested_column.lower():
                return column
        raise ValueError(
            f"Label column {requested_column!r} was not found in the dataset."
        )

    lowered = {str(column).lower(): column for column in columns}
    for candidate in ("label", "class", "attack_type", "target"):
        if candidate in lowered:
            return lowered[candidate]

    raise ValueError(
        "Could not identify the label column. Use --label-column to specify it."
    )


def _table_to_training_frame(frame, label_column):
    selected_label_column = _select_label_column(
        frame.columns,
        label_column,
    )
    feature_columns = {
        str(column).lower(): column
        for column in frame.columns
    }

    if not any(name.lower() in feature_columns for name in SUPERVISED_FEATURE_NAMES):
        raise ValueError(
            "The dataset has no columns matching the supervised feature schema."
        )

    rows = []
    for row_number, (_, row) in enumerate(frame.iterrows(), start=2):
        features = {
            name: row[feature_columns[name.lower()]]
            if name.lower() in feature_columns
            else None
            for name in SUPERVISED_FEATURE_NAMES
        }
        vector = supervised_features_to_vector(features)
        label = _normalize_label(
            row[selected_label_column],
            row_number=row_number,
        )
        rows.append(dict(zip(SUPERVISED_FEATURE_NAMES, vector), label=label))

    return pd.DataFrame(rows, columns=SUPERVISED_FEATURE_NAMES + ["label"])


def _load_table_dataset(dataset_path, label_column):
    suffix = dataset_path.suffix.lower()
    if suffix == ".csv":
        frame = pd.read_csv(dataset_path)
    elif suffix in {".parquet", ".pq"}:
        try:
            frame = pd.read_parquet(dataset_path)
        except ImportError as error:
            raise RuntimeError(
                "Reading Parquet requires an installed Parquet engine such as "
                "pyarrow or fastparquet."
            ) from error
    else:
        raise ValueError(
            "Dataset must be a .csv, .parquet, .pq, or .pcap/.pcapng file."
        )

    if frame.empty:
        raise ValueError(f"Dataset contains no rows: {dataset_path}")
    return _table_to_training_frame(frame, label_column)


def _assign_source_label(labels, source_ip, class_id):
    existing = labels.get(source_ip)
    if existing is not None and existing != class_id:
        raise ValueError(
            f"Ground truth assigns multiple classes to source {source_ip}: "
            f"{SUPERVISED_CLASSES[existing]} and {SUPERVISED_CLASSES[class_id]}."
        )
    labels[source_ip] = class_id


def _load_pcap_dataset(pcap_path, ground_truth_path):
    if ground_truth_path is None:
        raise ValueError(
            "PCAP training requires its labeled ground-truth JSON file; "
            "provide it with --ground-truth."
        )

    with ground_truth_path.open("r", encoding="utf-8") as ground_truth_file:
        ground_truth = json.load(ground_truth_file)

    if not isinstance(ground_truth, dict):
        raise ValueError("Ground-truth JSON must contain an object.")

    labels = {}
    expected_detections = ground_truth.get("expected_detections", [])
    benign_ips = ground_truth.get("benign_ips", [])
    if not isinstance(expected_detections, list) or not isinstance(benign_ips, list):
        raise ValueError(
            "Ground truth must define expected_detections and benign_ips as lists."
        )

    for detection in expected_detections:
        if not isinstance(detection, dict):
            raise ValueError("Each expected detection must be a JSON object.")
        source_ip = detection.get("source_ip")
        attack_type = detection.get("attack_type")
        if not source_ip:
            raise ValueError(
                f"Unsupported expected detection entry: {detection!r}"
            )
        try:
            class_id = _normalize_label(attack_type)
        except ValueError as error:
            raise ValueError(
                f"Unsupported expected detection entry: {detection!r}"
            ) from error
        _assign_source_label(
            labels,
            str(source_ip),
            class_id,
        )

    for source_ip in benign_ips:
        if not source_ip:
            raise ValueError("Ground truth contains an empty benign source IP.")
        _assign_source_label(labels, str(source_ip), 0)

    from inference.train_model_from_pcap import extract_training_vectors

    capture_records = []
    extract_training_vectors(
        str(pcap_path),
        capture_records=capture_records,
    )

    rows = []
    for record in capture_records:
        source_ip = record["source_ip"]
        class_id = labels.get(source_ip)
        if class_id is None:
            continue
        vector = supervised_features_to_vector(record["features"])
        rows.append(
            dict(zip(SUPERVISED_FEATURE_NAMES, vector), label=class_id)
        )

    if not rows:
        raise ValueError(
            "No feature windows matched labeled source IPs in the ground truth."
        )
    return pd.DataFrame(rows, columns=SUPERVISED_FEATURE_NAMES + ["label"])


def load_labeled_dataset(dataset_path, ground_truth_path=None, label_column=None):
    dataset_path = Path(dataset_path)
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")

    if dataset_path.suffix.lower() in {".pcap", ".pcapng"}:
        if ground_truth_path is None:
            return _load_pcap_dataset(dataset_path, None)
        ground_truth_path = Path(ground_truth_path)
        if not ground_truth_path.is_file():
            raise FileNotFoundError(
                f"Ground-truth file not found: {ground_truth_path}"
            )
        return _load_pcap_dataset(dataset_path, ground_truth_path)

    if ground_truth_path is not None:
        raise ValueError(
            "--ground-truth is only used with .pcap or .pcapng datasets."
        )
    return _load_table_dataset(dataset_path, label_column)


def load_labeled_datasets(dataset_paths, ground_truth_paths=None, label_column=None):
    if isinstance(dataset_paths, (str, os.PathLike)):
        dataset_paths = [dataset_paths]
    else:
        dataset_paths = list(dataset_paths)

    if ground_truth_paths is None:
        ground_truth_paths = []
    elif isinstance(ground_truth_paths, (str, os.PathLike)):
        ground_truth_paths = [ground_truth_paths]
    else:
        ground_truth_paths = list(ground_truth_paths)

    pcap_count = sum(
        Path(dataset_path).suffix.lower() in {".pcap", ".pcapng"}
        for dataset_path in dataset_paths
    )
    if len(ground_truth_paths) != pcap_count:
        raise ValueError(
            f"Provide one --ground-truth file for each PCAP dataset "
            f"({pcap_count} PCAP file(s), {len(ground_truth_paths)} "
            "ground-truth file(s))."
        )

    datasets = []
    ground_truth_iter = iter(ground_truth_paths)
    for dataset_path in dataset_paths:
        is_pcap = Path(dataset_path).suffix.lower() in {".pcap", ".pcapng"}
        ground_truth_path = next(ground_truth_iter) if is_pcap else None
        datasets.append(
            load_labeled_dataset(
                dataset_path,
                ground_truth_path=ground_truth_path,
                label_column=label_column,
            )
        )

    if not datasets:
        raise ValueError("Provide at least one labeled dataset.")
    return pd.concat(datasets, ignore_index=True)


def _split_dataset(features, labels, test_size, random_state):
    class_counts = Counter(labels)
    insufficient = {
        SUPERVISED_CLASSES[class_id]: count
        for class_id, count in class_counts.items()
        if count < 2
    }
    if insufficient:
        raise ValueError(
            "Stratified train/test split needs at least two rows per class "
            f"after deduplication; found {insufficient}."
        )

    train_indices = []
    test_indices = []
    for class_id in sorted(class_counts):
        class_indices = [
            index
            for index, label in enumerate(labels)
            if int(label) == int(class_id)
        ]
        class_test_count = min(
            len(class_indices) - 1,
            max(1, math.ceil(len(class_indices) * test_size)),
        )
        class_train, class_test = train_test_split(
            class_indices,
            test_size=class_test_count,
            random_state=random_state + int(class_id),
        )
        train_indices.extend(class_train)
        test_indices.extend(class_test)

    return (
        features.iloc[train_indices],
        features.iloc[test_indices],
        labels[train_indices],
        labels[test_indices],
    )


def train_supervised(
    dataset_paths,
    ground_truth_paths=None,
    label_column=None,
    test_size=0.2,
    random_state=DEFAULT_RANDOM_STATE,
    model_path=DEFAULT_MODEL_PATH,
    metadata_path=DEFAULT_METADATA_PATH,
):
    if not 0 < test_size < 1:
        raise ValueError("--test-size must be between 0 and 1.")

    dataset = load_labeled_datasets(
        dataset_paths,
        ground_truth_paths=ground_truth_paths,
        label_column=label_column,
    )
    original_rows = len(dataset)
    dataset = dataset.drop_duplicates(
        subset=SUPERVISED_FEATURE_NAMES + ["label"]
    ).reset_index(drop=True)
    if dataset.empty:
        raise ValueError("No training rows remain after deduplication.")

    features = dataset[SUPERVISED_FEATURE_NAMES]
    labels = dataset["label"].to_numpy()
    X_train, X_test, y_train, y_test = _split_dataset(
        features,
        labels,
        test_size,
        random_state,
    )

    model = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            (
                "classifier",
                RandomForestClassifier(
                    class_weight="balanced_subsample",
                    random_state=random_state,
                ),
            ),
        ]
    )
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    evaluated_classes = [int(class_id) for class_id in sorted(set(labels))]
    target_names = [
        SUPERVISED_CLASSES[class_id]
        for class_id in evaluated_classes
    ]
    report = classification_report(
        y_test,
        predictions,
        labels=evaluated_classes,
        target_names=target_names,
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=evaluated_classes,
    )
    metrics = {
        "macro_f1": float(
            f1_score(y_test, predictions, average="macro", zero_division=0)
        ),
        "weighted_f1": float(
            f1_score(y_test, predictions, average="weighted", zero_division=0)
        ),
        "per_class": {
            class_name: {
                "precision": float(report[class_name]["precision"]),
                "recall": float(report[class_name]["recall"]),
                "f1": float(report[class_name]["f1-score"]),
                "support": int(report[class_name]["support"]),
            }
            for class_name in target_names
        },
        "confusion_matrix": matrix.tolist(),
        "evaluated_class_ids": evaluated_classes,
        "evaluated_class_names": target_names,
    }

    print(f"Rows before deduplication: {original_rows}")
    print(f"Rows after deduplication:  {len(dataset)}")
    print(f"Macro-F1:                  {metrics['macro_f1']:.4f}")
    print(f"Weighted-F1:               {metrics['weighted_f1']:.4f}")
    print("Per-class precision/recall:")
    for class_name in target_names:
        class_metrics = metrics["per_class"][class_name]
        print(
            f"  {class_name}: precision={class_metrics['precision']:.4f}, "
            f"recall={class_metrics['recall']:.4f}"
        )
    print("Confusion matrix (rows=true, columns=predicted):")
    print(f"Class order: {target_names}")
    print(matrix)

    model.fit(features, labels)
    model_path = Path(model_path)
    metadata_path = Path(metadata_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)

    metadata = {
        "SUPERVISED_CLASSES": SUPERVISED_CLASSES,
        "SUPERVISED_FEATURE_NAMES": SUPERVISED_FEATURE_NAMES,
        "confidence_threshold": CONFIDENCE_THRESHOLD,
        "metrics": metrics,
        "training_rows": len(dataset),
        "rows_before_deduplication": original_rows,
        "random_state": random_state,
        "test_size": test_size,
    }
    with metadata_path.open("w", encoding="utf-8") as metadata_file:
        json.dump(metadata, metadata_file, indent=2)
        metadata_file.write(os.linesep)

    print(f"Saved supervised model:    {model_path}")
    print(f"Saved supervised metadata: {metadata_path}")
    return metrics


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Train an independent supervised SentinelFlow classifier from "
            "labeled CSV/Parquet rows or labeled PCAP windows."
        )
    )
    parser.add_argument(
        "datasets",
        nargs="+",
        help="One or more labeled .csv/.parquet or .pcap/.pcapng datasets.",
    )
    parser.add_argument(
        "--ground-truth",
        action="append",
        help=(
            "Ground-truth JSON for a PCAP; repeat once for each PCAP, "
            "in the order the PCAPs appear."
        ),
    )
    parser.add_argument(
        "--label-column",
        help="Label column for CSV/Parquet (auto-detected if omitted).",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction of rows held out for stratified testing (default: 0.2).",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=DEFAULT_RANDOM_STATE,
        help=f"Random seed for splitting and training (default: {DEFAULT_RANDOM_STATE}).",
    )
    parser.add_argument(
        "--model-output",
        default=str(DEFAULT_MODEL_PATH),
        help=f"Model output path (default: {DEFAULT_MODEL_PATH}).",
    )
    parser.add_argument(
        "--metadata-output",
        default=str(DEFAULT_METADATA_PATH),
        help=f"Metadata output path (default: {DEFAULT_METADATA_PATH}).",
    )
    args = parser.parse_args()

    train_supervised(
        args.datasets,
        ground_truth_paths=args.ground_truth,
        label_column=args.label_column,
        test_size=args.test_size,
        random_state=args.random_state,
        model_path=args.model_output,
        metadata_path=args.metadata_output,
    )


if __name__ == "__main__":
    main()
