import argparse
import json
import logging
import math
import os
import random
import re
import tempfile
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)

from inference.supervised_schema import (
    SUPERVISED_CLASSES,
    SUPERVISED_DEFAULT_VALUES,
    SUPERVISED_FEATURE_NAMES,
    supervised_features_to_vector,
)
from inference.train_supervised import (
    DEFAULT_METADATA_PATH,
    DEFAULT_MODEL_PATH,
    load_labeled_dataset,
    train_supervised,
)


_CLASS_IDS_BY_NAME = {
    class_name: class_id
    for class_id, class_name in SUPERVISED_CLASSES.items()
}
LOGGER = logging.getLogger(__name__)
CSV_CHUNK_SIZE = 100_000
_OUTPUT_COLUMNS = [
    "capture_id",
    "source_ip",
    "window_timestamp",
    *SUPERVISED_FEATURE_NAMES,
    "label",
]


def _normalized_column(name):
    return "".join(character for character in str(name).casefold() if character.isalnum())


def _find_column(columns, candidates):
    normalized_columns = {
        _normalized_column(column): column
        for column in columns
    }
    for candidate in candidates:
        selected = normalized_columns.get(_normalized_column(candidate))
        if selected is not None:
            return selected
    return None


def _select_label_column(columns, requested_column=None):
    if requested_column is not None:
        selected = _find_column(columns, [requested_column])
        if selected is None:
            raise ValueError(f"Label column {requested_column!r} was not found.")
        return selected

    selected = _find_column(columns, ["Label", "Class", "attack_type", "Target"])
    if selected is None:
        raise ValueError(
            "Could not identify the label column. Use --label-column to specify it."
        )
    return selected


def normalize_public_label(value):
    if pd.isna(value):
        raise ValueError("Dataset contains an empty attack label.")

    label = str(value).strip().upper()
    if label in _CLASS_IDS_BY_NAME:
        return _CLASS_IDS_BY_NAME[label]

    try:
        numeric_label = float(label)
    except ValueError:
        numeric_label = math.nan
    if math.isfinite(numeric_label) and numeric_label.is_integer():
        class_id = int(numeric_label)
        if class_id in SUPERVISED_CLASSES:
            return class_id

    compact = re.sub(r"[^a-z0-9]", "", label.casefold())
    if compact in {"benign", "normal", "normaltraffic"}:
        return 0
    if compact in {
        "ddos",
        "dos",
        "doshulk",
        "dosgoldeneye",
        "dosslowloris",
        "dosslowhttptest",
    }:
        return 1
    if any(token in compact for token in ("portscan", "reconnaissance", "recon")):
        return 2
    if any(token in compact for token in ("beacon", "botnet", "bot", "backdoor", "commandandcontrol")):
        return 3
    if any(token in compact for token in ("dga", "dnstunnel", "dnstunnell", "dnstunneling")):
        return 4
    if any(token in compact for token in ("tls", "ssl")):
        return 5
    if any(token in compact for token in ("exfil", "infiltration")):
        return 6
    if any(token in compact for token in ("syn", "ddos", "drdos", "dos", "flood")):
        return 1

    raise ValueError(
        f"Unsupported public dataset label {value!r}. Add an explicit mapping "
        "before preparing this dataset."
    )


def _normalize_label_series(values, ignore_unknown_labels=False):
    normalized = pd.Series(np.nan, index=values.index, dtype=float)
    unknown = Counter()
    for value in pd.unique(values):
        is_missing = pd.isna(value)
        mask = values.isna() if is_missing else values.eq(value)
        try:
            class_id = normalize_public_label(value)
        except ValueError:
            if not ignore_unknown_labels:
                raise
            unknown_label = "<empty>" if is_missing else str(value).strip()
            unknown[unknown_label] += int(mask.sum())
            continue
        normalized.loc[mask] = class_id
    return normalized, unknown


def _log_ignored_labels(unknown, capture_id):
    if not unknown:
        return
    details = ", ".join(
        f"{label!r}: {count}"
        for label, count in sorted(unknown.items(), key=lambda item: item[0].casefold())
    )
    LOGGER.warning(
        "Ignoring %d rows with unsupported labels in %s: %s",
        sum(unknown.values()),
        capture_id,
        details,
    )


def _numeric_series(frame, candidates):
    column = _find_column(frame.columns, candidates)
    if column is None:
        return pd.Series(np.nan, index=frame.index, dtype=float)
    return pd.to_numeric(frame[column], errors="coerce")


def _timestamp_series(frame):
    column = _find_column(
        frame.columns,
        ["window_timestamp", "Timestamp", "Flow Start", "Start Time", "StartTime", "stime"],
    )
    if column is None:
        return pd.Series(np.nan, index=frame.index, dtype=float)

    values = frame[column]
    numeric = pd.to_numeric(values, errors="coerce")
    if numeric.notna().all():
        return numeric.astype(float)

    parsed = pd.to_datetime(values, utc=True, errors="coerce")
    result = pd.Series(np.nan, index=frame.index, dtype=float)
    valid = parsed.notna()
    result.loc[valid] = parsed.loc[valid].astype("int64") / 1_000_000_000.0
    return result


def map_public_csv_frame(
    frame,
    capture_id,
    label_column=None,
    ignore_unknown_labels=False,
):
    """Map common flow-table columns into the fixed supervised feature schema."""
    if frame.empty:
        raise ValueError(f"Dataset contains no rows for capture {capture_id!r}.")

    selected_label = _select_label_column(frame.columns, label_column)
    feature_columns = {
        _normalized_column(column): column
        for column in frame.columns
    }
    features = pd.DataFrame(index=frame.index)
    for name in SUPERVISED_FEATURE_NAMES:
        column = feature_columns.get(_normalized_column(name))
        if column is None:
            features[name] = np.nan
        else:
            features[name] = pd.to_numeric(frame[column], errors="coerce")

    def fill_missing(name, values):
        missing = features[name].isna()
        features.loc[missing, name] = values.loc[missing]

    flow_duration_column = _find_column(
        frame.columns,
        ["Flow Duration", "Flow Duration (us)", "Flow Duration Microseconds", "dur", "Duration"],
    )
    duration_seconds = pd.Series(np.nan, index=frame.index, dtype=float)
    if flow_duration_column is not None:
        duration = pd.to_numeric(frame[flow_duration_column], errors="coerce")
        normalized_duration = _normalized_column(flow_duration_column)
        if normalized_duration.startswith("flowduration"):
            duration_seconds = duration / 1_000_000.0
        else:
            duration_seconds = duration
        duration_seconds = duration_seconds.where(duration_seconds > 0)

    fwd_packets = _numeric_series(
        frame,
        ["Total Fwd Packets", "Tot Fwd Pkts", "Fwd Packets", "spkts"],
    )
    bwd_packets = _numeric_series(
        frame,
        ["Total Backward Packets", "Tot Bwd Pkts", "Bwd Packets", "dpkts"],
    )
    packet_total = fwd_packets.fillna(0.0) + bwd_packets.fillna(0.0)

    fwd_bytes = _numeric_series(
        frame,
        [
            "Total Length of Fwd Packets",
            "Fwd Packet Length Total",
            "TotLen Fwd Pkts",
            "sbytes",
        ],
    )
    bwd_bytes = _numeric_series(
        frame,
        [
            "Total Length of Bwd Packets",
            "Bwd Packet Length Total",
            "TotLen Bwd Pkts",
            "dbytes",
        ],
    )
    byte_total = fwd_bytes.fillna(0.0) + bwd_bytes.fillna(0.0)

    flow_packet_rate = _numeric_series(
        frame,
        ["Flow Packets/s", "Packets/s", "Total Packets/s"],
    )
    fwd_packet_rate = _numeric_series(frame, ["Fwd Packets/s", "Fwd Pkts/s"])
    bwd_packet_rate = _numeric_series(frame, ["Bwd Packets/s", "Bwd Pkts/s"])
    combined_packet_rate = fwd_packet_rate.fillna(0.0) + bwd_packet_rate.fillna(0.0)
    combined_packet_rate = combined_packet_rate.where(
        fwd_packet_rate.notna() | bwd_packet_rate.notna()
    )
    derived_packet_rate = packet_total / duration_seconds
    packet_rate = flow_packet_rate.fillna(combined_packet_rate).fillna(derived_packet_rate)
    fill_missing("packets_per_second", packet_rate)

    flow_byte_rate = _numeric_series(
        frame,
        ["Flow Bytes/s", "Bytes/s", "Total Bytes/s"],
    )
    fill_missing("bytes_per_second", flow_byte_rate.fillna(byte_total / duration_seconds))

    destination_port_column = _find_column(
        frame.columns,
        ["Destination Port", "Dst Port", "dport", "dp"],
    )
    destination_ip_column = _find_column(
        frame.columns,
        ["Destination IP", "Dst IP", "dstip", "dst"],
    )
    has_destination = destination_port_column is not None or destination_ip_column is not None
    if has_destination:
        unique_destinations = pd.Series(1.0, index=frame.index)
        fill_missing("unique_destinations", unique_destinations)
    if destination_port_column is not None:
        destination_port = pd.to_numeric(frame[destination_port_column], errors="coerce")
        unique_ports = destination_port.notna().astype(float)
        fill_missing("unique_destination_ports", unique_ports)
        fill_missing("rolling_unique_destination_ports", unique_ports)

    flow_marker = _find_column(frame.columns, ["Flow ID", "Flow Duration", "dur"])
    if flow_marker is not None:
        fill_missing("active_flows", pd.Series(1.0, index=frame.index))

    fill_missing("bytes_received", bwd_bytes)
    fill_missing("exfil_bytes_sent", fwd_bytes)
    fill_missing("exfil_bytes_received", bwd_bytes)
    fill_missing("exfil_bytes_per_second", fwd_bytes / duration_seconds)

    sent = fwd_bytes.fillna(0.0)
    received = bwd_bytes.fillna(0.0)
    ratio = pd.Series(np.nan, index=frame.index, dtype=float)
    ratio.loc[received > 0] = sent.loc[received > 0] / received.loc[received > 0]
    ratio.loc[(received == 0) & (sent > 0)] = sent.loc[(received == 0) & (sent > 0)]
    fill_missing("outbound_inbound_ratio", ratio)
    fill_missing("exfil_outbound_inbound_ratio", ratio)

    syn_count = _numeric_series(frame, ["SYN Flag Count", "SYN Flag Cnt", "Syn Count"])
    rst_count = _numeric_series(frame, ["RST Flag Count", "RST Flag Cnt", "Rst Count"])
    syn_ratio = syn_count / packet_total.where(packet_total > 0)
    rst_ratio = rst_count / packet_total.where(packet_total > 0)
    fill_missing("syn_packet_ratio", syn_ratio)
    fill_missing("rolling_syn_ratio", syn_ratio)
    fill_missing("rst_packet_ratio", rst_ratio)

    unique_destinations = features["unique_destinations"].fillna(0.0)
    unique_ports = features["unique_destination_ports"].fillna(0.0)
    ports_per_destination = unique_ports / unique_destinations.where(unique_destinations > 0)
    fill_missing("ports_per_destination", ports_per_destination)

    for name in SUPERVISED_FEATURE_NAMES:
        features[name] = (
            pd.to_numeric(features[name], errors="coerce")
            .replace([np.inf, -np.inf], np.nan)
            .fillna(float(SUPERVISED_DEFAULT_VALUES[name]))
        )

    labels, unknown = _normalize_label_series(
        frame[selected_label],
        ignore_unknown_labels=ignore_unknown_labels,
    )
    _log_ignored_labels(unknown, capture_id)
    supported_rows = labels.notna()
    if not supported_rows.any():
        raise ValueError(
            f"No supported labels remain in capture {capture_id!r}."
        )
    source_column = _find_column(
        frame.columns,
        ["Source IP", "Src IP", "srcip", "src"],
    )
    source_ips = (
        frame[source_column].fillna("").astype(str)
        if source_column is not None
        else pd.Series("", index=frame.index)
    )

    result = features.copy()
    result.insert(0, "capture_id", str(capture_id))
    result.insert(1, "source_ip", source_ips)
    result.insert(2, "window_timestamp", _timestamp_series(frame))
    result["label"] = labels.loc[supported_rows].astype(int)
    return result.loc[supported_rows, _OUTPUT_COLUMNS]


def _read_table(path):
    suffix = path.suffix.casefold()
    if suffix == ".csv":
        try:
            return pd.read_csv(path, encoding="utf-8-sig")
        except UnicodeDecodeError:
            LOGGER.info("Retrying %s using cp1252 encoding.", path)
            return pd.read_csv(path, encoding="cp1252")
    if suffix in {".parquet", ".pq"}:
        try:
            return pd.read_parquet(path)
        except ImportError as error:
            raise RuntimeError(
                "Reading Parquet requires an installed engine such as pyarrow "
                "or fastparquet."
            ) from error
    raise ValueError(f"Unsupported tabular input: {path}")


def _capture_aliases(path, capture_id):
    return {
        str(capture_id).casefold(),
        path.name.casefold(),
        path.stem.casefold(),
        str(path.resolve()).casefold(),
    }


def _resolve_capture_id(selector, capture_paths):
    selector_text = str(selector)
    selector_path = Path(selector_text)
    selector_aliases = {
        selector_text.casefold(),
        selector_path.name.casefold(),
        selector_path.stem.casefold(),
    }
    matches = []
    for path, capture_id in capture_paths:
        if selector_aliases.intersection(_capture_aliases(path, capture_id)):
            matches.append(capture_id)
    if len(matches) != 1:
        raise ValueError(
            f"Ground-truth capture {selector!r} matched {len(matches)} input files."
        )
    return matches[0]


def _flatten_ground_truth(manifest, capture_paths):
    entries = []

    def add_entries(items, capture_selector=None):
        if not isinstance(items, list):
            raise ValueError("Ground-truth labels for each capture must be a list.")
        for entry in items:
            if not isinstance(entry, dict):
                raise ValueError("Each ground-truth label must be a JSON object.")
            flattened = dict(entry)
            if capture_selector is not None and not any(
                key in flattened for key in ("capture_id", "capture", "pcap", "file")
            ):
                flattened["capture_id"] = capture_selector
            entries.append(flattened)

    if isinstance(manifest, list):
        add_entries(manifest)
    elif isinstance(manifest, dict) and isinstance(manifest.get("labels"), list):
        add_entries(manifest["labels"])
    elif isinstance(manifest, dict) and (
        "expected_detections" in manifest or "benign_ips" in manifest
    ):
        selector = manifest.get("pcap_file")
        expected = manifest.get("expected_detections", [])
        benign_ips = manifest.get("benign_ips", [])
        if not isinstance(expected, list) or not isinstance(benign_ips, list):
            raise ValueError(
                "Ground-truth expected_detections and benign_ips must be lists."
            )
        for detection in expected:
            if not isinstance(detection, dict):
                raise ValueError("Each expected detection must be a JSON object.")
            entry = dict(detection)
            if selector is not None:
                entry.setdefault("capture_id", selector)
            entries.append(entry)
        for source_ip in benign_ips:
            entry = {"source_ip": source_ip, "attack_type": "BENIGN"}
            if selector is not None:
                entry["capture_id"] = selector
            entries.append(entry)
    elif isinstance(manifest, dict) and isinstance(manifest.get("captures"), list):
        for capture in manifest["captures"]:
            if not isinstance(capture, dict):
                raise ValueError("Each ground-truth capture must be a JSON object.")
            selector = (
                capture.get("capture_id")
                or capture.get("pcap")
                or capture.get("file")
                or capture.get("name")
            )
            labels = capture.get("labels")
            if selector is None or labels is None:
                raise ValueError(
                    "Each capture entry needs a capture_id/file and labels list."
                )
            add_entries(labels, selector)
    elif isinstance(manifest, dict) and isinstance(manifest.get("captures"), dict):
        for selector, labels in manifest["captures"].items():
            if isinstance(labels, dict):
                labels = labels.get("labels")
            add_entries(labels, selector)
    elif isinstance(manifest, dict):
        add_entries_by_capture = True
        for selector, labels in manifest.items():
            if not isinstance(labels, list):
                add_entries_by_capture = False
                break
        if not add_entries_by_capture:
            raise ValueError(
                "Ground truth must be a list, contain a labels list, or map "
                "capture IDs to label lists."
            )
        for selector, labels in manifest.items():
            add_entries(labels, selector)
    else:
        raise ValueError("Ground-truth JSON must contain an object or a list.")

    if len(capture_paths) > 1:
        missing_capture = [
            entry for entry in entries
            if not any(key in entry for key in ("capture_id", "capture", "pcap", "file"))
        ]
        if missing_capture:
            raise ValueError(
                "Ground-truth entries for multiple PCAPs must identify capture_id "
                "or be nested under a capture in the JSON file."
            )

    by_capture = {capture_id: [] for _, capture_id in capture_paths}
    for entry in entries:
        selector = (
            entry.get("capture_id")
            or entry.get("capture")
            or entry.get("pcap")
            or entry.get("file")
        )
        if selector is None:
            if len(capture_paths) != 1:
                raise ValueError("Ground-truth entry is missing its capture ID.")
            capture_id = capture_paths[0][1]
        else:
            capture_id = _resolve_capture_id(selector, capture_paths)

        source_ip = entry.get("source_ip")
        start_ts = entry.get("start_ts")
        end_ts = entry.get("end_ts")
        attack_type = entry.get("attack_type")
        if not source_ip or attack_type is None:
            raise ValueError(
                "Ground-truth entries require source_ip and attack_type, "
                f"and attack_type: {entry!r}"
            )
        if (start_ts is None) != (end_ts is None):
            raise ValueError(
                f"Ground-truth intervals require both start_ts and end_ts: {entry!r}"
            )
        if start_ts is not None:
            try:
                start_ts = float(start_ts)
                end_ts = float(end_ts)
            except (TypeError, ValueError) as error:
                raise ValueError(f"Invalid ground-truth interval: {entry!r}") from error
            if (
                not math.isfinite(start_ts)
                or not math.isfinite(end_ts)
                or start_ts >= end_ts
            ):
                raise ValueError(f"Invalid ground-truth interval: {entry!r}")

        by_capture[capture_id].append(
            {
                "source_ip": str(source_ip),
                "start_ts": start_ts,
                "end_ts": end_ts,
                "class_id": normalize_public_label(attack_type),
            }
        )
    return by_capture


def _load_pcap_rows(input_paths, ground_truth_path):
    if ground_truth_path is None:
        raise ValueError("PCAP mode requires --ground-truth.")

    capture_paths = [(path, path.name) for path in input_paths]
    if len({capture_id.casefold() for _, capture_id in capture_paths}) != len(capture_paths):
        raise ValueError("PCAP input basenames must be unique to form capture_id values.")

    with Path(ground_truth_path).open("r", encoding="utf-8") as file:
        manifest = json.load(file)
    labels_by_capture = _flatten_ground_truth(manifest, capture_paths)

    from inference.train_model_from_pcap import extract_training_vectors

    rows = []
    for pcap_path, capture_id in capture_paths:
        capture_records = []
        extract_training_vectors(str(pcap_path), capture_records=capture_records)
        capture_labels = labels_by_capture[capture_id]
        for record in capture_records:
            timestamp = float(record["window_timestamp"])
            midpoint = float(record.get("window_start", timestamp - 1.0)) + 0.5
            matching_classes = {
                label["class_id"]
                for label in capture_labels
                if label["source_ip"] == str(record["source_ip"])
                and (
                    label["start_ts"] is None
                    or label["start_ts"] <= midpoint < label["end_ts"]
                )
            }
            if not matching_classes:
                continue
            if len(matching_classes) != 1:
                raise ValueError(
                    "Overlapping ground-truth intervals assign different labels "
                    f"to source {record['source_ip']} at {midpoint}."
                )
            vector = supervised_features_to_vector(record["features"])
            row = dict(zip(SUPERVISED_FEATURE_NAMES, vector))
            row.update(
                capture_id=capture_id,
                source_ip=str(record["source_ip"]),
                window_timestamp=timestamp,
                label=matching_classes.pop(),
            )
            rows.append(row)

    if not rows:
        raise ValueError("No extracted PCAP windows matched the ground-truth labels.")
    return pd.DataFrame(rows, columns=_OUTPUT_COLUMNS)


def _count_csv_labels(path, label_column, encoding, ignore_unknown_labels):
    header = pd.read_csv(path, nrows=0, encoding=encoding)
    selected_label = _select_label_column(header.columns, label_column)
    class_counts = Counter()
    unknown = Counter()
    for chunk in pd.read_csv(
        path,
        usecols=[selected_label],
        chunksize=CSV_CHUNK_SIZE,
        encoding=encoding,
        low_memory=False,
    ):
        labels, chunk_unknown = _normalize_label_series(
            chunk[selected_label],
            ignore_unknown_labels=ignore_unknown_labels,
        )
        for class_id in labels.dropna().unique():
            class_counts[int(class_id)] += int(labels.eq(class_id).sum())
        unknown.update(chunk_unknown)
    return selected_label, class_counts, unknown


def _load_sampled_csv_capture(
    path,
    label_column,
    ignore_unknown_labels,
    max_rows_per_class,
    encoding_override=None,
):
    encodings = (
        [encoding_override]
        if encoding_override is not None
        else ["utf-8-sig", "cp1252"]
    )
    last_decode_error = None
    for encoding in encodings:
        try:
            selected_label, class_counts, unknown = _count_csv_labels(
                path,
                label_column,
                encoding,
                ignore_unknown_labels,
            )
            break
        except UnicodeDecodeError as error:
            last_decode_error = error
    else:
        raise last_decode_error

    _log_ignored_labels(unknown, path.name)
    if not class_counts:
        raise ValueError(f"No supported labels remain in capture {path}.")

    selected_occurrences = {
        class_id: np.linspace(
            0,
            count - 1,
            min(count, max_rows_per_class),
            dtype=np.int64,
        )
        for class_id, count in class_counts.items()
    }

    def read_chunks():
        return pd.read_csv(
            path,
            chunksize=CSV_CHUNK_SIZE,
            encoding=encoding,
            low_memory=False,
        )

    selected_frames = []
    seen = Counter()
    row_offset = 0
    try:
        for chunk in read_chunks():
            chunk.index = range(row_offset, row_offset + len(chunk))
            row_offset += len(chunk)
            labels, _ = _normalize_label_series(
                chunk[selected_label],
                ignore_unknown_labels=ignore_unknown_labels,
            )
            supported = labels.notna()
            if not supported.any():
                continue
            mapped = map_public_csv_frame(
                chunk.loc[supported],
                capture_id=path.name,
                label_column=selected_label,
                ignore_unknown_labels=False,
            )
            for class_id, class_rows in mapped.groupby("label", sort=False):
                class_id = int(class_id)
                begin = seen[class_id]
                end = begin + len(class_rows)
                candidates = np.arange(begin, end, dtype=np.int64)
                keep = np.isin(candidates, selected_occurrences[class_id])
                if keep.any():
                    selected_frames.append(class_rows.iloc[keep])
                seen[class_id] = end
    except UnicodeDecodeError as error:
        if encoding != "utf-8-sig":
            raise
        LOGGER.info("Retrying %s using cp1252 encoding.", path)
        return _load_sampled_csv_capture(
            path,
            label_column,
            ignore_unknown_labels,
            max_rows_per_class,
            encoding_override="cp1252",
        )

    if not selected_frames:
        raise ValueError(f"No supported rows could be sampled from {path}.")
    sampled = pd.concat(selected_frames, ignore_index=True)
    retained = sampled["label"].value_counts().to_dict()
    LOGGER.info(
        "Sampled %d rows from %s (per-class cap %d; class rows %s).",
        len(sampled),
        path,
        max_rows_per_class,
        {
            SUPERVISED_CLASSES[int(class_id)]: int(count)
            for class_id, count in retained.items()
        },
    )
    return sampled


def _load_csv_rows(
    input_paths,
    label_column=None,
    ignore_unknown_labels=False,
    max_rows_per_class_per_capture=None,
):
    frames = []
    for path in input_paths:
        if (
            max_rows_per_class_per_capture is not None
            and path.suffix.casefold() == ".csv"
        ):
            frames.append(
                _load_sampled_csv_capture(
                    path,
                    label_column,
                    ignore_unknown_labels,
                    max_rows_per_class_per_capture,
                )
            )
            continue

        frame = _read_table(path)
        frames.append(
            map_public_csv_frame(
                frame,
                capture_id=path.name,
                label_column=label_column,
                ignore_unknown_labels=ignore_unknown_labels,
            )
        )
    if not frames:
        raise ValueError("Provide at least one CSV or Parquet input.")
    return pd.concat(frames, ignore_index=True)


def deduplicate_feature_rows(frame):
    """Drop ambiguous vectors and deduplicate rows before any split."""
    feature_and_label = frame.drop_duplicates(
        subset=SUPERVISED_FEATURE_NAMES + ["label"]
    )
    conflicts = feature_and_label.duplicated(
        subset=SUPERVISED_FEATURE_NAMES,
        keep=False,
    )
    if conflicts.any():
        conflicting_rows = feature_and_label.loc[conflicts]
        conflicting_labels = sorted(
            SUPERVISED_CLASSES[int(value)]
            for value in conflicting_rows["label"].unique()
        )
        conflicting_features = conflicting_rows[
            SUPERVISED_FEATURE_NAMES
        ].drop_duplicates()
        marked = frame.merge(
            conflicting_features.assign(_ambiguous_feature=True),
            on=SUPERVISED_FEATURE_NAMES,
            how="left",
        )
        ambiguous_rows = marked["_ambiguous_feature"].notna()
        LOGGER.warning(
            "Dropping %d rows across %d feature vectors with conflicting labels "
            "%s.",
            int(ambiguous_rows.sum()),
            len(conflicting_features),
            conflicting_labels,
        )
        frame = marked.loc[~ambiguous_rows, frame.columns]
    return frame.drop_duplicates(
        subset=SUPERVISED_FEATURE_NAMES
    ).reset_index(drop=True)


def _sort_chronologically(frame):
    if "window_timestamp" not in frame or frame["window_timestamp"].isna().any():
        raise ValueError(
            "Chronological splitting requires a timestamp column in every row. "
            "Use multiple capture files or provide timestamps."
        )
    return frame.sort_values(
        ["window_timestamp", "capture_id"],
        kind="mergesort",
    )


def _split_one_capture_chronologically(frame, validation_size):
    ordered = _sort_chronologically(frame)
    if len(ordered) < 3:
        raise ValueError(
            "At least three rows are required to create train and validation "
            "partitions within one capture."
        )
    validation_count = max(1, math.ceil(len(ordered) * validation_size))
    if validation_count >= len(ordered):
        raise ValueError("Validation split leaves no training rows.")
    return ordered.iloc[:-validation_count], ordered.iloc[-validation_count:]


def _split_capture_label_groups_chronologically(frame):
    ordered = _sort_chronologically(frame)
    partitions = {"train": [], "validation": [], "test": []}

    for _, group in ordered.groupby(
        ["capture_id", "label"],
        sort=False,
        dropna=False,
    ):
        group = group.sort_values("window_timestamp", kind="mergesort")
        row_count = len(group)
        if row_count == 1:
            train_end = 1
            validation_end = 1
        elif row_count == 2:
            train_end = 1
            validation_end = 1
        else:
            train_end = max(
                1,
                min(math.floor(row_count * 0.70), row_count - 2),
            )
            validation_end = max(
                train_end + 1,
                min(math.floor(row_count * 0.85), row_count - 1),
            )

        partitions["train"].append(group.iloc[:train_end])
        partitions["validation"].append(group.iloc[train_end:validation_end])
        partitions["test"].append(group.iloc[validation_end:])

    result = {
        name: pd.concat(groups, ignore_index=True)
        if groups
        else ordered.iloc[0:0].copy()
        for name, groups in partitions.items()
    }
    if any(partition.empty for partition in result.values()):
        raise ValueError(
            "Chronological splitting needs enough capture/label rows to create "
            "non-empty train, validation, and test partitions."
        )
    return result


def split_prepared_rows(
    frame,
    strategy="capture",
    test_size=0.2,
    validation_size=0.2,
    random_state=42,
):
    if not 0 < test_size < 1 or not 0 < validation_size < 1:
        raise ValueError("Split sizes must be between 0 and 1.")
    if test_size + validation_size >= 1:
        raise ValueError("Test and validation fractions must sum to less than 1.")
    if frame.empty:
        raise ValueError("Cannot split an empty dataset.")
    if strategy not in {"capture", "chronological"}:
        raise ValueError("Split strategy must be 'capture' or 'chronological'.")

    capture_ids = list(pd.unique(frame["capture_id"]))
    if strategy == "chronological":
        return {
            name: partition.reset_index(drop=True)
            for name, partition in _split_capture_label_groups_chronologically(
                frame
            ).items()
        }
    if len(capture_ids) == 1:
        ordered = _sort_chronologically(frame)
        row_count = len(ordered)
        test_count = max(1, math.ceil(row_count * test_size))
        validation_count = max(1, math.ceil(row_count * validation_size))
        train_count = row_count - test_count - validation_count
        if train_count < 1:
            raise ValueError(
                "Not enough rows to create non-empty train, validation, and test splits."
            )
        train_end = train_count
        validation_end = train_count + validation_count
        return {
            "train": ordered.iloc[:train_end].reset_index(drop=True),
            "validation": ordered.iloc[train_end:validation_end].reset_index(drop=True),
            "test": ordered.iloc[validation_end:].reset_index(drop=True),
        }

    randomizer = random.Random(random_state)
    randomizer.shuffle(capture_ids)
    if len(capture_ids) == 2:
        test_capture = capture_ids[0]
        train_capture = capture_ids[1]
        train_and_validation = frame[frame["capture_id"] == train_capture]
        train, validation = _split_one_capture_chronologically(
            train_and_validation,
            validation_size,
        )
        test = frame[frame["capture_id"] == test_capture]
        return {
            "train": train.reset_index(drop=True),
            "validation": validation.reset_index(drop=True),
            "test": test.reset_index(drop=True),
        }

    test_count = max(1, math.ceil(len(capture_ids) * test_size))
    validation_count = max(1, math.ceil(len(capture_ids) * validation_size))
    while test_count + validation_count >= len(capture_ids):
        if test_count >= validation_count and test_count > 1:
            test_count -= 1
        elif validation_count > 1:
            validation_count -= 1
        else:
            raise ValueError("At least three capture files are needed for capture splitting.")

    test_captures = set(capture_ids[:test_count])
    validation_captures = set(
        capture_ids[test_count:test_count + validation_count]
    )
    train_captures = set(capture_ids[test_count + validation_count:])
    return {
        "train": frame[frame["capture_id"].isin(train_captures)].reset_index(drop=True),
        "validation": frame[
            frame["capture_id"].isin(validation_captures)
        ].reset_index(drop=True),
        "test": frame[frame["capture_id"].isin(test_captures)].reset_index(drop=True),
    }


def feature_overlap_count(left, right):
    left_rows = left[SUPERVISED_FEATURE_NAMES].drop_duplicates()
    right_rows = right[SUPERVISED_FEATURE_NAMES].drop_duplicates()
    return int(
        left_rows.merge(
            right_rows,
            on=SUPERVISED_FEATURE_NAMES,
            how="inner",
        ).shape[0]
    )


def calibrate_confidence_threshold(
    y_true,
    probabilities,
    classes,
    benign_fpr_limit=0.01,
):
    y_true = np.asarray(y_true, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    classes = np.asarray(classes, dtype=int)
    if probabilities.ndim != 2 or probabilities.shape != (len(y_true), len(classes)):
        raise ValueError("Probability matrix shape does not match labels and classes.")
    benign_rows = y_true == 0
    if not benign_rows.any():
        raise ValueError("Threshold calibration requires benign validation rows.")
    if not 0 <= benign_fpr_limit <= 1:
        raise ValueError("Benign false-positive rate limit must be between 0 and 1.")

    top_columns = probabilities.argmax(axis=1)
    top_classes = classes[top_columns]
    top_confidence = probabilities[np.arange(len(y_true)), top_columns]
    candidates = [round(0.60 + step * 0.01, 2) for step in range(36)]
    feasible = []

    for threshold in candidates:
        predictions = np.where(
            (top_classes != 0) & (top_confidence >= threshold),
            top_classes,
            0,
        )
        benign_fpr = float(np.mean(predictions[benign_rows] != 0))
        if benign_fpr <= benign_fpr_limit:
            macro_f1 = float(
                f1_score(
                    y_true,
                    predictions,
                    labels=list(SUPERVISED_CLASSES),
                    average="macro",
                    zero_division=0,
                )
            )
            feasible.append(
                {
                    "confidence_threshold": threshold,
                    "macro_f1": macro_f1,
                    "benign_false_positive_rate": benign_fpr,
                }
            )

    if not feasible:
        raise ValueError(
            "No threshold from 0.60 to 0.95 satisfies the benign false-positive "
            f"rate limit of {benign_fpr_limit:.1%}."
        )
    return max(
        feasible,
        key=lambda result: (
            result["macro_f1"],
            -result["benign_false_positive_rate"],
            result["confidence_threshold"],
        ),
    )


def _train_and_calibrate(
    train_path,
    validation_path,
    test_path,
    feature_overlap,
    model_path,
    metadata_path,
    random_state,
    benign_fpr_limit,
):
    with tempfile.TemporaryDirectory(prefix="sentinelflow-supervised-") as temp_dir:
        temporary_model = Path(temp_dir) / "model.joblib"
        temporary_metadata = Path(temp_dir) / "metadata.json"
        train_metrics = train_supervised(
            train_path,
            random_state=random_state,
            model_path=temporary_model,
            metadata_path=temporary_metadata,
        )
        model = joblib.load(temporary_model)
        validation = load_labeled_dataset(validation_path)
        y_validation = validation["label"].to_numpy(dtype=int)
        probabilities = model.predict_proba(
            validation[SUPERVISED_FEATURE_NAMES]
        )
        calibration = calibrate_confidence_threshold(
            y_validation,
            probabilities,
            model.classes_,
            benign_fpr_limit=benign_fpr_limit,
        )
        with temporary_metadata.open("r", encoding="utf-8") as file:
            metadata = json.load(file)

    metadata["confidence_threshold"] = calibration["confidence_threshold"]
    metadata["threshold_calibration"] = {
        **calibration,
        "benign_false_positive_rate_limit": benign_fpr_limit,
        "validation_rows": int(len(y_validation)),
        "method": "maximum macro-F1 subject to benign FPR limit",
    }
    metadata["metrics"]["validation_macro_f1"] = calibration["macro_f1"]
    test_metrics = _evaluate_held_out(
        model,
        test_path,
        confidence_threshold=calibration["confidence_threshold"],
        feature_overlap=feature_overlap,
    )
    metadata["metrics"]["held_out_test"] = test_metrics
    model_path = Path(model_path)
    metadata_path = Path(metadata_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)
    with metadata_path.open("w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=2)
        file.write(os.linesep)

    print(
        "Calibrated confidence threshold: "
        f"{calibration['confidence_threshold']:.2f} "
        f"(validation macro-F1={calibration['macro_f1']:.4f}, "
        f"benign FPR={calibration['benign_false_positive_rate']:.2%})"
    )
    print(
        f"Held-out test macro-F1: {test_metrics['macro_f1']:.4f} "
        f"(weighted-F1={test_metrics['weighted_f1']:.4f}, "
        f"benign FPR={test_metrics['benign_false_positive_rate']:.2%}, "
        f"feature overlap={test_metrics['feature_overlap_count']})"
    )
    print("Held-out per-class precision / recall / F1:")
    for class_name, class_metrics in test_metrics["per_class"].items():
        print(
            f"  {class_name}: precision={class_metrics['precision']:.4f}, "
            f"recall={class_metrics['recall']:.4f}, "
            f"F1={class_metrics['f1']:.4f}, "
            f"support={class_metrics['support']}"
        )
    print(f"Saved supervised model:    {model_path}")
    print(f"Saved supervised metadata: {metadata_path}")
    return train_metrics, calibration, test_metrics


def _evaluate_held_out(
    model,
    test_path,
    confidence_threshold,
    feature_overlap,
):
    test = load_labeled_dataset(test_path)
    y_true = test["label"].to_numpy(dtype=int)
    probabilities = model.predict_proba(test[SUPERVISED_FEATURE_NAMES])
    classes = np.asarray(model.classes_, dtype=int)
    top_columns = probabilities.argmax(axis=1)
    top_classes = classes[top_columns]
    top_confidence = probabilities[np.arange(len(y_true)), top_columns]
    predictions = np.where(
        (top_classes != 0) & (top_confidence >= confidence_threshold),
        top_classes,
        0,
    )
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true,
        predictions,
        labels=list(SUPERVISED_CLASSES),
        zero_division=0,
    )
    benign_rows = y_true == 0
    benign_false_positive_rate = (
        float(np.mean(predictions[benign_rows] != 0))
        if benign_rows.any()
        else None
    )
    return {
        "macro_f1": float(
            f1_score(
                y_true,
                predictions,
                labels=list(SUPERVISED_CLASSES),
                average="macro",
                zero_division=0,
            )
        ),
        "weighted_f1": float(
            f1_score(y_true, predictions, average="weighted", zero_division=0)
        ),
        "per_class": {
            SUPERVISED_CLASSES[class_id]: {
                "precision": float(precision[class_id]),
                "recall": float(recall[class_id]),
                "f1": float(f1[class_id]),
                "support": int(support[class_id]),
            }
            for class_id in SUPERVISED_CLASSES
        },
        "confusion_matrix": confusion_matrix(
            y_true,
            predictions,
            labels=list(SUPERVISED_CLASSES),
        ).tolist(),
        "feature_overlap_count": int(feature_overlap),
        "benign_false_positive_rate": benign_false_positive_rate,
        "rows": int(len(y_true)),
        "confidence_threshold": float(confidence_threshold),
    }


def _supplement_paths(pcap_paths, ground_truth_paths):
    pcap_paths = [] if pcap_paths is None else [Path(path) for path in pcap_paths]
    ground_truth_paths = (
        []
        if ground_truth_paths is None
        else [Path(path) for path in ground_truth_paths]
    )
    if bool(pcap_paths) != bool(ground_truth_paths):
        raise ValueError(
            "--supplement-pcap and --supplement-ground-truth must be provided together."
        )
    if len(pcap_paths) != len(ground_truth_paths):
        raise ValueError(
            "Provide one --supplement-ground-truth file for each supplement PCAP."
        )
    for pcap_path, ground_truth_path in zip(pcap_paths, ground_truth_paths):
        if not pcap_path.is_file():
            raise FileNotFoundError(f"Supplement PCAP not found: {pcap_path}")
        if pcap_path.suffix.casefold() not in {".pcap", ".pcapng"}:
            raise ValueError(f"Unsupported supplement PCAP: {pcap_path}")
        if not ground_truth_path.is_file():
            raise FileNotFoundError(
                f"Supplement ground-truth file not found: {ground_truth_path}"
            )
    return pcap_paths, ground_truth_paths


def _append_supplement_rows(splits, supplement_rows):
    held_out = pd.concat(
        [splits["validation"], splits["test"]],
        ignore_index=True,
    )
    held_out_keys = held_out[SUPERVISED_FEATURE_NAMES + ["label"]].drop_duplicates(
        subset=SUPERVISED_FEATURE_NAMES
    )
    matching = supplement_rows.merge(
        held_out_keys,
        on=SUPERVISED_FEATURE_NAMES,
        how="inner",
        suffixes=("_supplement", "_held_out"),
    )
    conflicting = matching[
        matching["label_supplement"] != matching["label_held_out"]
    ]
    if not conflicting.empty:
        raise ValueError(
            "Supplement PCAP features conflict with held-out labels; refusing "
            "to introduce leakage or ambiguous training labels."
        )

    held_out_features = held_out_keys[SUPERVISED_FEATURE_NAMES]
    candidates = supplement_rows.merge(
        held_out_features,
        on=SUPERVISED_FEATURE_NAMES,
        how="left",
        indicator=True,
    )
    held_out_overlap = int((candidates["_merge"] == "both").sum())
    supplement_rows = candidates.loc[
        candidates["_merge"] == "left_only",
        _OUTPUT_COLUMNS,
    ]
    if held_out_overlap:
        LOGGER.info(
            "Excluded %d supplement rows whose feature vectors occur in held-out "
            "validation/test data.",
            held_out_overlap,
        )

    original_train_rows = len(splits["train"])
    combined_train = pd.concat(
        [splits["train"], supplement_rows],
        ignore_index=True,
    )
    splits["train"] = deduplicate_feature_rows(combined_train)
    return int(len(splits["train"]) - original_train_rows)


def prepare_public_dataset(
    mode,
    input_paths,
    output_dir,
    ground_truth_path=None,
    label_column=None,
    split_strategy="capture",
    test_size=0.2,
    validation_size=0.2,
    random_state=42,
    calibrate_threshold=False,
    benign_fpr_limit=0.01,
    ignore_unknown_labels=False,
    max_rows_per_class_per_capture=None,
    supplement_pcap_paths=None,
    supplement_ground_truth_paths=None,
    model_path=DEFAULT_MODEL_PATH,
    metadata_path=DEFAULT_METADATA_PATH,
):
    paths = [Path(path) for path in input_paths]
    supplement_pcaps, supplement_ground_truths = _supplement_paths(
        supplement_pcap_paths,
        supplement_ground_truth_paths,
    )
    if (
        max_rows_per_class_per_capture is not None
        and max_rows_per_class_per_capture < 1
    ):
        raise ValueError("max_rows_per_class_per_capture must be positive.")
    if not paths:
        raise ValueError("Provide one or more input captures or tables.")
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f"Input dataset not found: {path}")

    if mode == "pcap":
        if supplement_pcaps:
            raise ValueError(
                "Supplement PCAPs are supported only in CSV mode; include all "
                "captures in --inputs for PCAP mode."
            )
        if any(path.suffix.casefold() not in {".pcap", ".pcapng"} for path in paths):
            raise ValueError("PCAP mode accepts only .pcap or .pcapng inputs.")
        rows = _load_pcap_rows(paths, ground_truth_path)
    elif mode == "csv":
        if any(path.suffix.casefold() not in {".csv", ".parquet", ".pq"} for path in paths):
            raise ValueError("CSV mode accepts only .csv, .parquet, or .pq inputs.")
        if ground_truth_path is not None:
            raise ValueError("--ground-truth is only used in PCAP mode.")
        rows = _load_csv_rows(
            paths,
            label_column=label_column,
            ignore_unknown_labels=ignore_unknown_labels,
            max_rows_per_class_per_capture=max_rows_per_class_per_capture,
        )
    else:
        raise ValueError("Mode must be 'pcap' or 'csv'.")

    supplement_rows = None
    if supplement_pcaps:
        supplement_frames = [
            _load_pcap_rows([pcap_path], ground_truth_path)
            for pcap_path, ground_truth_path in zip(
                supplement_pcaps,
                supplement_ground_truths,
            )
        ]
        supplement_rows = pd.concat(supplement_frames, ignore_index=True)
        if split_strategy == "chronological":
            rows = pd.concat([rows, supplement_rows], ignore_index=True)

    rows = deduplicate_feature_rows(rows)
    splits = split_prepared_rows(
        rows,
        strategy=split_strategy,
        test_size=test_size,
        validation_size=validation_size,
        random_state=random_state,
    )
    supplement_rows_added = 0
    if supplement_rows is not None and split_strategy != "chronological":
        supplement_rows_added = _append_supplement_rows(splits, supplement_rows)

    supplement_capture_ids = (
        set(supplement_rows["capture_id"].astype(str).unique())
        if supplement_rows is not None
        else set()
    )
    supplement_rows_by_split = {
        name: int(
            frame["capture_id"].astype(str).isin(supplement_capture_ids).sum()
        )
        for name, frame in splits.items()
    }
    if split_strategy == "chronological":
        supplement_rows_added = supplement_rows_by_split["train"]
    overlaps = {
        "train_validation": feature_overlap_count(splits["train"], splits["validation"]),
        "train_test": feature_overlap_count(splits["train"], splits["test"]),
        "validation_test": feature_overlap_count(
            splits["validation"],
            splits["test"],
        ),
    }
    if any(overlaps.values()):
        raise RuntimeError(f"Exact feature-row leakage found between splits: {overlaps}")

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_paths = {}
    for split_name, split_frame in splits.items():
        output_path = output_dir / f"{split_name}.csv"
        split_frame.to_csv(output_path, index=False)
        output_paths[split_name] = output_path

    split_manifest = {
        "mode": mode,
        "split_strategy": split_strategy,
        "random_state": random_state,
        "rows": {name: int(len(frame)) for name, frame in splits.items()},
        "capture_ids": {
            name: sorted(str(value) for value in frame["capture_id"].unique())
            for name, frame in splits.items()
        },
        "exact_feature_overlap": overlaps,
        "supplement_rows_added_to_train": supplement_rows_added,
        "supplement_rows_by_split": supplement_rows_by_split,
        "label_counts": {
            name: {
                SUPERVISED_CLASSES[int(class_id)]: int(count)
                for class_id, count in frame["label"].value_counts().items()
            }
            for name, frame in splits.items()
        },
    }
    manifest_path = output_dir / "split_manifest.json"
    with manifest_path.open("w", encoding="utf-8") as file:
        json.dump(split_manifest, file, indent=2)
        file.write(os.linesep)

    for split_name, split_path in output_paths.items():
        print(f"{split_name.title()} rows: {len(splits[split_name])} -> {split_path}")
    print(f"Exact feature-row overlap: {overlaps}")
    print(f"Split manifest: {manifest_path}")

    calibration = None
    train_metrics = None
    test_metrics = None
    if calibrate_threshold:
        if splits["validation"].empty:
            raise ValueError("Threshold calibration requires a non-empty validation split.")
        train_metrics, calibration, test_metrics = _train_and_calibrate(
            output_paths["train"],
            output_paths["validation"],
            output_paths["test"],
            feature_overlap=sum(overlaps.values()),
            model_path=model_path,
            metadata_path=metadata_path,
            random_state=random_state,
            benign_fpr_limit=benign_fpr_limit,
        )

    return {
        "splits": splits,
        "output_paths": output_paths,
        "manifest_path": manifest_path,
        "overlap_counts": overlaps,
        "train_metrics": train_metrics,
        "calibration": calibration,
        "test_metrics": test_metrics,
        "supplement_rows_added_to_train": supplement_rows_added,
        "supplement_rows_by_split": supplement_rows_by_split,
    }


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Prepare leakage-aware public traffic datasets for SentinelFlow "
            "supervised training."
        )
    )
    parser.add_argument("--mode", choices=("pcap", "csv"), required=True)
    parser.add_argument(
        "--inputs",
        nargs="+",
        required=True,
        help="Input .pcap/.pcapng files (pcap mode) or .csv/.parquet files (csv mode).",
    )
    parser.add_argument(
        "--ground-truth",
        help="JSON source/time/attack mapping required in PCAP mode.",
    )
    parser.add_argument(
        "--supplement-pcap",
        nargs="+",
        help="PCAP captures to append to the training split in CSV mode.",
    )
    parser.add_argument(
        "--supplement-ground-truth",
        nargs="+",
        help=(
            "Ground-truth JSON files corresponding by position to "
            "--supplement-pcap."
        ),
    )
    parser.add_argument("--label-column", help="Label column for CSV/Parquet input.")
    parser.add_argument(
        "--output-dir",
        default="scratch/prepared_public_dataset",
        help="Directory for train.csv, validation.csv, test.csv, and split manifest.",
    )
    parser.add_argument(
        "--split-strategy",
        choices=("capture", "chronological"),
        default="capture",
        help=(
            "Split by whole capture files, or chronologically within each "
            "(capture_id, label) group using 70/15/15 partitions."
        ),
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Test fraction for capture splitting; chronological mode uses 15%.",
    )
    parser.add_argument(
        "--validation-size",
        type=float,
        default=0.2,
        help="Validation fraction for capture splitting; chronological mode uses 15%.",
    )
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument(
        "--ignore-unknown-labels",
        action="store_true",
        help="Log and drop labels that are outside the seven supervised classes.",
    )
    parser.add_argument(
        "--max-rows-per-class-per-capture",
        type=int,
        help=(
            "Deterministically sample at most this many rows per class from each "
            "CSV capture to limit memory use."
        ),
    )
    parser.add_argument(
        "--calibrate-threshold",
        action="store_true",
        help=(
            "Train on train.csv, calibrate on validation.csv under the benign "
            "FPR limit, and save the supervised model and metadata."
        ),
    )
    parser.add_argument(
        "--benign-fpr-limit",
        type=float,
        default=0.01,
        help="Maximum validation false-positive rate for BENIGN rows (default: 0.01).",
    )
    parser.add_argument("--model-output", default=str(DEFAULT_MODEL_PATH))
    parser.add_argument("--metadata-output", default=str(DEFAULT_METADATA_PATH))
    args = parser.parse_args()

    prepare_public_dataset(
        mode=args.mode,
        input_paths=args.inputs,
        output_dir=args.output_dir,
        ground_truth_path=args.ground_truth,
        label_column=args.label_column,
        split_strategy=args.split_strategy,
        test_size=args.test_size,
        validation_size=args.validation_size,
        random_state=args.random_state,
        calibrate_threshold=args.calibrate_threshold,
        benign_fpr_limit=args.benign_fpr_limit,
        ignore_unknown_labels=args.ignore_unknown_labels,
        max_rows_per_class_per_capture=args.max_rows_per_class_per_capture,
        supplement_pcap_paths=args.supplement_pcap,
        supplement_ground_truth_paths=args.supplement_ground_truth,
        model_path=args.model_output,
        metadata_path=args.metadata_output,
    )


if __name__ == "__main__":
    main()
