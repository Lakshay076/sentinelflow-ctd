"""
CTD — ML Model Training Script

Trains an UNSUPERVISED anomaly-detection model
(Isolation Forest) on examples of "normal" traffic
behavior, then saves the trained model to disk so
inference/ml_detector.py can load and use it.

============================================================
WHY UNSUPERVISED / ISOLATION FOREST, AND NOT A CLASSIFIER?
============================================================

A supervised classifier (e.g. Random Forest trained to say
"port scan" vs "not port scan") needs a large LABELED
dataset of real attacks to learn from. Building/obtaining
one is a significant undertaking on its own, and is
explicitly out of scope for a first working student
prototype.

Isolation Forest instead only needs examples of "normal"
behavior. It works by randomly partitioning the data
and observing that outliers get "isolated" into their own
tiny partition much faster than normal points do (an
unusual point sticks out and gets separated quickly; a
normal point, surrounded by lots of similar points, takes
many more splits to isolate). This matches this project's
real situation well: we know roughly what NORMAL traffic
looks like, but a labeled dataset covering every possible
ATTACK variant is much harder to obtain.

The trained model complements (does not replace) the 5
rule-based detectors already in this project. The ML layer
is meant to catch combinations of MILD weirdness across
many features at once -- patterns too subtle or too varied
for a single fixed threshold rule to catch reliably.

============================================================
IMPORTANT HONESTY NOTE -- READ BEFORE YOUR SIH SUBMISSION
============================================================

The training data generated below is SYNTHETIC -- reasonable
made-up numbers representing what "normal" traffic roughly
looks like, NOT real captured traffic from your own network.

This is a deliberate, clearly-labeled placeholder so the ML
layer is functional and demonstrable immediately. Before a
final submission, you should replace generate_synthetic_
normal_data() below with a baseline built from features
extracted from YOUR OWN recorded normal traffic (e.g. an
hour of ordinary browsing captured with your existing
collector, with the resulting feature vectors saved to a
CSV and loaded here instead). Document in your report which
version you used.
"""

import json
import os

import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

from inference.feature_schema import FEATURE_NAMES


MODEL_PATH = os.path.join(
    os.path.dirname(__file__), "model.joblib"
)

STATS_PATH = os.path.join(
    os.path.dirname(__file__), "feature_stats.json"
)


def generate_synthetic_normal_data(n_samples: int = 3000):
    """
    Generate n_samples rows of made-up, but realistic-shaped,
    "normal" traffic feature vectors, in FEATURE_NAMES order.

    SEE THE HONESTY NOTE ABOVE. Replace this function with
    real captured-baseline data before your final submission.
    """

    rng = np.random.default_rng(seed=42)

    n = n_samples

    packets_per_second = rng.gamma(shape=2.0, scale=1.5, size=n)
    bytes_per_second = rng.gamma(shape=2.0, scale=300.0, size=n)
    syn_packet_ratio = rng.beta(2, 20, size=n)
    rst_packet_ratio = rng.beta(2, 30, size=n)
    unique_destinations = rng.poisson(lam=2, size=n).astype(float)
    unique_destination_ports = rng.poisson(lam=2, size=n).astype(float)
    active_flows = rng.poisson(lam=3, size=n).astype(float)
    flows_per_second = rng.gamma(shape=2.0, scale=1.5, size=n)
    ports_per_destination = 1.0 + rng.poisson(lam=0.3, size=n)
    bytes_received = rng.gamma(shape=2.0, scale=800.0, size=n)
    outbound_inbound_ratio = rng.beta(2, 10, size=n) * 2.0

    # Most windows have no beacon/DNS/TLS activity at all --
    # so these cluster tightly around their "no signal"
    # default value, with a little natural noise.
    beacon_interval_cv = np.clip(
        rng.normal(loc=1.0, scale=0.3, size=n), 0.3, 2.0
    )
    dns_high_entropy_ratio = rng.beta(1, 50, size=n)
    dns_queries_per_second = rng.gamma(shape=1.5, scale=0.3, size=n)
    tls_avg_cipher_count = np.clip(
        rng.normal(loc=25.0, scale=5.0, size=n), 8, 35
    )
    tls_missing_sni_ratio = rng.beta(1, 50, size=n)

    columns = {
        "packets_per_second": packets_per_second,
        "bytes_per_second": bytes_per_second,
        "syn_packet_ratio": syn_packet_ratio,
        "rst_packet_ratio": rst_packet_ratio,
        "unique_destinations": unique_destinations,
        "unique_destination_ports": unique_destination_ports,
        "active_flows": active_flows,
        "flows_per_second": flows_per_second,
        "ports_per_destination": ports_per_destination,
        "bytes_received": bytes_received,
        "outbound_inbound_ratio": outbound_inbound_ratio,
        "beacon_interval_cv": beacon_interval_cv,
        "dns_high_entropy_ratio": dns_high_entropy_ratio,
        "dns_queries_per_second": dns_queries_per_second,
        "tls_avg_cipher_count": tls_avg_cipher_count,
        "tls_missing_sni_ratio": tls_missing_sni_ratio,
    }

    # Assemble into a matrix, columns in FEATURE_NAMES order.
    X = np.column_stack(
        [columns[name] for name in FEATURE_NAMES]
    )

    return X


def train():

    print("=" * 60)
    print("CTD -- ML Model Training")
    print("=" * 60)

    print()
    print("Generating synthetic 'normal traffic' baseline...")
    print("(see the honesty note at the top of this file)")

    X = generate_synthetic_normal_data()

    print(f"Training data shape: {X.shape}")

    print()
    print("Training Isolation Forest...")

    model = IsolationForest(
        n_estimators=150,
        contamination=0.03,
        random_state=42,
    )

    model.fit(X)

    print("Training complete.")

    # ---------------------------------------------------
    # Save per-feature mean/std, used later to explain
    # WHICH features were unusual for a given alert
    # (turns a black-box score into readable evidence).
    # ---------------------------------------------------

    means = X.mean(axis=0)
    stds = X.std(axis=0)

    # Avoid division-by-zero later for any constant column.
    stds = np.where(stds < 1e-6, 1e-6, stds)

    stats = {
        name: {"mean": float(m), "std": float(s)}
        for name, m, s in zip(FEATURE_NAMES, means, stds)
    }

    with open(STATS_PATH, "w") as f:
        json.dump(stats, f, indent=2)

    print(f"Saved feature statistics -> {STATS_PATH}")

    joblib.dump(model, MODEL_PATH)

    print(f"Saved trained model -> {MODEL_PATH}")

    # ---------------------------------------------------
    # Quick sanity check: score the training data itself
    # and a few obviously-extreme synthetic points, so you
    # can see the model is behaving sensibly.
    # ---------------------------------------------------

    print()
    print("Sanity check on training data:")

    predictions = model.predict(X)

    n_flagged = int((predictions == -1).sum())

    print(
        f"  {n_flagged} / {len(X)} training points flagged "
        f"as anomalies ({n_flagged / len(X):.1%}) "
        f"-- should roughly match the contamination setting."
    )

    print()
    print("Done. Run inference/ml_detector.py's self-test with:")
    print("  python -m inference.ml_detector")


if __name__ == "__main__":
    train()
