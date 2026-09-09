# Aligning this project with the SIH problem statement

## What changed and why

| Before | After | Why |
|---|---|---|
| `collector/packet_collector.py` sniffs a live NIC (`en0`) | `collector/pcap_replay_collector.py` reads a `.pcap` file | A live NIC is bidirectional and can send. A file on disk cannot send anything, ever — it's the software equivalent of a hardware data diode: physically read-only. |
| Traffic = one laptop's own packets | Traffic = a multi-host `.pcap` you feed in (real capture, public dataset, or `scripts/generate_synthetic_traffic.py`) | The SIH scenario is a gateway/peering link carrying MANY hosts' traffic, not one machine's own packets. |
| `inference/train_model.py` trains on invented statistical distributions | `inference/train_model_from_pcap.py` trains on real feature vectors produced by replaying an actual benign pcap through the live pipeline | Training features must be computed the same way as inference features, from real traffic shape, or the learned "normal" baseline doesn't match reality. |
| No stated throughput | `pcap_replay_collector.py` prints sustained pps / Mbps / flows-per-second after every run | The SIH deliverable explicitly requires you to state and demonstrate a tested throughput. |

Nothing in the detection core changed: `flow/`, `features/`, `detectors/`, `alerts/`, `api/`, `frontend/` are untouched. Only the packet *source* and the model's *training data source* changed — which is exactly the right amount of change, since the detection logic already matches the SIH's required threat list.

## Directory Structure & Canonical Scripts

- `collector/pcap_replay_collector.py` — Ingests and replays PCAP files through the 1-second streaming window pipeline and detector engines.
- `scripts/generate_synthetic_traffic.py` — Builds multi-host synthetic gateway `.pcap` files with labeled attack scenarios and ground-truth manifests.
- `scripts/validate_detections.py` — Evaluates detector accuracy against `.ground_truth.json` manifests (Precision, Recall, F1).
- `inference/train_model_from_pcap.py` — Trains the Isolation Forest model on feature vectors extracted directly from benign PCAP captures.
- `docs/SIH_ALIGNMENT.md` — This alignment and architecture guide.

## How to use it

```bash
# 1) Get traffic to replay — pick ONE:
#    a) a real pcap you captured (tcpdump/Wireshark)
#    b) a public dataset (CICIDS2017, UNSW-NB15, CTU-13, MAWILab)
#    c) generate a quick synthetic multi-host demo file:
python scripts/generate_synthetic_traffic.py --out demo.pcap

# 2) Replay it through the full detection pipeline:
python -m collector.pcap_replay_collector demo.pcap

# 3) Benchmark throughput (report this number in your writeup):
python -m collector.pcap_replay_collector demo.pcap --max-speed

# 4) Validate detection accuracy against ground truth:
python scripts/validate_detections.py demo.pcap.ground_truth.json

# 5) Retrain the ML model on a REAL benign-only capture:
python scripts/generate_synthetic_traffic.py --out benign.pcap --attacks
python -m inference.train_model_from_pcap benign.pcap
```

## What's still a placeholder / next steps

- **NetFlow/IPFIX/sFlow ingestion** — not implemented yet. The pcap-replay path covers the "packet captures" input type from the problem statement; flow-record ingestion (pre-aggregated 5-tuple summaries from routers) would be a second, smaller adapter that constructs `PacketRecord`-like summaries directly from exported flow fields instead of parsing raw packets, feeding into the same `FlowEngine`/`FeatureContext` pipeline.
- **Real training data** — `train_model_from_pcap.py` is ready, but you still need an actual real/public benign capture to point it at before your final submission (the synthetic generator is for pipeline smoke-testing only, not a training baseline).
- **JA4 fingerprinting** — the TLS detector currently computes JA3 only; the SIH brief also mentions JA4 as an option worth exploring for the writeup.
