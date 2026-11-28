"""
SentinelFlow-CTD — Supervised Threat Classification Package

This package provides:
  - CIC-IDS2017 dataset loading and cleaning
  - Label mapping to SentinelFlow threat categories
  - Random Forest multiclass classifier training
  - Model evaluation and artifact management
  - (Phase 2+) Live feature adapter for integration with the detection pipeline

The supervised classifier is an *additive* layer that runs alongside the
existing Isolation Forest anomaly detector. It never replaces or modifies
the existing rule-based or anomaly detection pipeline.
"""
