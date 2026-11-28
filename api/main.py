from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes.alerts import router as alerts_router
from api.routes.pcap import router as pcap_router
from alerts.alert_store import AlertStore
from api.routes.metrics import router as metrics_router

app = FastAPI(
    title="CTD — Cyber Threat Detection API",
    version="1.0.0",
    description=(
        "Detection-only network threat monitoring API with SIH-aligned PCAP replay and throughput benchmarking."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts_router)
app.include_router(pcap_router)
app.include_router(metrics_router)

@app.get("/")
def root():

    return {
        "name": "CTD",
        "description": "Cyber Threat Detection",
        "status": "running",
        "mode": "detection-only",
    }


@app.get("/api/stats")
def get_stats():

    store = AlertStore()

    alerts = store.all()

    active = [
        alert
        for alert in alerts
        if alert.status == "ACTIVE"
    ]

    resolved = [
        alert
        for alert in alerts
        if alert.status == "RESOLVED"
    ]

    attack_types = {}
    predicted_threats = {}

    for alert in alerts:

        attack_type = alert.attack_type

        attack_types[attack_type] = (
            attack_types.get(
                attack_type,
                0,
            ) + 1
        )

        if alert.predicted_threat:
            predicted_threats[alert.predicted_threat] = (
                predicted_threats.get(alert.predicted_threat, 0) + 1
            )

    try:
        from supervised.classifier import get_threat_classifier
        clf = get_threat_classifier()
        classifier_available = bool(clf and clf.is_available)
        model_version = clf._artifacts["version"] if (classifier_available and clf._artifacts) else None
    except Exception:
        classifier_available = False
        model_version = None

    return {
        "total_alerts": len(alerts),
        "active_alerts": len(active),
        "resolved_alerts": len(resolved),
        "attack_types": attack_types,
        "predicted_threats": predicted_threats,
        "classifier_available": classifier_available,
        "classifier_model_version": model_version,
    }
@app.get("/api/health")
def health_check():

    return {
        "status": "healthy",
        "service": "ctd-api",
    }
