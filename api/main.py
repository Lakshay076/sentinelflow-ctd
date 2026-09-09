from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes.alerts import router as alerts_router
from api.routes.pcap import router as pcap_router
from alerts.alert_store import AlertStore


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

    for alert in alerts:

        attack_type = alert.attack_type

        attack_types[attack_type] = (
            attack_types.get(
                attack_type,
                0,
            ) + 1
        )

    return {
        "total_alerts": len(alerts),
        "active_alerts": len(active),
        "resolved_alerts": len(resolved),
        "attack_types": attack_types,
    }
@app.get("/api/health")
def health_check():

    return {
        "status": "healthy",
        "service": "ctd-api",
    }
