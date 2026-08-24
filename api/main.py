from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes.alerts import router as alerts_router
from alerts.alert_store import AlertStore


app = FastAPI(
    title="CTD — Cyber Threat Detection API",
    version="1.0.0",
    description=(
        "Detection-only network threat monitoring API."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://192.168.56.105:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)

app.include_router(alerts_router)


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
