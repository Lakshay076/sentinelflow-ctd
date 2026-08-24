from fastapi import APIRouter, HTTPException

from alerts.alert_store import AlertStore


router = APIRouter(
    prefix="/api/alerts",
    tags=["Alerts"],
)

store = AlertStore()


@router.get("/active")
def get_active_alerts():
    alerts = store.active()

    return {
        "count": len(alerts),
        "alerts": [
            alert.to_dict()
            for alert in alerts
        ],
    }


@router.get("/history")
def get_alert_history():
    alerts = store.all()

    return {
        "count": len(alerts),
        "alerts": [
            alert.to_dict()
            for alert in alerts
        ],
    }


@router.get("/{alert_id}")
def get_alert(alert_id: int):

    alert = store.get(alert_id)

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    return alert.to_dict()
