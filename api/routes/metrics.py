from fastapi import APIRouter

from telemetry.live_metrics import live_metrics


router = APIRouter(
    prefix="/api/metrics",
    tags=["Live Metrics"],
)


@router.get("/live")
def get_live_metrics():
    """
    Returns the latest live telemetry window and the
    rolling 60-second history.
    """

    return {
        "status": "ok",
        "latest": live_metrics.latest(),
        "history": live_metrics.history(),
    }
