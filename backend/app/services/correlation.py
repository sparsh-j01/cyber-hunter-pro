from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, List

from app.db.mongo import get_database


PHASE_WEIGHTS: dict[str, int] = {
    "Recon": 1,
    "Delivery": 2,
    "Installation": 5,
    "C2": 8,
    "Actions": 10,
}

KCPS_THRESHOLD = 15


async def calculate_kcps_for_host(host_id: str) -> dict[str, Any]:
    """
    Calculate Kill Chain Progression Score (KCPS) for a given host.
    KCPS = sum(Weight_phase * Confidence_detection)
    Confidence_detection is approximated as 1.0 when an event is tagged for that phase.
    """
    db = get_database()
    events_cursor = db["events"].find({"host.id": host_id}).sort("timestamp", 1)
    phases: dict[str, float] = defaultdict(float)
    timeline: List[dict[str, Any]] = []

    async for ev in events_cursor:
        phase = ev.get("kill_chain_phase")
        if phase in PHASE_WEIGHTS:
            phases[phase] += PHASE_WEIGHTS[phase] * 1.0

        timeline.append(
            {
                "event_id": ev.get("event_id"),
                "timestamp": ev.get("timestamp"),
                "phase": phase,
                "mitre": ev.get("mitre", {}),
                "threat_intel": ev.get("threat_intel", {}),
                "action": ev.get("action"),
            }
        )

    kcps = sum(phases.values())

    ransomware = _detect_ransomware_pattern(timeline)

    return {
        "host_id": host_id,
        "kcps": kcps,
        "phases": phases,
        "is_critical": kcps >= KCPS_THRESHOLD,
        "timeline": timeline,
        "ransomware_suspected": ransomware["suspected"],
        "ransomware_reason": ransomware["reason"],
    }


def _detect_ransomware_pattern(timeline: List[dict[str, Any]]) -> dict[str, Any]:
    """
    Simple heuristic ransomware detector.

    We look for bursts of file modification actions within a short window.
    Any action labelled "file_write" or "file_encrypt" counts towards the burst.
    If we see >= 100 such events within 60 seconds, we flag ransomware.
    """
    WINDOW = timedelta(seconds=60)
    THRESHOLD = 100

    window: deque[datetime] = deque()

    for ev in timeline:
        action = (ev.get("action") or "").lower()
        if action not in {"file_write", "file_encrypt"}:
            continue

        ts = ev.get("timestamp")
        if not isinstance(ts, datetime):
            try:
                ts = datetime.fromisoformat(str(ts))
            except Exception:
                continue

        window.append(ts)
        # Drop events older than WINDOW from the left
        while window and ts - window[0] > WINDOW:
            window.popleft()

        if len(window) >= THRESHOLD:
            return {
                "suspected": True,
                "reason": f"Observed {len(window)} rapid file modification events within {WINDOW.seconds} seconds.",
            }

    return {
        "suspected": False,
        "reason": "No ransomware-like file activity burst detected.",
    }


async def matrix_summary() -> dict[str, Any]:
    """
    Aggregate counts per MITRE technique for the heatmap/matrix.
    """
    db = get_database()
    pipeline = [
        {
            "$group": {
                "_id": {
                    "technique_id": "$mitre.technique_id",
                    "tactic": "$mitre.tactic",
                },
                "count": {"$sum": 1},
            }
        }
    ]

    cursor = db["events"].aggregate(pipeline)
    techniques: list[dict[str, Any]] = []
    async for row in cursor:
        tid = row["_id"]["technique_id"]
        if not tid:
            continue
        techniques.append(
            {
                "technique_id": tid,
                "tactic": row["_id"]["tactic"],
                "count": row["count"],
            }
        )
    return {"techniques": techniques}

