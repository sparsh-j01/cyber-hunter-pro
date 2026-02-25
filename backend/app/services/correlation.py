from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from app.db.mongo import get_database


PHASE_WEIGHTS: dict[str, int] = {
    "Recon": 1,
    "Delivery": 2,
    "Installation": 5,
    "C2": 8,
    "Actions": 10,
}

KCPS_THRESHOLD = 15


def assign_severity(event_dict: dict[str, Any]) -> str:
    """
    Auto-compute severity for an incoming event based on its attributes.

    Rules (evaluated top-down, first match wins):
      - Critical: ransomware-like action (file_encrypt) OR kill chain phase is C2/Actions
      - High:     malicious intel + Installation/Exploitation phase
      - Medium:   malicious intel with a known MITRE technique
      - Low:      everything else
    """
    action = (event_dict.get("action") or "").lower()
    phase = event_dict.get("kill_chain_phase") or ""
    threat = event_dict.get("threat_intel") or {}
    is_malicious = threat.get("is_malicious", False)
    mitre = event_dict.get("mitre") or {}
    technique_id = mitre.get("technique_id")

    if action in {"file_encrypt", "file_write"} and phase in {"Installation", "Actions"}:
        return "Critical"
    if phase in {"C2", "Actions"}:
        return "Critical"
    if is_malicious and phase in {"Installation", "Exploitation"}:
        return "High"
    if is_malicious and technique_id:
        return "Medium"
    if is_malicious:
        return "Medium"
    return "Low"


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
                "severity": ev.get("severity"),
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


async def alert_feed(limit: int = 50) -> list[dict[str, Any]]:
    """
    Return the most recent events sorted by timestamp descending,
    formatted as an alert feed for the SIEM dashboard.
    """
    db = get_database()
    cursor = (
        db["events"]
        .find({})
        .sort("timestamp", -1)
        .limit(limit)
    )
    feed: list[dict[str, Any]] = []
    async for ev in cursor:
        feed.append(
            {
                "event_id": ev.get("event_id"),
                "timestamp": ev.get("timestamp"),
                "host_id": (ev.get("host") or {}).get("id"),
                "host_ip": (ev.get("host") or {}).get("ip"),
                "action": ev.get("action"),
                "severity": ev.get("severity", "Low"),
                "kill_chain_phase": ev.get("kill_chain_phase"),
                "mitre_technique": (ev.get("mitre") or {}).get("technique_id"),
                "mitre_tactic": (ev.get("mitre") or {}).get("tactic"),
                "threat_group": (ev.get("threat_intel") or {}).get("threat_group"),
                "is_malicious": (ev.get("threat_intel") or {}).get("is_malicious", False),
            }
        )
    return feed


async def severity_stats() -> dict[str, int]:
    """
    Return counts of events per severity level.
    """
    db = get_database()
    pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
    ]
    cursor = db["events"].aggregate(pipeline)
    stats: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    async for row in cursor:
        level = row["_id"] or "Low"
        if level in stats:
            stats[level] = row["count"]
    return stats


async def geo_heatmap() -> list[dict[str, Any]]:
    """
    Aggregate events by country for the geographic heatmap.
    """
    db = get_database()
    pipeline = [
        {"$match": {"geo.country_code": {"$ne": None}}},
        {
            "$group": {
                "_id": "$geo.country_code",
                "country_name": {"$first": "$geo.country_name"},
                "lat": {"$avg": "$geo.lat"},
                "lon": {"$avg": "$geo.lon"},
                "count": {"$sum": 1},
            }
        },
        {"$sort": {"count": -1}},
    ]
    cursor = db["events"].aggregate(pipeline)
    result: list[dict[str, Any]] = []
    async for row in cursor:
        result.append(
            {
                "country_code": row["_id"],
                "country_name": row.get("country_name", row["_id"]),
                "lat": row["lat"],
                "lon": row["lon"],
                "count": row["count"],
            }
        )
    return result
