from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import PlainTextResponse

from app.db.mongo import get_database
from app.models.events import NormalizedEvent
from app.services.correlation import calculate_kcps_for_host, matrix_summary


router = APIRouter()


@router.get("/intel/summary")
async def get_intel_summary() -> dict[str, Any]:
    """
    Basic aggregation over threat_intel for executive and analyst views.
    """
    db = get_database()
    pipeline = [
        {
            "$group": {
                "_id": "$threat_intel.threat_group",
                "count": {"$sum": 1},
            }
        }
    ]
    cursor = db["events"].aggregate(pipeline)
    groups: list[dict[str, Any]] = []
    async for row in cursor:
        groups.append(
            {
                "threat_group": row["_id"],
                "count": row["count"],
            }
        )

    total_events = await db["events"].count_documents({})
    malicious_events = await db["events"].count_documents(
        {"threat_intel.is_malicious": True}
    )

    return {
        "total_events": total_events,
        "malicious_events": malicious_events,
        "threat_groups": groups,
    }


@router.post("/logs/submit")
async def submit_log(event: NormalizedEvent) -> dict[str, Any]:
    """
    Endpoint for log forwarders to submit normalized events.
    In a full system this would also accept raw logs and run normalization.
    """
    db = get_database()
    payload = event.model_dump()
    await db["events"].insert_one(payload)
    return {"event_id": event.event_id}


@router.get("/hunt/matrix")
async def get_hunt_matrix() -> dict[str, Any]:
    """
    Returns data for the MITRE heatmap.
    """
    return await matrix_summary()


@router.get("/hunt/killchain/{host_id}")
async def get_killchain_for_host(host_id: str) -> dict[str, Any]:
    """
    Chronological Kill Chain for a given host.
    """
    return await calculate_kcps_for_host(host_id)


@router.get(
    "/hunt/killchain/{host_id}/report",
    response_class=PlainTextResponse,
)
async def get_killchain_report(host_id: str) -> str:
    """
    Exportable Incident Response report for a given host.
    Returns a plain-text summary that can be downloaded or copied into a ticket.
    """
    data = await calculate_kcps_for_host(host_id)
    lines: list[str] = []

    lines.append(f"Incident Report for Host: {data['host_id']}")
    lines.append("=" * 60)
    lines.append("")
    lines.append("Kill Chain Summary")
    lines.append("------------------")
    lines.append(f"KCPS: {data['kcps']:.1f}")
    lines.append(f"Critical Lead: {'YES' if data['is_critical'] else 'NO'}")
    lines.append(f"Ransomware Suspected: {'YES' if data.get('ransomware_suspected') else 'NO'}")
    if data.get("ransomware_reason"):
        lines.append(f"Ransomware Notes: {data['ransomware_reason']}")
    lines.append("")
    lines.append("Phase Scores:")
    for phase, score in data["phases"].items():
        lines.append(f"  - {phase}: {score:.1f}")

    lines.append("")
    lines.append("Timeline:")
    lines.append("---------")
    for ev in data["timeline"]:
        ts = ev.get("timestamp")
        ts_str = ts.isoformat() if isinstance(ts, datetime) else str(ts)
        phase = ev.get("phase") or "Unknown"
        mitre = ev.get("mitre") or {}
        tech_id = mitre.get("technique_id") or "N/A"
        tech_name = mitre.get("technique_name") or ""
        threat = ev.get("threat_intel") or {}
        actor = threat.get("threat_group") or "Unknown"
        action = ev.get("action") or "N/A"
        lines.append(
            f"- [{ts_str}] Phase={phase} Technique={tech_id} {tech_name} "
            f"Actor={actor} Action={action}"
        )

    return "\n".join(lines)


@router.put("/alerts/{alert_id}/status")
async def update_alert_status(
    alert_id: str, status: str = Body(..., embed=True)
) -> dict[str, Any]:
    """
    Update alert status. For now alerts are stored in a dedicated collection.
    """
    if status not in {"False Positive", "Investigating", "Resolved"}:
        raise HTTPException(status_code=400, detail="Invalid status")

    db = get_database()
    result = await db["alerts"].update_one(
        {"_id": alert_id},
        {"$set": {"status": status, "updated_at": datetime.utcnow()}},
        upsert=True,
    )
    return {"alert_id": alert_id, "status": status, "upserted": bool(result.upserted_id)}


@router.post("/intel/stix/import")
async def import_stix_bundle(bundle: Dict[str, Any]) -> dict[str, Any]:
    """
    Basic STIX/TAXII-style CTI import.

    This endpoint accepts a JSON bundle in the spirit of STIX 2.1 and
    stores it into an `intel_feeds` collection. In a real deployment,
    this would be driven by a TAXII client; here it's a simple simulation
    that lets you say: "we can import STIX-formatted threat intelligence".
    """
    db = get_database()
    result = await db["intel_feeds"].insert_one(
        {
            "ingested_at": datetime.utcnow(),
            "bundle": bundle,
        }
    )
    return {"id": str(result.inserted_id)}

