from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import PlainTextResponse

from app.db.mongo import get_database
from app.models.events import NormalizedEvent
from app.services.correlation import (
    alert_feed,
    assign_severity,
    calculate_kcps_for_host,
    geo_heatmap,
    matrix_summary,
    severity_stats,
)


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
    Auto-assigns severity if not provided.
    """
    db = get_database()
    payload = event.model_dump()
    # Auto-assign severity when not explicitly set
    if payload.get("severity") is None:
        payload["severity"] = assign_severity(payload)
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
        sev = ev.get("severity") or "Low"
        lines.append(
            f"- [{ts_str}] Phase={phase} Technique={tech_id} {tech_name} "
            f"Actor={actor} Action={action} Severity={sev}"
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


# ── SIEM Alert Feed ──────────────────────────────────────────────────────


@router.get("/alerts/feed")
async def get_alert_feed() -> dict[str, Any]:
    """
    Returns the most recent events as a SIEM-style alert feed,
    including severity, host info, MITRE technique, and threat group.
    """
    feed = await alert_feed(limit=50)
    return {"alerts": feed}


@router.get("/alerts/stats")
async def get_alert_stats() -> dict[str, int]:
    """
    Returns severity distribution counts.
    """
    return await severity_stats()


# ── Geographic Heatmap ───────────────────────────────────────────────────


@router.get("/hunt/heatmap")
async def get_heatmap() -> dict[str, Any]:
    """
    Aggregate events by country for the attacker activity heatmap.
    """
    data = await geo_heatmap()
    return {"countries": data}


# ── Ransomware Simulation ───────────────────────────────────────────────


@router.post("/simulate/ransomware")
async def simulate_ransomware_attack() -> dict[str, Any]:
    """
    In-process ransomware simulation.
    Generates a realistic multi-phase attack ending in rapid file_encrypt events
    so that the ransomware detector triggers.
    """
    import random
    from uuid import uuid4

    db = get_database()
    host_id = "VICTIM-PC-01"
    host_ip = "10.0.1.42"
    base_time = datetime.utcnow()

    # Source IPs with geo data for heatmap demo
    attacker_profiles = [
        {"ip": "185.220.101.34", "geo": {"lat": 55.75, "lon": 37.62, "country_code": "RU", "country_name": "Russia"}},
        {"ip": "112.175.18.6", "geo": {"lat": 39.02, "lon": 125.75, "country_code": "KP", "country_name": "North Korea"}},
        {"ip": "58.218.204.31", "geo": {"lat": 31.23, "lon": 121.47, "country_code": "CN", "country_name": "China"}},
        {"ip": "91.219.236.174", "geo": {"lat": 51.50, "lon": -0.13, "country_code": "GB", "country_name": "United Kingdom"}},
        {"ip": "198.51.100.22", "geo": {"lat": 38.90, "lon": -77.04, "country_code": "US", "country_name": "United States"}},
        {"ip": "5.34.180.205", "geo": {"lat": 35.69, "lon": 51.39, "country_code": "IR", "country_name": "Iran"}},
        {"ip": "46.166.186.243", "geo": {"lat": 52.52, "lon": 13.40, "country_code": "DE", "country_name": "Germany"}},
        {"ip": "103.224.182.240", "geo": {"lat": -6.21, "lon": 106.85, "country_code": "ID", "country_name": "Indonesia"}},
    ]

    # Kill chain phases with events
    scenario = [
        # Phase 1: Recon
        {"offset_s": 0,   "phase": "Recon",        "action": "dns_query",       "technique_id": "T1595",     "technique_name": "Active Scanning",           "tactic": "Reconnaissance",   "group": "APT28"},
        {"offset_s": 5,   "phase": "Recon",        "action": "port_scan",       "technique_id": "T1046",     "technique_name": "Network Service Discovery", "tactic": "Discovery",        "group": "APT28"},
        # Phase 2: Delivery
        {"offset_s": 30,  "phase": "Delivery",     "action": "email_received",  "technique_id": "T1566.001", "technique_name": "Spearphishing Attachment",  "tactic": "Initial Access",   "group": "APT28"},
        {"offset_s": 35,  "phase": "Delivery",     "action": "file_download",   "technique_id": "T1204.002", "technique_name": "Malicious File",            "tactic": "Execution",        "group": "APT28"},
        # Phase 3: Exploitation
        {"offset_s": 60,  "phase": "Exploitation", "action": "process_create",  "technique_id": "T1059.001", "technique_name": "PowerShell",                "tactic": "Execution",        "group": "APT28"},
        # Phase 4: Installation
        {"offset_s": 90,  "phase": "Installation", "action": "registry_write",  "technique_id": "T1547.001", "technique_name": "Registry Run Keys",         "tactic": "Persistence",      "group": "APT28"},
        {"offset_s": 95,  "phase": "Installation", "action": "service_create",  "technique_id": "T1543.003", "technique_name": "Windows Service",           "tactic": "Persistence",      "group": "APT28"},
        # Phase 5: C2
        {"offset_s": 120, "phase": "C2",           "action": "network_connect", "technique_id": "T1071.001", "technique_name": "Web Protocols",             "tactic": "Command and Control", "group": "APT28"},
        {"offset_s": 125, "phase": "C2",           "action": "dns_query",       "technique_id": "T1071.004", "technique_name": "DNS",                       "tactic": "Command and Control", "group": "APT28"},
    ]

    events_created = 0
    from datetime import timedelta

    # Insert pre-ransomware KillChain events
    for step in scenario:
        attacker = random.choice(attacker_profiles)
        ev = {
            "event_id": str(uuid4()),
            "timestamp": base_time + timedelta(seconds=step["offset_s"]),
            "host": {"id": host_id, "ip": host_ip, "os": "win11"},
            "actor": {"user": "jdoe", "process_name": "powershell.exe"},
            "action": step["action"],
            "threat_intel": {
                "is_malicious": True,
                "matched_ioc": attacker["ip"],
                "threat_group": step["group"],
            },
            "mitre": {
                "tactic": step["tactic"],
                "technique_id": step["technique_id"],
                "technique_name": step["technique_name"],
            },
            "kill_chain_phase": step["phase"],
            "geo": attacker["geo"],
        }
        ev["severity"] = assign_severity(ev)
        await db["events"].insert_one(ev)
        events_created += 1

    # Phase 6: Actions – Ransomware burst (150 file_encrypt in ~30 seconds)
    for i in range(150):
        attacker = random.choice(attacker_profiles)
        offset = 180 + (i * 0.2)  # ~30 seconds total
        ev = {
            "event_id": str(uuid4()),
            "timestamp": base_time + timedelta(seconds=offset),
            "host": {"id": host_id, "ip": host_ip, "os": "win11"},
            "actor": {"user": "SYSTEM", "process_name": "svchost.exe"},
            "action": "file_encrypt",
            "threat_intel": {
                "is_malicious": True,
                "matched_ioc": f"sha256_{uuid4().hex[:16]}",
                "threat_group": "APT28",
            },
            "mitre": {
                "tactic": "Impact",
                "technique_id": "T1486",
                "technique_name": "Data Encrypted for Impact",
            },
            "kill_chain_phase": "Actions",
            "geo": attacker["geo"],
        }
        ev["severity"] = assign_severity(ev)
        await db["events"].insert_one(ev)
        events_created += 1

    return {
        "status": "Simulation complete",
        "host_id": host_id,
        "events_created": events_created,
        "message": f"Injected {events_created} events for {host_id}. "
                   "Check Kill Chain tab with host VICTIM-PC-01 to see ransomware detection.",
    }
