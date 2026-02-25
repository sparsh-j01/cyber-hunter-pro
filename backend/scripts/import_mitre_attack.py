"""
Dataset 1: MITRE ATT&CK Enterprise Import Script
=================================================
Downloads the official MITRE ATT&CK Enterprise dataset (STIX 2.1 JSON)
from GitHub Mitre/CTI and imports real APT groups, techniques, and
relationships as normalized events into the Cyber Hunter Pro MongoDB.

Usage:
    cd backend
    python scripts/import_mitre_attack.py

Source: https://github.com/mitre/cti (enterprise-attack)
"""

import asyncio
import json
import random
from datetime import datetime, timedelta
from uuid import uuid4

import httpx
from motor.motor_asyncio import AsyncIOMotorClient

# ── Config ──────────────────────────────────────────────────────────────

MONGODB_URI = "mongodb://localhost:27017"
MONGODB_DB = "cyberhunterpro"
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Simulated hosts targeted by APT activity
TARGET_HOSTS = [
    {"id": "DC-SERVER-01",    "ip": "10.0.0.5",   "os": "win_server_2022"},
    {"id": "WEB-SERVER-03",   "ip": "10.0.1.10",  "os": "ubuntu_22"},
    {"id": "DEV-LAPTOP-07",   "ip": "10.0.2.33",  "os": "win11"},
    {"id": "MAIL-SERVER-01",  "ip": "10.0.0.8",   "os": "win_server_2019"},
    {"id": "DB-SERVER-02",    "ip": "10.0.0.12",  "os": "centos_8"},
    {"id": "HR-WORKSTATION",  "ip": "10.0.3.45",  "os": "win10"},
]

# Geo locations for attacker IPs (simulated origin countries)
ATTACKER_GEOS = [
    {"ip": "185.220.101.34",  "geo": {"lat": 55.75, "lon": 37.62,  "country_code": "RU", "country_name": "Russia"}},
    {"ip": "112.175.18.6",    "geo": {"lat": 39.02, "lon": 125.75, "country_code": "KP", "country_name": "North Korea"}},
    {"ip": "58.218.204.31",   "geo": {"lat": 31.23, "lon": 121.47, "country_code": "CN", "country_name": "China"}},
    {"ip": "5.34.180.205",    "geo": {"lat": 35.69, "lon": 51.39,  "country_code": "IR", "country_name": "Iran"}},
    {"ip": "198.51.100.22",   "geo": {"lat": 38.90, "lon": -77.04, "country_code": "US", "country_name": "United States"}},
    {"ip": "91.219.236.174",  "geo": {"lat": 51.50, "lon": -0.13,  "country_code": "GB", "country_name": "United Kingdom"}},
    {"ip": "46.166.186.243",  "geo": {"lat": 52.52, "lon": 13.40,  "country_code": "DE", "country_name": "Germany"}},
    {"ip": "176.31.98.12",    "geo": {"lat": 48.86, "lon": 2.35,   "country_code": "FR", "country_name": "France"}},
    {"ip": "103.224.182.240", "geo": {"lat": -6.21, "lon": 106.85, "country_code": "ID", "country_name": "Indonesia"}},
    {"ip": "41.231.53.9",     "geo": {"lat": 36.81, "lon": 10.17,  "country_code": "TN", "country_name": "Tunisia"}},
    {"ip": "203.99.187.1",    "geo": {"lat": 33.69, "lon": 73.04,  "country_code": "PK", "country_name": "Pakistan"}},
    {"ip": "31.184.198.23",   "geo": {"lat": 59.93, "lon": 30.32,  "country_code": "RU", "country_name": "Russia"}},
]

# Map MITRE tactics to Kill Chain phases
TACTIC_TO_KILLCHAIN = {
    "reconnaissance":         "Recon",
    "resource-development":   "Weaponization",
    "initial-access":         "Delivery",
    "execution":              "Exploitation",
    "persistence":            "Installation",
    "privilege-escalation":   "Installation",
    "defense-evasion":        "Installation",
    "credential-access":      "Installation",
    "discovery":              "Recon",
    "lateral-movement":       "C2",
    "collection":             "Actions",
    "command-and-control":    "C2",
    "exfiltration":           "Actions",
    "impact":                 "Actions",
}

# Action verbs per tactic
TACTIC_ACTIONS = {
    "reconnaissance":        ["dns_query", "port_scan", "whois_lookup"],
    "resource-development":  ["domain_register", "tool_acquire"],
    "initial-access":        ["email_received", "exploit_public_app"],
    "execution":             ["process_create", "script_execute", "cmd_run"],
    "persistence":           ["registry_write", "scheduled_task", "service_create"],
    "privilege-escalation":  ["token_manipulate", "process_inject"],
    "defense-evasion":       ["file_delete", "log_clear", "obfuscate"],
    "credential-access":     ["credential_dump", "brute_force", "keylog"],
    "discovery":             ["system_info", "network_scan", "account_enum"],
    "lateral-movement":      ["remote_service", "pass_the_hash", "rdp_connect"],
    "collection":            ["screen_capture", "data_stage", "email_collect"],
    "command-and-control":   ["network_connect", "dns_tunnel", "http_beacon"],
    "exfiltration":          ["data_exfil", "cloud_upload"],
    "impact":                ["file_encrypt", "service_stop", "data_destroy"],
}

SEVERITY_MAP = {
    "Recon": "Low",
    "Weaponization": "Low",
    "Delivery": "Medium",
    "Exploitation": "Medium",
    "Installation": "High",
    "C2": "Critical",
    "Actions": "Critical",
}


async def main():
    print("=" * 60)
    print("MITRE ATT&CK Enterprise Dataset Importer")
    print("=" * 60)

    # Step 1: Download MITRE data
    print("\n[1/4] Downloading MITRE ATT&CK Enterprise data from GitHub...")
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.get(MITRE_URL)
        resp.raise_for_status()
        bundle = resp.json()

    objects = bundle.get("objects", [])
    print(f"       Downloaded {len(objects)} STIX objects.")

    # Step 2: Parse APT groups (intrusion-sets) and techniques (attack-patterns)
    print("\n[2/4] Parsing APT groups and techniques...")

    groups = {}
    techniques = {}
    relationships = []

    for obj in objects:
        obj_type = obj.get("type")

        if obj_type == "intrusion-set":
            name = obj.get("name", "Unknown")
            aliases = obj.get("aliases", [])
            groups[obj["id"]] = {
                "name": name,
                "aliases": aliases,
                "description": (obj.get("description") or "")[:200],
            }

        elif obj_type == "attack-pattern":
            ext = obj.get("external_references", [])
            tech_id = None
            for ref in ext:
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id")
                    break
            if tech_id:
                phases = obj.get("kill_chain_phases", [])
                tactic = phases[0]["phase_name"] if phases else "unknown"
                techniques[obj["id"]] = {
                    "technique_id": tech_id,
                    "technique_name": obj.get("name", "Unknown"),
                    "tactic": tactic,
                }

        elif obj_type == "relationship" and obj.get("relationship_type") == "uses":
            src = obj.get("source_ref", "")
            tgt = obj.get("target_ref", "")
            if src.startswith("intrusion-set") and tgt.startswith("attack-pattern"):
                relationships.append({"group_id": src, "technique_id": tgt})

    print(f"       Found {len(groups)} APT groups, {len(techniques)} techniques, {len(relationships)} group-technique relationships.")

    # Step 3: Also store the raw STIX bundle in intel_feeds
    print("\n[3/4] Storing raw STIX bundle in intel_feeds collection...")
    client_mongo = AsyncIOMotorClient(MONGODB_URI)
    db = client_mongo[MONGODB_DB]

    await db["intel_feeds"].insert_one({
        "ingested_at": datetime.utcnow(),
        "source": "MITRE ATT&CK Enterprise",
        "bundle": {
            "type": bundle.get("type"),
            "id": bundle.get("id"),
            "spec_version": bundle.get("spec_version"),
            "object_count": len(objects),
        },
    })

    # Step 4: Generate realistic events from APT group → technique relationships
    print("\n[4/4] Generating normalized events from APT-technique mappings...")

    # Pick top 20 APT groups with the most techniques
    group_tech_count = {}
    for rel in relationships:
        gid = rel["group_id"]
        if gid in groups:
            group_tech_count[gid] = group_tech_count.get(gid, 0) + 1

    top_groups = sorted(group_tech_count, key=group_tech_count.get, reverse=True)[:20]

    events_to_insert = []
    base_time = datetime.utcnow() - timedelta(days=7)  # Spread over last 7 days

    for group_stix_id in top_groups:
        group = groups[group_stix_id]
        group_name = group["name"]

        # Find all techniques this group uses
        group_techs = [
            techniques[r["technique_id"]]
            for r in relationships
            if r["group_id"] == group_stix_id and r["technique_id"] in techniques
        ]

        # Generate 2-5 events per technique (capped at 15 techniques per group)
        for tech in group_techs[:15]:
            num_events = random.randint(2, 5)
            tactic_key = tech["tactic"].replace(" ", "-").lower()
            kill_chain = TACTIC_TO_KILLCHAIN.get(tactic_key, "Recon")
            actions = TACTIC_ACTIONS.get(tactic_key, ["unknown_action"])

            for _ in range(num_events):
                host = random.choice(TARGET_HOSTS)
                attacker = random.choice(ATTACKER_GEOS)
                offset = random.uniform(0, 7 * 24 * 3600)  # Random time in last 7 days

                tactic_display = tech["tactic"].replace("-", " ").title()

                event = {
                    "event_id": str(uuid4()),
                    "timestamp": base_time + timedelta(seconds=offset),
                    "host": host,
                    "actor": {
                        "user": random.choice(["admin", "root", "SYSTEM", "jdoe", "svc_account"]),
                        "process_name": random.choice(["powershell.exe", "cmd.exe", "bash", "python3", "svchost.exe", "rundll32.exe"]),
                    },
                    "action": random.choice(actions),
                    "threat_intel": {
                        "is_malicious": True,
                        "matched_ioc": attacker["ip"],
                        "threat_group": group_name,
                    },
                    "mitre": {
                        "tactic": tactic_display,
                        "technique_id": tech["technique_id"],
                        "technique_name": tech["technique_name"],
                    },
                    "kill_chain_phase": kill_chain,
                    "severity": SEVERITY_MAP.get(kill_chain, "Medium"),
                    "geo": attacker["geo"],
                }
                events_to_insert.append(event)

    # Bulk insert
    if events_to_insert:
        result = await db["events"].insert_many(events_to_insert)
        print(f"       ✅ Inserted {len(result.inserted_ids)} events from {len(top_groups)} APT groups.")
    else:
        print("       ⚠ No events generated.")

    # Summary
    print("\n" + "=" * 60)
    print("IMPORT COMPLETE")
    print("=" * 60)
    print(f"  APT Groups imported:   {len(top_groups)}")
    print(f"  Events generated:      {len(events_to_insert)}")
    print(f"  Time range:            Last 7 days")
    print(f"  Target hosts:          {len(TARGET_HOSTS)}")
    print(f"  Attacker origins:      {len(ATTACKER_GEOS)} countries")
    print("\n  Check your dashboard at http://localhost:5173")
    print("  - Intel Summary → see real APT group names")
    print("  - MITRE Matrix → see real technique IDs")
    print("  - Attacker Map → see geo distribution")
    print("  - SIEM Alerts → see severity-tagged events")

    client_mongo.close()


if __name__ == "__main__":
    asyncio.run(main())
