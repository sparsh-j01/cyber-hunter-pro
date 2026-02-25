"""
Dataset 2: CICIDS Network Intrusion Logs Importer
==================================================
Generates a realistic CICIDS-style network intrusion dataset and imports
it as normalized events. Since the full CICIDS-2017 dataset is ~8 GB,
this script generates synthetic events modeled after the real CICIDS
labels and flow features—giving the same analytical value for the demo.

The generated data matches real CICIDS attack types:
  - Benign traffic
  - DoS Hulk / DoS Slowhttptest / DoS Slowloris / DoS GoldenEye
  - DDoS
  - PortScan
  - FTP-Patator / SSH-Patator (brute force)
  - Bot
  - Web Attack – Brute Force / SQL Injection / XSS
  - Infiltration
  - Heartbleed

Usage:
    cd backend
    python scripts/import_cicids_logs.py

Source model: CIC-IDS-2017 – Canadian Institute for Cybersecurity
"""

import asyncio
import random
from datetime import datetime, timedelta
from uuid import uuid4

from motor.motor_asyncio import AsyncIOMotorClient

# ── Config ──────────────────────────────────────────────────────────────

MONGODB_URI = "mongodb://localhost:27017"
MONGODB_DB = "cyberhunterpro"

# CICIDS-2017 attack labels → MITRE + Kill Chain mapping
CICIDS_ATTACK_TYPES = [
    {
        "label": "DoS Hulk",
        "mitre_technique": "T1498.001",
        "mitre_tactic": "Impact",
        "technique_name": "Direct Network Flood",
        "kill_chain": "Actions",
        "action": "network_flood",
        "severity": "Critical",
        "count": 80,
    },
    {
        "label": "DoS Slowhttptest",
        "mitre_technique": "T1499.002",
        "mitre_tactic": "Impact",
        "technique_name": "Service Exhaustion Flood",
        "kill_chain": "Actions",
        "action": "slow_http",
        "severity": "High",
        "count": 30,
    },
    {
        "label": "DoS Slowloris",
        "mitre_technique": "T1499.001",
        "mitre_tactic": "Impact",
        "technique_name": "OS Exhaustion Flood",
        "kill_chain": "Actions",
        "action": "slow_connection",
        "severity": "High",
        "count": 25,
    },
    {
        "label": "DoS GoldenEye",
        "mitre_technique": "T1499",
        "mitre_tactic": "Impact",
        "technique_name": "Endpoint Denial of Service",
        "kill_chain": "Actions",
        "action": "http_flood",
        "severity": "High",
        "count": 25,
    },
    {
        "label": "DDoS",
        "mitre_technique": "T1498",
        "mitre_tactic": "Impact",
        "technique_name": "Network Denial of Service",
        "kill_chain": "Actions",
        "action": "ddos_attack",
        "severity": "Critical",
        "count": 60,
    },
    {
        "label": "PortScan",
        "mitre_technique": "T1046",
        "mitre_tactic": "Discovery",
        "technique_name": "Network Service Discovery",
        "kill_chain": "Recon",
        "action": "port_scan",
        "severity": "Low",
        "count": 70,
    },
    {
        "label": "FTP-Patator",
        "mitre_technique": "T1110.001",
        "mitre_tactic": "Credential Access",
        "technique_name": "Password Guessing",
        "kill_chain": "Installation",
        "action": "brute_force",
        "severity": "High",
        "count": 40,
    },
    {
        "label": "SSH-Patator",
        "mitre_technique": "T1110.001",
        "mitre_tactic": "Credential Access",
        "technique_name": "Password Guessing",
        "kill_chain": "Installation",
        "action": "brute_force",
        "severity": "High",
        "count": 40,
    },
    {
        "label": "Bot",
        "mitre_technique": "T1071.001",
        "mitre_tactic": "Command And Control",
        "technique_name": "Application Layer Protocol – Web",
        "kill_chain": "C2",
        "action": "http_beacon",
        "severity": "Critical",
        "count": 30,
    },
    {
        "label": "Web Attack – Brute Force",
        "mitre_technique": "T1110",
        "mitre_tactic": "Credential Access",
        "technique_name": "Brute Force",
        "kill_chain": "Installation",
        "action": "web_brute_force",
        "severity": "Medium",
        "count": 25,
    },
    {
        "label": "Web Attack – SQL Injection",
        "mitre_technique": "T1190",
        "mitre_tactic": "Initial Access",
        "technique_name": "Exploit Public-Facing Application",
        "kill_chain": "Exploitation",
        "action": "sql_injection",
        "severity": "Critical",
        "count": 20,
    },
    {
        "label": "Web Attack – XSS",
        "mitre_technique": "T1189",
        "mitre_tactic": "Initial Access",
        "technique_name": "Drive-by Compromise",
        "kill_chain": "Delivery",
        "action": "xss_inject",
        "severity": "Medium",
        "count": 20,
    },
    {
        "label": "Infiltration",
        "mitre_technique": "T1021",
        "mitre_tactic": "Lateral Movement",
        "technique_name": "Remote Services",
        "kill_chain": "C2",
        "action": "lateral_move",
        "severity": "High",
        "count": 15,
    },
    {
        "label": "Heartbleed",
        "mitre_technique": "T1190",
        "mitre_tactic": "Initial Access",
        "technique_name": "Exploit Public-Facing Application",
        "kill_chain": "Exploitation",
        "action": "heartbleed_exploit",
        "severity": "Critical",
        "count": 10,
    },
    {
        "label": "Benign",
        "mitre_technique": None,
        "mitre_tactic": None,
        "technique_name": None,
        "kill_chain": None,
        "action": "normal_traffic",
        "severity": "Low",
        "count": 100,
    },
]

# Network hosts (internal)
INTERNAL_HOSTS = [
    {"id": "WEB-DMZ-01",    "ip": "172.16.0.1",  "os": "ubuntu_22"},
    {"id": "WEB-DMZ-02",    "ip": "172.16.0.2",  "os": "ubuntu_22"},
    {"id": "APP-SERVER-01", "ip": "192.168.10.5", "os": "centos_8"},
    {"id": "APP-SERVER-02", "ip": "192.168.10.6", "os": "win_server_2022"},
    {"id": "DB-CLUSTER-01", "ip": "192.168.20.3", "os": "ubuntu_22"},
    {"id": "FTP-SERVER",    "ip": "192.168.10.21","os": "debian_12"},
    {"id": "SSH-GATEWAY",   "ip": "192.168.10.22","os": "centos_8"},
    {"id": "USER-WS-01",    "ip": "10.0.5.101",  "os": "win10"},
    {"id": "USER-WS-02",    "ip": "10.0.5.102",  "os": "win11"},
]

# Attacker IPs with geo data (simulated external sources)
ATTACKER_SOURCES = [
    {"ip": "23.227.38.65",    "geo": {"lat": 43.65, "lon": -79.38, "country_code": "CA", "country_name": "Canada"}},
    {"ip": "89.248.167.131",  "geo": {"lat": 52.37, "lon": 4.90,   "country_code": "NL", "country_name": "Netherlands"}},
    {"ip": "45.33.32.156",    "geo": {"lat": 37.77, "lon": -122.42,"country_code": "US", "country_name": "United States"}},
    {"ip": "185.220.101.34",  "geo": {"lat": 55.75, "lon": 37.62,  "country_code": "RU", "country_name": "Russia"}},
    {"ip": "58.218.204.31",   "geo": {"lat": 31.23, "lon": 121.47, "country_code": "CN", "country_name": "China"}},
    {"ip": "193.239.147.51",  "geo": {"lat": 47.37, "lon": 8.55,   "country_code": "CH", "country_name": "Switzerland"}},
    {"ip": "41.77.209.18",    "geo": {"lat": -1.29, "lon": 36.82,  "country_code": "KE", "country_name": "Kenya"}},
    {"ip": "103.75.190.12",   "geo": {"lat": 1.35,  "lon": 103.82, "country_code": "SG", "country_name": "Singapore"}},
    {"ip": "82.102.20.187",   "geo": {"lat": 48.21, "lon": 16.37,  "country_code": "AT", "country_name": "Austria"}},
    {"ip": "200.160.2.3",     "geo": {"lat": -23.55,"lon": -46.63, "country_code": "BR", "country_name": "Brazil"}},
    {"ip": "211.114.48.77",   "geo": {"lat": 37.57, "lon": 126.98, "country_code": "KR", "country_name": "South Korea"}},
    {"ip": "103.224.182.240", "geo": {"lat": -6.21, "lon": 106.85, "country_code": "ID", "country_name": "Indonesia"}},
]

# Network flow metadata ranges (modeled after CICIDS features)
FLOW_PROTOCOLS = ["TCP", "UDP", "ICMP"]
DEST_PORTS = [21, 22, 80, 443, 445, 3306, 3389, 8080, 8443]


async def main():
    print("=" * 60)
    print("CICIDS Network Intrusion Logs Importer")
    print("=" * 60)

    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[MONGODB_DB]

    events = []
    base_time = datetime.utcnow() - timedelta(days=5)  # Spread over last 5 days

    print("\n[1/2] Generating CICIDS-style network events...")

    for attack_type in CICIDS_ATTACK_TYPES:
        label = attack_type["label"]
        count = attack_type["count"]

        for i in range(count):
            host = random.choice(INTERNAL_HOSTS)
            attacker = random.choice(ATTACKER_SOURCES)
            offset = random.uniform(0, 5 * 24 * 3600)

            # Network flow metadata
            protocol = random.choice(FLOW_PROTOCOLS)
            dst_port = random.choice(DEST_PORTS)
            flow_duration = random.uniform(0.001, 120.0) if label != "Benign" else random.uniform(0.5, 300.0)
            total_fwd_packets = random.randint(1, 500)
            total_bwd_packets = random.randint(0, 200)

            is_malicious = label != "Benign"

            event = {
                "event_id": str(uuid4()),
                "timestamp": base_time + timedelta(seconds=offset),
                "host": host,
                "actor": {
                    "user": attacker["ip"],  # source IP as actor for network logs
                    "process_name": f"{protocol.lower()}/{dst_port}",
                },
                "action": attack_type["action"],
                "threat_intel": {
                    "is_malicious": is_malicious,
                    "matched_ioc": attacker["ip"] if is_malicious else None,
                    "threat_group": f"CICIDS-{label.replace(' ', '_')}" if is_malicious else None,
                },
                "mitre": (
                    {
                        "tactic": attack_type["mitre_tactic"],
                        "technique_id": attack_type["mitre_technique"],
                        "technique_name": attack_type["technique_name"],
                    }
                    if attack_type["mitre_technique"]
                    else {"tactic": None, "technique_id": None, "technique_name": None}
                ),
                "kill_chain_phase": attack_type["kill_chain"],
                "severity": attack_type["severity"],
                "geo": attacker["geo"] if is_malicious else None,
                # Extra CICIDS-specific metadata (stored but not used in schema)
                "cicids_meta": {
                    "label": label,
                    "protocol": protocol,
                    "dst_port": dst_port,
                    "flow_duration_sec": round(flow_duration, 3),
                    "total_fwd_packets": total_fwd_packets,
                    "total_bwd_packets": total_bwd_packets,
                    "flow_bytes_per_s": round(
                        (total_fwd_packets + total_bwd_packets) * random.randint(40, 1500) / max(flow_duration, 0.001),
                        2,
                    ),
                },
            }
            events.append(event)

        print(f"   → {label}: {count} events")

    # Bulk insert
    print(f"\n[2/2] Inserting {len(events)} events into MongoDB...")
    result = await db["events"].insert_many(events)
    print(f"       ✅ Inserted {len(result.inserted_ids)} CICIDS events.")

    # Summary
    total_malicious = sum(a["count"] for a in CICIDS_ATTACK_TYPES if a["label"] != "Benign")
    total_benign = sum(a["count"] for a in CICIDS_ATTACK_TYPES if a["label"] == "Benign")

    print("\n" + "=" * 60)
    print("IMPORT COMPLETE")
    print("=" * 60)
    print(f"  Attack categories:     {len(CICIDS_ATTACK_TYPES) - 1}")
    print(f"  Malicious events:      {total_malicious}")
    print(f"  Benign events:         {total_benign}")
    print(f"  Total events:          {len(events)}")
    print(f"  Attacker origins:      {len(ATTACKER_SOURCES)} countries")
    print(f"  Target hosts:          {len(INTERNAL_HOSTS)}")
    print("\n  Data modeled after: CIC-IDS-2017 (Canadian Institute for Cybersecurity)")
    print("  Attack types include: DoS, DDoS, PortScan, Brute Force, Bot,")
    print("                        SQL Injection, XSS, Infiltration, Heartbleed")

    client.close()


if __name__ == "__main__":
    asyncio.run(main())
