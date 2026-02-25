from datetime import datetime
from typing import Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


KillChainPhase = Literal[
    "Recon",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "C2",
    "Actions",
]

SeverityLevel = Literal["Critical", "High", "Medium", "Low"]


class Host(BaseModel):
    id: str
    ip: str
    os: Optional[str] = None


class Actor(BaseModel):
    user: Optional[str] = None
    process_name: Optional[str] = None


class ThreatIntel(BaseModel):
    is_malicious: bool = False
    matched_ioc: Optional[str] = None
    threat_group: Optional[str] = None


class MitreInfo(BaseModel):
    tactic: Optional[str] = None
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None


class Geo(BaseModel):
    lat: Optional[float] = None
    lon: Optional[float] = None
    country_code: Optional[str] = None
    country_name: Optional[str] = None


class NormalizedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    host: Host
    actor: Actor
    action: str
    threat_intel: ThreatIntel = Field(default_factory=ThreatIntel)
    mitre: MitreInfo = Field(default_factory=MitreInfo)
    kill_chain_phase: Optional[KillChainPhase] = None
    severity: Optional[SeverityLevel] = None
    geo: Optional[Geo] = None

    class Config:
        populate_by_name = True
