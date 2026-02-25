from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.core.config import get_settings


_client: AsyncIOMotorClient | None = None


def get_client() -> AsyncIOMotorClient:
    global _client
    if _client is None:
        settings = get_settings()
        _client = AsyncIOMotorClient(settings.mongodb_uri)
    return _client


def get_database() -> AsyncIOMotorDatabase:
    settings = get_settings()
    return get_client()[settings.mongodb_db]


async def create_indexes() -> None:
    """
    Ensure indexes for fast pivoting on normalized events.
    This follows the TRD requirement that all normalized schema fields are indexed.
    """
    db = get_database()
    events = db["events"]

    # Basic compound indexes for common pivots
    await events.create_index("event_id", unique=True)
    await events.create_index("timestamp")
    await events.create_index("host.id")
    await events.create_index("host.ip")
    await events.create_index("actor.user")
    await events.create_index("actor.process_name")
    await events.create_index("threat_intel.threat_group")
    await events.create_index("mitre.technique_id")
    await events.create_index("kill_chain_phase")

