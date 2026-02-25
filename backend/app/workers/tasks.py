from datetime import datetime

from celery import shared_task
from pymongo import MongoClient

from app.core.config import get_settings


@shared_task
def enrich_event_with_cti(event_id: str) -> None:
    """
    Placeholder for CTI enrichment logic.
    In a full implementation this would:
      - poll TAXII/STIX feeds
      - update threat_intel fields on the event
    This task is optional and not required to run the basic demo.
    """
    settings = get_settings()
    client = MongoClient(settings.mongodb_uri)
    try:
        db = client[settings.mongodb_db]
        db["events"].update_one(
            {"event_id": event_id},
            {
                "$set": {
                    "threat_intel.enriched_at": datetime.utcnow(),
                }
            },
        )
    finally:
        client.close()

