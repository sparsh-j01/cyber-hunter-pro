import os

from celery import Celery

from app.core.config import get_settings


settings = get_settings()

os.environ.setdefault("FORKED_BY_MULTIPROCESSING", "1")

celery_app = Celery(
    "cyberhunterpro",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_routes={
        "app.workers.tasks.*": {"queue": "default"},
    },
    task_default_queue="default",
)

