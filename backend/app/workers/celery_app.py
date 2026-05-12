from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery("mini_siem", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.beat_schedule = {
    "run-detection-every-minute": {
        "task": "app.workers.tasks.run_detection_task",
        "schedule": 60.0,
    },
    "run-retention-hourly": {
        "task": "app.workers.tasks.run_retention_task",
        "schedule": 3600.0,
    },
}
celery_app.conf.timezone = "UTC"
