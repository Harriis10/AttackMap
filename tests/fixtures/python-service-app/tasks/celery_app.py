"""Celery application (synthetic fixture)."""
from __future__ import annotations

from celery import Celery

celery_app = Celery(
    "orders",
    broker="redis://127.0.0.1:6379/0",
    backend="redis://127.0.0.1:6379/1",
)

celery_app.conf.task_routes = {
    "tasks.jobs.*": {"queue": "orders"},
}
