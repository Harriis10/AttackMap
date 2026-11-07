"""Background jobs (synthetic fixture)."""
from __future__ import annotations

from tasks.celery_app import celery_app


@celery_app.task(bind=True)
def process_order(self, order_id: int):
    return {"order_id": order_id, "status": "processed"}


@celery_app.task
def sync_inventory(product_id: int):
    return {"product_id": product_id}


def enqueue_order(order_id: int):
    process_order.apply_async((order_id,), queue="orders")
    sync_inventory.delay(product_id=7)
