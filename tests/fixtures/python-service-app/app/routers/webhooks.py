"""Inbound webhook routes (synthetic fixture)."""
from __future__ import annotations

import os

import requests

from fastapi import APIRouter

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("/stripe")
def stripe_webhook(event: dict):
    # Forwards inbound events without verifying the Stripe-Signature header.
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    requests.post("https://billing.example.com/events", json=event, headers={"X-Secret": secret})
    return {"received": True}
