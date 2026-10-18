"""FastAPI application entrypoint (synthetic fixture)."""
from __future__ import annotations

import uvicorn
from fastapi import Depends, FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.deps import verify_tenant
from app.routers import items, webhooks

app = FastAPI(title="orders-api")

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["orders.example.com"])

app.include_router(items.router, prefix="/api", dependencies=[Depends(verify_tenant)])

app.include_router(webhooks.router)


@app.post("/admin/rebuild")
def rebuild_index():
    # Deliberate gap: privileged rebuild mutation with no auth dependency.
    return {"rebuilt": True}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
