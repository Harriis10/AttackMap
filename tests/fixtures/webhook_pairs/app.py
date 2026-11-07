# Paired webhook-exposure fixtures (AM038).
#
# Flagged by the webhook-exposure synthesis:
#   POST /hooks/orders — accepts inbound events and writes with no signature
#                        verification (the taint-backed public-webhook finding
#                        cannot fire: nothing request-derived reaches a sink).
#
# NOT flagged (safe twins):
#   POST /hooks/signed — HMAC-SHA256 verified with compare_digest before the
#                        write (region-scoped: orders must stay flagged).
#   GET  /hooks/status — webhook-style path but read-only.
#   POST /sync/run     — ordinary mutation without auth: belongs to the
#                        unauth-state-change finding, not the webhook family.
from fastapi import FastAPI, Header
import hashlib
import hmac
import os
import sqlite3

app = FastAPI()


@app.post("/hooks/orders")
def orders_hook() -> dict[str, bool]:
    db = sqlite3.connect("hooks.db")
    db.execute("insert into hook_events(source) values ('orders')")
    db.commit()
    return {"accepted": True}


@app.post("/hooks/signed")
def signed_hook(x_hub_signature: str = Header(default="")) -> dict[str, bool]:
    mac = hmac.new(
        os.getenv("HOOK_SECRET", "").encode(), b"orders", hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(x_hub_signature, "sha256=" + mac):
        return {"accepted": False}
    db = sqlite3.connect("hooks.db")
    db.execute("insert into hook_events(source) values ('signed')")
    db.commit()
    return {"accepted": True}


@app.get("/hooks/status")
def hook_status() -> dict[str, int]:
    db = sqlite3.connect("hooks.db")
    n = db.execute("select count(*) from hook_events").fetchone()[0]
    return {"events": n}


@app.post("/sync/run")
def run_sync() -> dict[str, bool]:
    db = sqlite3.connect("hooks.db")
    db.execute("insert into sync_runs(source) values ('manual')")
    db.commit()
    return {"started": True}
