from fastapi import FastAPI, Header, HTTPException
import hmac
import hashlib
import os
import sqlite3

app = FastAPI()


@app.post("/hooks/payments")
def payments_hook(x_hub_signature: str = Header(default="")) -> dict[str, bool]:
    # Signature gate: events without a valid HMAC are rejected before any write.
    mac = hmac.new(
        os.getenv("HOOK_SECRET", "").encode(), b"payments", hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(x_hub_signature, "sha256=" + mac):
        raise HTTPException(status_code=403)
    db = sqlite3.connect("hooks.db")
    db.execute("insert into hook_events(source) values (?)", ("payments",))
    db.commit()
    return {"accepted": True}


@app.post("/hooks/imports")
def imports_hook() -> dict[str, bool]:
    db = sqlite3.connect("hooks.db")
    db.execute("insert into hook_events(source) values (?)", ("imports",))
    db.commit()
    return {"accepted": True}
