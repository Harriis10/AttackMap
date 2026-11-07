from fastapi import Depends, FastAPI, Header
import hashlib
import hmac
import os
import sqlite3

app = FastAPI()


@app.get("/docs/{doc_id}")
def get_doc(doc_id: str) -> dict[str, str]:
    db = sqlite3.connect("docs.db")
    row = db.execute(
        "select title, body from docs where id = ?", (doc_id,)
    ).fetchone()
    return {"title": row[0]}


@app.delete("/docs/{doc_id}")
def delete_doc(doc_id: str) -> dict[str, bool]:
    db = sqlite3.connect("docs.db")
    db.execute("delete from docs where id = ?", (doc_id,))
    db.commit()
    return {"deleted": True}


@app.post("/hooks/github")
def github_hook() -> dict[str, bool]:
    # Accepts inbound events with no signature verification.
    db = sqlite3.connect("docs.db")
    db.execute("insert into hook_events(source) values (?)", ("github",))
    db.commit()
    return {"accepted": True}


@app.post("/hooks/verified")
def verified_hook(x_hub_signature: str = Header(default="")) -> dict[str, bool]:
    # Safe twin: HMAC-SHA256 verified before any write.
    mac = hmac.new(
        os.getenv("HOOK_SECRET", "").encode(), b"github", hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(x_hub_signature, "sha256=" + mac):
        return {"accepted": False}
    db = sqlite3.connect("docs.db")
    db.execute("insert into hook_events(source) values (?)", ("verified",))
    db.commit()
    return {"accepted": True}


@app.get("/hooks/events")
def list_hook_events() -> dict[str, list]:
    db = sqlite3.connect("docs.db")
    rows = db.execute("select source from hook_events").fetchall()
    return {"events": [r[0] for r in rows]}


def require_admin():
    return {"role": "admin"}


@app.post("/admin/bulk")
def bulk_reindex() -> dict[str, bool]:
    db = sqlite3.connect("docs.db")
    db.execute("reindex")
    db.commit()
    return {"reindexed": True}


@app.post("/admin/sync", dependencies=[Depends(require_admin)])
def sync_docs() -> dict[str, bool]:
    # Safe twin: router-declared auth dependency on the route decorator.
    db = sqlite3.connect("docs.db")
    db.execute("insert into sync_log(source) values ('manual')")
    db.commit()
    return {"synced": True}


@app.post("/jobs/run")
def run_job(payload: dict) -> dict[str, bool]:
    name = payload.get("name", "nightly")
    db = sqlite3.connect("docs.db")
    db.execute("insert into jobs(name) values (?)", (name,))
    db.commit()
    return {"started": True}
