"""Independent inert-source probes for the sibling static mount helper."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "src"))
from attackmap.ecosystem_python import scan_python_services
from attackmap.python_route_binding import BindingIndex


def main():
    prelude = "from fastapi import FastAPI, APIRouter, Depends, HTTPException\nimport jwt\n"
    tail = "\napi = APIRouter()\n@api.get('/public')\ndef public(): return {}\napp = FastAPI()\napp.include_router(api, dependencies=[Depends(guard)])\n"
    specimens = {
        "blocking-control": "def guard(token):\n    if not token:\n        raise HTTPException(status_code=401)\n",
        "constant-credential": "def guard():\n    token = True\n    if not token:\n        raise HTTPException(status_code=401)\n",
        "jwt-signature-disabled": "def guard(token):\n    try:\n        jwt.decode(token, key='secret', algorithms=['HS256'], options={'verify_signature': False})\n    except Exception:\n        raise HTTPException(status_code=401)\n",
        "constructor-default-rebinding": "def FakeRouter(): return object()\ndef unrelated(default=(APIRouter := FakeRouter)): pass\ndef guard(token):\n    if not token:\n        raise HTTPException(status_code=401)\n",
        "exception-default-rebinding": "def fake_exception(**kwargs): return Exception()\ndef unrelated(default=(HTTPException := fake_exception)): pass\ndef guard(token):\n    if not token:\n        raise HTTPException(status_code=401)\n",
    }
    rows = []
    for name, body in specimens.items():
        text = prelude + body + tail
        fixture = ROOT / ".tmp/wp039-python-20261023/mount-independent" / name
        fixture.mkdir(parents=True, exist_ok=True)
        path = fixture / "main.py"
        if path.exists() and path.read_text(encoding="utf-8") != text:
            raise RuntimeError(f"Refusing to replace different specimen: {path}")
        if not path.exists():
            path.write_text(text, encoding="utf-8")
        bindings = BindingIndex({"main.py": text})
        result = scan_python_services(fixture)
        rows.append({"case": name, "fixture_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                     "guards": [{"name": definition.name, "blocking_guard": definition.blocking_guard} for definition, _node, _scope in bindings.definitions],
                     "mounts": [{"supported": mount.supported, "dependencies": [item.name for item in mount.dependencies]} for mount in bindings.mounts],
                     "routes": [route.model_dump(mode="json") for route in result.routes],
                     "limitations": result.limitations})
    products = [ROOT / "src/attackmap/python_route_binding.py", ROOT / "src/attackmap/ecosystem_python.py"]
    output = {"scope": "Inert static extraction; no FastAPI/PyJWT imports or execution.",
              "sources": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in products}, "results": rows}
    output_path = Path(sys.argv[1])
    output_path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output_path), "routes": {row["case"]: [(route["path"], route["auth"]) for route in row["routes"]] for row in rows}}))


if __name__ == "__main__":
    main()
