"""Read-only engine probe over newly retained, inert settings specimens."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "src"))
from attackmap.ecosystem_python import scan_python_services


def main():
    fixture_root = ROOT / ".tmp/wp039-python-20261023/django-settings-review"
    settings = "ROOT_URLCONF = 'project.urls'\nMIDDLEWARE = ['django.contrib.auth.middleware.AuthenticationMiddleware', 'django.contrib.auth.middleware.LoginRequiredMiddleware']\n"
    additions = {
        "valid-control": "",
        "delete-middleware": "del MIDDLEWARE\n",
        "delete-root": "del ROOT_URLCONF\n",
        "function-rebinding": "def MIDDLEWARE(): pass\n",
        "import-rebinding": "from elsewhere import MIDDLEWARE\n",
        "except-capture": "try:\n    something()\nexcept Exception as MIDDLEWARE:\n    pass\n",
        "match-capture": "match something:\n    case MIDDLEWARE:\n        pass\n",
        "match-mapping-rest": "match something:\n    case {'item': _, **MIDDLEWARE}:\n        pass\n",
    }
    results = []
    for name, addition in additions.items():
        case = fixture_root / name
        sources = {
            "project/settings.py": settings + addition,
            "project/urls.py": "from django.urls import path\nfrom app import views\nurlpatterns = [path('public/', views.public)]\n",
            "app/views.py": "def public(request): return None\n",
        }
        for rel, source in sources.items():
            destination = case / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() and destination.read_text(encoding="utf-8") != source:
                raise RuntimeError(f"Refusing to replace different specimen: {destination}")
            if not destination.exists():
                destination.write_text(source, encoding="utf-8")
        result = scan_python_services(case)
        expected = "required" if name == "valid-control" else "unknown"
        routes = [route.model_dump(mode="json") for route in result.routes]
        actual = [route.auth for route in result.routes if route.path == "/public/"]
        results.append({"case": name, "expected_auth": expected, "actual_auth": actual,
                        "pass": actual == [expected], "routes": routes,
                        "limitations": result.limitations,
                        "files": {rel: hashlib.sha256((case / rel).read_bytes()).hexdigest() for rel in sources}})
    product = ROOT / "src/attackmap/ecosystem_python.py"
    output = {"scope": "Static source extraction only; specimens are not executed.",
              "source_sha256": hashlib.sha256(product.read_bytes()).hexdigest(), "results": results}
    output_path = Path(sys.argv[1])
    output_path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output_path), "pass_count": sum(row["pass"] for row in results),
                      "case_count": len(results), "failures": [row["case"] for row in results if not row["pass"]]}))


if __name__ == "__main__":
    main()
