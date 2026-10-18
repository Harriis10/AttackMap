"""Site-level views (synthetic fixture)."""
from __future__ import annotations

from django.http import JsonResponse


def health(request):
    return JsonResponse({"status": "ok"})
