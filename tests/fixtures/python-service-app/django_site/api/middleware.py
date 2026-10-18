"""Custom middleware (synthetic fixture)."""
from __future__ import annotations


class TenantMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.tenant = request.headers.get("X-Tenant", "public")
        return self.get_response(request)
