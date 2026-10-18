"""Root URL configuration (synthetic fixture)."""
from __future__ import annotations

from django.contrib import admin
from django.urls import include, path

from django_site import views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("django_site.api.urls")),
    path("health/", views.health, name="health"),
]
