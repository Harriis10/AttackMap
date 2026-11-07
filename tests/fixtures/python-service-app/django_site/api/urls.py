"""API URL configuration (synthetic fixture)."""
from __future__ import annotations

from django.urls import path

from django_site.api import views

urlpatterns = [
    path("notes/", views.note_list, name="note-list"),
    path("notes/search", views.note_search, name="note-search"),
    path("notes/<int:pk>", views.note_detail, name="note-detail"),
]
