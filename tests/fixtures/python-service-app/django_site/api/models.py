"""API models (synthetic fixture)."""
from __future__ import annotations

from django.db import models


class Note(models.Model):
    title = models.CharField(max_length=200)
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)
