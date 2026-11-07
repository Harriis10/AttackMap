"""Django settings (synthetic fixture)."""
from __future__ import annotations

import os

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "fixture-insecure-key")

DEBUG = False

ALLOWED_HOSTS = ["www.example.com"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django_site.api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_site.api.middleware.TenantMiddleware",
]

ROOT_URLCONF = "django_site.urls"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "orders",
        "USER": "orders",
        "PASSWORD": os.environ.get("DB_PASSWORD", ""),
        "HOST": "127.0.0.1",
    }
}
