"""Pydantic settings for the FastAPI app (synthetic fixture)."""
from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql://orders:orders@127.0.0.1:5432/orders"
    api_token: str = Field(..., env="API_TOKEN")
    session_secret: str = Field(..., env="SESSION_SECRET")

    model_config = {"env_file": ".env"}


settings = Settings()
