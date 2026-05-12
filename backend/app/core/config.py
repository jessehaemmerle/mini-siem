from functools import lru_cache
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Mini SIEM"
    environment: str = "development"
    api_prefix: str = "/api"
    database_url: str = "sqlite:///./mini_siem.db"
    redis_url: str = "redis://redis:6379/0"
    opensearch_url: str = "http://opensearch:9200"
    opensearch_user: str | None = None
    opensearch_password: str | None = None
    jwt_secret: str = Field(default="change-me-in-production")
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 60
    api_key_hash_secret: str = Field(default="change-me-api-key-pepper")
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:8080"]
    demo_ingest_api_key: str = "demo-ingest-key"
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "siem@example.local"
    webhook_timeout_seconds: int = 5
    login_rate_limit: int = 10
    ingestion_rate_limit: int = 600
    default_retention_days: int = 90
    enable_demo_seed_on_start: bool = True

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_origins(cls, value: Any) -> list[str]:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
