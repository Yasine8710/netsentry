from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NETSENTRY_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./var/netsentry.db"
    upload_dir: Path = Path("./var/uploads")
    max_upload_mb: int = 50
    max_packets: int = 500_000
    analysis_timeout_s: int = 120
    retention_hours: int = 720  # analysis records; temp uploads are removed immediately
    frontend_dir: Path | None = None  # built UI to serve; defaults to ../frontend/dist
    cors_origins: str = "http://localhost:5173"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
