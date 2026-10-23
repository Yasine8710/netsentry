"""Validated application settings persisted in the database."""

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.detectors.base import ConfigError
from app.detectors.engine import DetectionEngine
from app.models.tables import AppSetting, RuleMetadata


class UiPrefs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    density: str = Field("comfortable", pattern="^(comfortable|compact)$")
    reduced_motion: bool = False
    default_page_size: int = Field(25, ge=10, le=100)


class RuleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    params: dict[str, float | int] = Field(default_factory=dict)


class AppSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_upload_mb: int = Field(50, ge=1, le=500)
    max_packets: int = Field(500_000, ge=1_000, le=5_000_000)
    retention_hours: int = Field(24, ge=1, le=24 * 365)
    store_packet_rows: int = Field(50_000, ge=0, le=500_000)
    detection: dict[str, RuleConfig] = Field(default_factory=dict)
    ui: UiPrefs = Field(default_factory=UiPrefs)


class SettingsValidationError(ValueError):
    pass


class SettingsService:
    KEY = "app_settings"

    def __init__(self, session: Session) -> None:
        self.s = session

    @staticmethod
    def defaults() -> AppSettings:
        env = get_settings()
        return AppSettings(
            max_upload_mb=env.max_upload_mb,
            max_packets=env.max_packets,
            retention_hours=env.retention_hours,
        )

    def get(self) -> AppSettings:
        row = self.s.get(AppSetting, self.KEY)
        return AppSettings.model_validate(row.value) if row else self.defaults()

    def update(self, payload: dict) -> AppSettings:
        try:
            new = AppSettings.model_validate(payload)
            self.engine_config(new)  # validates rule ids and parameter ranges
        except (ValidationError, ConfigError) as exc:
            raise SettingsValidationError(str(exc)) from exc
        row = self.s.get(AppSetting, self.KEY)
        data = new.model_dump()
        if row is None:
            self.s.add(AppSetting(key=self.KEY, value=data))
        else:
            row.value = data
        self.s.commit()
        return new

    @staticmethod
    def engine_config(settings: AppSettings) -> dict:
        cfg = {rid: rc.model_dump() for rid, rc in settings.detection.items()}
        DetectionEngine(config=cfg)  # raises ConfigError if invalid
        return cfg

    def detection_config(self) -> dict:
        return self.engine_config(self.get())


def sync_rule_metadata(session: Session) -> None:
    """Upsert rule documentation rows from the code (the code is the source of truth)."""
    for meta in DetectionEngine().rules_metadata():
        row = session.get(RuleMetadata, meta["id"])
        values = {
            "name": meta["name"],
            "description": meta["description"],
            "limitations": meta["limitations"],
            "false_positive_notes": meta["false_positive_notes"],
            "parameters": meta["parameters"],
        }
        if row is None:
            session.add(RuleMetadata(rule_id=meta["id"], **values))
        else:
            for k, v in values.items():
                setattr(row, k, v)
    session.commit()
