"""Detection rule interface, finding model and parameter specs."""

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum

from app.analyzers.flow_analyzer import Flow
from app.analyzers.traffic_aggregator import TrafficAggregator


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


def confidence_label(score: float) -> str:
    """Evidence-strength bucket. It is NOT the probability that the activity is malicious.

    low (<0.4): thin or ambiguous evidence; medium (0.4-0.7); high (>=0.7): the observed
    pattern clearly exceeds the configured thresholds in the captured data.
    """
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


@dataclass(frozen=True, slots=True)
class ParamSpec:
    name: str
    default: float | int
    minimum: float | int
    maximum: float | int
    description: str
    kind: type = int

    def validate(self, value) -> float | int:
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ConfigError(f"{self.name}: must be a number")
        if self.kind is int and float(value) != int(value):
            raise ConfigError(f"{self.name}: must be an integer")
        v = self.kind(value)
        if not self.minimum <= v <= self.maximum:
            raise ConfigError(f"{self.name}: must be between {self.minimum} and {self.maximum}")
        return v


class ConfigError(ValueError):
    """Invalid detection configuration."""


@dataclass(slots=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    first_seen: float | None
    last_seen: float | None
    src_ips: list[str]
    dst_ips: list[str]
    evidence: dict
    explanation: str
    why_suspicious: str
    benign_explanations: list[str]
    recommended_steps: list[str]
    confidence: float
    key: str = ""  # stable identity of the finding within a rule (e.g. the source IP)

    @property
    def confidence_label(self) -> str:
        return confidence_label(self.confidence)

    @property
    def fingerprint(self) -> str:
        raw = f"{self.rule_id}|{self.key}|{self.first_seen}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass(slots=True)
class AnalysisContext:
    aggregator: TrafficAggregator
    flows: list[Flow]
    flows_truncated: bool = False
    notes: list[str] = field(default_factory=list)


class DetectionRule(ABC):
    id: str
    name: str
    description: str
    limitations: list[str]
    false_positive_notes: str
    params: list[ParamSpec]

    @abstractmethod
    def detect(self, ctx: AnalysisContext, params: dict) -> list[Finding]:
        """Return findings. Must be deterministic for identical input and params."""

    def resolve_params(self, overrides: dict | None) -> dict:
        overrides = overrides or {}
        known = {p.name: p for p in self.params}
        unknown = set(overrides) - set(known)
        if unknown:
            raise ConfigError(f"{self.id}: unknown parameter(s): {', '.join(sorted(unknown))}")
        return {
            name: spec.validate(overrides[name]) if name in overrides else spec.default
            for name, spec in known.items()
        }

    def metadata(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "limitations": list(self.limitations),
            "false_positive_notes": self.false_positive_notes,
            "parameters": [
                {
                    "name": p.name,
                    "default": p.default,
                    "minimum": p.minimum,
                    "maximum": p.maximum,
                    "description": p.description,
                }
                for p in self.params
            ],
        }
