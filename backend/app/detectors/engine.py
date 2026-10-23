"""Runs detection rules over an AnalysisContext."""

from app.detectors.base import AnalysisContext, ConfigError, DetectionRule, Finding


def default_rules() -> list[DetectionRule]:
    # Imported lazily so rule modules can import the base without cycles.
    from app.detectors import registry

    return registry.all_rules()


class DetectionEngine:
    """config shape: {rule_id: {"enabled": bool, "params": {name: value}}}"""

    def __init__(
        self, rules: list[DetectionRule] | None = None, config: dict | None = None
    ) -> None:
        self.rules = sorted(rules if rules is not None else default_rules(), key=lambda r: r.id)
        self.config = config or {}
        ids = {r.id for r in self.rules}
        if len(ids) != len(self.rules):
            raise ConfigError("Duplicate rule ids")
        unknown = set(self.config) - ids
        if unknown:
            raise ConfigError(f"Unknown rule(s) in config: {', '.join(sorted(unknown))}")
        # Validate eagerly so bad config fails before any analysis work.
        self._params = {r.id: r.resolve_params(self._rule_cfg(r).get("params")) for r in self.rules}

    def _rule_cfg(self, rule: DetectionRule) -> dict:
        cfg = self.config.get(rule.id, {})
        extra = set(cfg) - {"enabled", "params"}
        if extra:
            raise ConfigError(f"{rule.id}: unknown config key(s): {', '.join(sorted(extra))}")
        return cfg

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            if not self._rule_cfg(rule).get("enabled", True):
                continue
            findings.extend(rule.detect(ctx, self._params[rule.id]))
        findings.sort(
            key=lambda f: (
                -f.severity.rank,
                f.first_seen if f.first_seen is not None else float("inf"),
                f.rule_id,
                f.key,
            )
        )
        return findings

    def rules_metadata(self) -> list[dict]:
        return [r.metadata() | {"effective_params": self._params[r.id]} for r in self.rules]
