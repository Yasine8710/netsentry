import pytest

from app.analyzers.traffic_aggregator import TrafficAggregator
from app.detectors.base import (
    AnalysisContext,
    ConfigError,
    DetectionRule,
    Finding,
    ParamSpec,
    Severity,
    confidence_label,
)
from app.detectors.engine import DetectionEngine


class FakeRule(DetectionRule):
    id = "fake"
    name = "Fake"
    description = "d"
    limitations = ["l"]
    false_positive_notes = "n"
    params = [ParamSpec("threshold", 5, 1, 100, "t")]

    def detect(self, ctx, params):
        return [
            Finding(
                self.id,
                Severity.LOW,
                "t",
                2.0,
                3.0,
                ["a"],
                ["b"],
                {"th": params["threshold"]},
                "e",
                "w",
                ["b"],
                ["s"],
                0.5,
                key="k1",
            ),
            Finding(
                self.id,
                Severity.HIGH,
                "t",
                9.0,
                9.0,
                ["a"],
                [],
                {},
                "e",
                "w",
                [],
                [],
                0.9,
                key="k0",
            ),
        ]


def ctx():
    return AnalysisContext(TrafficAggregator(), [])


def test_runs_and_sorts_by_severity():
    out = DetectionEngine([FakeRule()]).run(ctx())
    assert [f.severity for f in out] == [Severity.HIGH, Severity.LOW]


def test_default_params_and_override():
    assert DetectionEngine([FakeRule()]).run(ctx())[1].evidence["th"] == 5
    cfg = {"fake": {"params": {"threshold": 7}}}
    assert DetectionEngine([FakeRule()], cfg).run(ctx())[1].evidence["th"] == 7


def test_disabled_rule_skipped():
    assert DetectionEngine([FakeRule()], {"fake": {"enabled": False}}).run(ctx()) == []


@pytest.mark.parametrize(
    "cfg",
    [
        {"nope": {}},
        {"fake": {"params": {"threshold": 0}}},
        {"fake": {"params": {"threshold": 101}}},
        {"fake": {"params": {"threshold": "5"}}},
        {"fake": {"params": {"threshold": 2.5}}},
        {"fake": {"params": {"bogus": 1}}},
        {"fake": {"enable": True}},
    ],
)
def test_invalid_config_rejected(cfg):
    with pytest.raises(ConfigError):
        DetectionEngine([FakeRule()], cfg)


def test_deterministic():
    a = DetectionEngine([FakeRule()]).run(ctx())
    b = DetectionEngine([FakeRule()]).run(ctx())
    assert [f.fingerprint for f in a] == [f.fingerprint for f in b]


def test_confidence_labels():
    assert [confidence_label(x) for x in (0.1, 0.4, 0.69, 0.7)] == [
        "low",
        "medium",
        "medium",
        "high",
    ]


def test_metadata_lists_parameters():
    m = DetectionEngine([FakeRule()]).rules_metadata()[0]
    assert m["effective_params"] == {"threshold": 5} and m["parameters"][0]["maximum"] == 100
