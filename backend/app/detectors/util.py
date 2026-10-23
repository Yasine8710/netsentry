"""Shared helpers for rules."""

from collections import Counter

from app.detectors.base import Severity


def best_window(events: list[tuple], window_s: float) -> tuple[int, int, int]:
    """Sliding window over time-sorted events (ts, value, ...).

    Returns (max distinct values, left index, right index) of the best window, where a window
    spans at most `window_s` seconds (inclusive). Earliest best window wins ties.
    """
    counts: Counter = Counter()
    left = 0
    best = (0, 0, -1)
    for right, ev in enumerate(events):
        counts[ev[1]] += 1
        while ev[0] - events[left][0] > window_s:
            v = events[left][1]
            counts[v] -= 1
            if counts[v] == 0:
                del counts[v]
            left += 1
        if len(counts) > best[0]:
            best = (len(counts), left, right)
    return best


def best_weighted_window(events: list[tuple], window_s: float) -> tuple[int, int, int]:
    """Like best_window but sums events' weight (ts, weight, ...)."""
    left = 0
    total = 0
    best = (0, 0, -1)
    for right, ev in enumerate(events):
        total += ev[1]
        while ev[0] - events[left][0] > window_s:
            total -= events[left][1]
            left += 1
        if total > best[0]:
            best = (total, left, right)
    return best


def severity_for_ratio(ratio: float, medium_at: float = 2.0, high_at: float = 5.0) -> Severity:
    """ratio = observed / configured threshold."""
    if ratio >= high_at:
        return Severity.HIGH
    if ratio >= medium_at:
        return Severity.MEDIUM
    return Severity.LOW


def confidence_for_ratio(ratio: float, bonus: float = 0.0, penalty: float = 0.0) -> float:
    """Evidence strength: 0.4 right at the threshold, rising to 0.8 at 5x, adjusted by context."""
    base = 0.4 + 0.4 * min(1.0, max(0.0, (ratio - 1.0) / 4.0))
    return round(min(0.95, max(0.1, base + bonus - penalty)), 2)
