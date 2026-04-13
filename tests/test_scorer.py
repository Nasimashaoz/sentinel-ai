"""
Sentinel AI — Tests for RiskScorer
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.scorer import RiskScorer


def test_critical_score():
    s = RiskScorer()
    score = s.score({"risk": "CRITICAL", "count": 1})
    assert score == 90, f"Expected 90, got {score}"


def test_high_score():
    s = RiskScorer()
    score = s.score({"risk": "HIGH", "count": 1})
    assert score == 70


def test_volume_boost_critical():
    s = RiskScorer()
    score = s.score({"risk": "CRITICAL", "count": 2000})
    assert score == 98  # 90 + 8


def test_volume_boost_high_100():
    s = RiskScorer()
    score = s.score({"risk": "HIGH", "count": 500})
    assert score == 74  # 70 + 4


def test_low_score():
    s = RiskScorer()
    score = s.score({"risk": "LOW", "count": 1})
    assert score == 20


def test_unknown_risk_defaults_low():
    s = RiskScorer()
    score = s.score({"risk": "UNKNOWN", "count": 1})
    assert score == 20


if __name__ == "__main__":
    test_critical_score()
    test_high_score()
    test_volume_boost_critical()
    test_volume_boost_high_100()
    test_low_score()
    test_unknown_risk_defaults_low()
    print("✅ All scorer tests passed")
