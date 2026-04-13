"""
Sentinel AI — Risk Scorer
Converts threat data into a numeric risk score 0-100.
"""


class RiskScorer:
    RISK_BASE = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 45, "LOW": 20}

    def score(self, threat: dict) -> int:
        base = self.RISK_BASE.get(threat.get("risk", "LOW"), 20)
        count = threat.get("count", 1)
        # Boost score for high-volume attacks
        if count > 1000:
            base = min(100, base + 8)
        elif count > 100:
            base = min(100, base + 4)
        elif count > 20:
            base = min(100, base + 2)
        return base
