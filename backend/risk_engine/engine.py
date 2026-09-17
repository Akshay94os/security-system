"""
AK Master Security System — Central Risk Engine (§36)
Unified risk scoring across all security modules.

Inputs:
- URL risk
- File risk
- Process risk
- Network risk
- Identity risk
- Authentication anomalies
- DLP findings
- AI-agent risk
- Behavioral anomalies
- System security state

Output:
- Risk category
- Confidence
- Contributing signals
- Recommended action

Every score has an explainable basis — no arbitrary visual scores.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class OverallRisk(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskCategory(str, Enum):
    IDENTITY = "IDENTITY"
    NETWORK = "NETWORK"
    WEB = "WEB"
    FILES = "FILES"
    APPLICATIONS = "APPLICATIONS"
    AI_AGENT = "AI_AGENT"
    DATA_PROTECTION = "DATA_PROTECTION"
    CONFIGURATION = "CONFIGURATION"
    MONITORING = "MONITORING"


@dataclass
class RiskSignal:
    category: RiskCategory
    source_module: str
    title: str
    description: str
    risk_score: float  # 0.0–1.0
    confidence: float  # 0.0–1.0
    evidence: str = ""
    recommended_action: str = ""
    timestamp: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "source_module": self.source_module,
            "title": self.title,
            "description": self.description,
            "risk_score": round(self.risk_score, 3),
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "recommended_action": self.recommended_action,
        }


@dataclass
class CategoryRiskScore:
    category: RiskCategory
    score: float  # 0.0–1.0
    level: str  # LOW, MEDIUM, HIGH, CRITICAL
    signal_count: int = 0
    top_issue: str = ""
    evidence: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "score": round(self.score, 3),
            "level": self.level,
            "signal_count": self.signal_count,
            "top_issue": self.top_issue,
            "evidence": self.evidence[:5],
            "recommended_actions": self.recommended_actions[:3],
        }


@dataclass
class RiskAssessment:
    overall_risk: OverallRisk
    overall_score: float
    category_scores: List[CategoryRiskScore] = field(default_factory=list)
    contributing_signals: List[RiskSignal] = field(default_factory=list)
    assessed_at: str = ""
    explanation: str = ""

    def to_dict(self) -> dict:
        return {
            "overall_risk": self.overall_risk.value,
            "overall_score": round(self.overall_score, 3),
            "category_scores": [c.to_dict() for c in self.category_scores],
            "contributing_signals_count": len(self.contributing_signals),
            "top_signals": [s.to_dict() for s in self.contributing_signals[:10]],
            "assessed_at": self.assessed_at,
            "explanation": self.explanation,
        }


def _score_to_level(score: float) -> str:
    if score >= 0.7:
        return "CRITICAL"
    elif score >= 0.4:
        return "HIGH"
    elif score >= 0.2:
        return "MEDIUM"
    return "LOW"


class RiskEngine:
    """
    Central risk engine that aggregates signals from all security modules.
    Produces a scorecard with per-category risk assessment.
    """

    def __init__(self):
        self._signals: List[RiskSignal] = []

    def add_signal(self, signal: RiskSignal) -> None:
        self._signals.append(signal)

    def clear(self) -> None:
        self._signals.clear()

    async def assess(self) -> RiskAssessment:
        """
        Compute a full risk assessment from accumulated signals.
        Also gathers real-time data from available modules.
        """
        # Gather real-time signals from modules
        await self._collect_live_signals()

        # Group by category
        category_groups: Dict[RiskCategory, List[RiskSignal]] = {}
        for cat in RiskCategory:
            category_groups[cat] = []

        for signal in self._signals:
            category_groups[signal.category].append(signal)

        # Compute per-category scores
        category_scores: List[CategoryRiskScore] = []
        for cat, signals in category_groups.items():
            if not signals:
                category_scores.append(CategoryRiskScore(
                    category=cat, score=0.0, level="LOW",
                    signal_count=0, top_issue="No issues detected",
                ))
                continue

            # Weighted average of signal scores by confidence
            total_weight = sum(s.confidence for s in signals)
            if total_weight == 0:
                score = 0.0
            else:
                score = sum(s.risk_score * s.confidence for s in signals) / total_weight

            # Boost score if many signals
            if len(signals) >= 3:
                score = min(1.0, score * 1.2)

            sorted_signals = sorted(signals, key=lambda s: s.risk_score * s.confidence, reverse=True)

            category_scores.append(CategoryRiskScore(
                category=cat,
                score=score,
                level=_score_to_level(score),
                signal_count=len(signals),
                top_issue=sorted_signals[0].title if sorted_signals else "",
                evidence=[s.evidence for s in sorted_signals[:5] if s.evidence],
                recommended_actions=[s.recommended_action for s in sorted_signals[:3] if s.recommended_action],
            ))

        # Compute overall score
        active_scores = [cs for cs in category_scores if cs.signal_count > 0]
        if active_scores:
            overall_score = max(cs.score for cs in active_scores)
        else:
            overall_score = 0.0

        overall_risk = OverallRisk(
            "CRITICAL" if overall_score >= 0.7
            else "HIGH" if overall_score >= 0.4
            else "MEDIUM" if overall_score >= 0.2
            else "LOW"
        )

        # Build explanation
        critical_cats = [cs for cs in category_scores if cs.level in ("CRITICAL", "HIGH")]
        if critical_cats:
            issues = [f"{cs.category.value}: {cs.top_issue}" for cs in critical_cats[:3]]
            explanation = "Elevated risk detected:\n" + "\n".join(f"• {i}" for i in issues)
        else:
            explanation = "System security posture is within normal parameters."

        return RiskAssessment(
            overall_risk=overall_risk,
            overall_score=overall_score,
            category_scores=category_scores,
            contributing_signals=sorted(
                self._signals,
                key=lambda s: s.risk_score * s.confidence,
                reverse=True,
            ),
            assessed_at=datetime.now(timezone.utc).isoformat(),
            explanation=explanation,
        )

    async def _collect_live_signals(self) -> None:
        """Collect real-time signals from available modules."""

        # Health-based signals
        try:
            from backend.security.health_monitor import run_health_check, ModuleStatus
            health = await run_health_check()
            for module in health.modules:
                if module.status == ModuleStatus.ERROR:
                    self._signals.append(RiskSignal(
                        category=RiskCategory.MONITORING,
                        source_module="health_monitor",
                        title=f"Module Error: {module.name}",
                        description=module.message,
                        risk_score=0.5,
                        confidence=0.95,
                        evidence=f"Status: {module.status.value}",
                        recommended_action=f"Investigate and restore {module.name}",
                    ))
                elif module.status == ModuleStatus.UNAVAILABLE:
                    self._signals.append(RiskSignal(
                        category=RiskCategory.MONITORING,
                        source_module="health_monitor",
                        title=f"Module Unavailable: {module.name}",
                        description=module.message,
                        risk_score=0.2,
                        confidence=0.9,
                        evidence=f"Status: {module.status.value}",
                        recommended_action=f"Install required dependencies for {module.name}",
                    ))
        except Exception as e:
            logger.error("Risk engine health check failed: %s", e)


# Singleton
_risk_engine: Optional[RiskEngine] = None


def get_risk_engine() -> RiskEngine:
    global _risk_engine
    if _risk_engine is None:
        _risk_engine = RiskEngine()
    return _risk_engine
