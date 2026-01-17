#!/usr/bin/env python3
"""
Response Decision Engine
========================

Autonomous response system with 7-level threat escalation.

Escalation Levels:
0. MONITOR - Log only, no action
1. ALERT - Generate alert for admin
2. RATE_LIMIT - Apply traffic rate limiting
3. DEPLOY_HONEYPOT - Redirect to honeypot
4. QUARANTINE - Move to quarantine zone
5. ISOLATE - Block all traffic except management
6. FULL_BLOCK - Complete network isolation

Decision Factors:
- Threat severity
- Attack confidence
- Device criticality
- Attack chain involvement
- Historical behavior
- Identity drift score

Author: Team RAKSHAK
"""

from enum import Enum
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

from loguru import logger


class ResponseLevel(Enum):
    """Response escalation levels."""
    MONITOR = 0
    ALERT = 1
    RATE_LIMIT = 2
    DEPLOY_HONEYPOT = 3
    QUARANTINE = 4
    ISOLATE = 5
    FULL_BLOCK = 6


@dataclass
class ThreatContext:
    """Context information for threat response decision."""
    threat_type: str
    severity: str  # low, medium, high, critical
    confidence: float  # 0.0-1.0
    source_ip: str
    device_type: str = "unknown"
    device_zone: str = "guest"
    identity_confidence: float = 0.0
    drift_score: float = 0.0
    in_attack_chain: bool = False
    chain_length: int = 0
    anomaly_count: int = 0
    is_repeat_offender: bool = False
    device_criticality: str = "low"  # low, medium, high, critical
    attack_indicators: List[str] = None

    def __post_init__(self):
        if self.attack_indicators is None:
            self.attack_indicators = []


@dataclass
class ResponseDecision:
    """Response decision output."""
    level: ResponseLevel
    action: str
    reason: str
    confidence: float
    auto_execute: bool
    escalation_path: List[str]
    recommended_duration: Optional[int] = None  # minutes
    requires_approval: bool = False


class ResponseDecisionEngine:
    """
    Autonomous response decision engine with graduated escalation.

    Makes intelligent decisions about threat response based on:
    - Threat characteristics
    - Device context
    - Attack patterns
    - Historical behavior
    """

    # Severity weights
    SEVERITY_WEIGHTS = {
        'low': 0.25,
        'medium': 0.50,
        'high': 0.75,
        'critical': 1.0
    }

    # Device criticality weights (reduces response aggressiveness)
    CRITICALITY_WEIGHTS = {
        'low': 1.0,      # Full response
        'medium': 0.80,  # 80% response
        'high': 0.60,    # 60% response
        'critical': 0.40  # 40% response (avoid disruption)
    }

    def __init__(self, config: dict):
        """
        Initialize response decision engine.

        Args:
            config: Configuration dictionary
        """
        self.config = config

        # Configuration
        response_config = config.get("enhanced_detection", {}).get("response_engine", {})
        self.enabled = response_config.get("enabled", True)
        self.auto_execution_threshold = response_config.get("auto_execution_threshold", ResponseLevel.QUARANTINE.value)
        self.require_approval_above = response_config.get("require_approval_above", ResponseLevel.ISOLATE.value)

        # Response history for repeat offender detection
        self.response_history: Dict[str, List[dict]] = {}

        logger.info(f"ResponseDecisionEngine initialized (auto_exec_threshold={self.auto_execution_threshold})")

    def decide_response(self, context: ThreatContext) -> ResponseDecision:
        """
        Decide appropriate response level for a threat.

        Args:
            context: Threat context information

        Returns:
            ResponseDecision object
        """
        if not self.enabled:
            return ResponseDecision(
                level=ResponseLevel.MONITOR,
                action="log_only",
                reason="Response engine disabled",
                confidence=1.0,
                auto_execute=False,
                escalation_path=[]
            )

        # Calculate threat score (0.0-1.0)
        threat_score = self._calculate_threat_score(context)

        # Calculate response level
        response_level = self._determine_response_level(threat_score, context)

        # Check if repeat offender (escalate if yes)
        if context.is_repeat_offender:
            response_level = self._escalate_for_repeat_offender(response_level)

        # Generate decision
        decision = self._generate_decision(response_level, context, threat_score)

        # Record decision
        self._record_decision(context.source_ip, decision)

        logger.info(
            f"Response Decision: {context.source_ip} | "
            f"Threat={context.threat_type} | Score={threat_score:.2f} | "
            f"Level={decision.level.name} | Action={decision.action}"
        )

        return decision

    def _calculate_threat_score(self, context: ThreatContext) -> float:
        """
        Calculate composite threat score (0.0-1.0).

        Components:
        - Severity (40%)
        - Confidence (20%)
        - Identity drift (15%)
        - Attack chain involvement (15%)
        - Anomaly history (10%)
        """
        # Base severity score
        severity_score = self.SEVERITY_WEIGHTS.get(context.severity, 0.5)

        # Confidence score
        confidence_score = context.confidence

        # Identity drift score
        drift_score = context.drift_score

        # Attack chain score
        if context.in_attack_chain:
            chain_score = min(context.chain_length / 5.0, 1.0)  # Normalize by 5 hops
        else:
            chain_score = 0.0

        # Anomaly history score
        anomaly_score = min(context.anomaly_count / 10.0, 1.0)  # Normalize by 10 anomalies

        # Weighted composite
        threat_score = (
            severity_score * 0.40 +
            confidence_score * 0.20 +
            drift_score * 0.15 +
            chain_score * 0.15 +
            anomaly_score * 0.10
        )

        # Apply device criticality modifier (reduce score for critical devices)
        criticality_modifier = self.CRITICALITY_WEIGHTS.get(context.device_criticality, 1.0)
        threat_score *= criticality_modifier

        # Special threat types (immediate escalation)
        if context.threat_type in ['IOT_LATERAL_MOVEMENT', 'QUARANTINE_BREACH_ATTEMPT', 'CASCADE_COMPROMISE']:
            threat_score = min(threat_score + 0.3, 1.0)  # Boost by 0.3

        return min(threat_score, 1.0)

    def _determine_response_level(self, threat_score: float, context: ThreatContext) -> ResponseLevel:
        """Determine response level based on threat score."""

        # Level 6: FULL_BLOCK (>= 0.95)
        if threat_score >= 0.95:
            return ResponseLevel.FULL_BLOCK

        # Level 5: ISOLATE (>= 0.80)
        elif threat_score >= 0.80:
            return ResponseLevel.ISOLATE

        # Level 4: QUARANTINE (>= 0.65)
        elif threat_score >= 0.65:
            return ResponseLevel.QUARANTINE

        # Level 3: DEPLOY_HONEYPOT (>= 0.50)
        elif threat_score >= 0.50:
            return ResponseLevel.DEPLOY_HONEYPOT

        # Level 2: RATE_LIMIT (>= 0.35)
        elif threat_score >= 0.35:
            return ResponseLevel.RATE_LIMIT

        # Level 1: ALERT (>= 0.20)
        elif threat_score >= 0.20:
            return ResponseLevel.ALERT

        # Level 0: MONITOR
        else:
            return ResponseLevel.MONITOR

    def _escalate_for_repeat_offender(self, current_level: ResponseLevel) -> ResponseLevel:
        """Escalate response for repeat offenders."""
        escalation_map = {
            ResponseLevel.MONITOR: ResponseLevel.ALERT,
            ResponseLevel.ALERT: ResponseLevel.RATE_LIMIT,
            ResponseLevel.RATE_LIMIT: ResponseLevel.DEPLOY_HONEYPOT,
            ResponseLevel.DEPLOY_HONEYPOT: ResponseLevel.QUARANTINE,
            ResponseLevel.QUARANTINE: ResponseLevel.ISOLATE,
            ResponseLevel.ISOLATE: ResponseLevel.FULL_BLOCK,
            ResponseLevel.FULL_BLOCK: ResponseLevel.FULL_BLOCK  # Max level
        }

        escalated = escalation_map.get(current_level, current_level)
        logger.warning(f"Escalating response for repeat offender: {current_level.name} → {escalated.name}")
        return escalated

    def _generate_decision(
        self,
        level: ResponseLevel,
        context: ThreatContext,
        threat_score: float
    ) -> ResponseDecision:
        """Generate complete response decision."""

        # Define actions for each level
        action_map = {
            ResponseLevel.MONITOR: {
                'action': 'log_only',
                'duration': None,
                'reason': f"Low threat score ({threat_score:.2f}), monitoring only"
            },
            ResponseLevel.ALERT: {
                'action': 'generate_alert',
                'duration': None,
                'reason': f"Suspicious activity detected (score={threat_score:.2f})"
            },
            ResponseLevel.RATE_LIMIT: {
                'action': 'apply_rate_limit',
                'duration': 30,  # 30 minutes
                'reason': f"Moderate threat detected, limiting traffic rate"
            },
            ResponseLevel.DEPLOY_HONEYPOT: {
                'action': 'redirect_to_honeypot',
                'duration': 60,  # 1 hour
                'reason': f"Likely attack detected, redirecting to honeypot for analysis"
            },
            ResponseLevel.QUARANTINE: {
                'action': 'move_to_quarantine_zone',
                'duration': 120,  # 2 hours
                'reason': f"High threat detected (score={threat_score:.2f}), quarantining device"
            },
            ResponseLevel.ISOLATE: {
                'action': 'full_network_isolation',
                'duration': 480,  # 8 hours
                'reason': f"Critical threat detected, isolating device from network"
            },
            ResponseLevel.FULL_BLOCK: {
                'action': 'complete_block_permanent',
                'duration': None,  # Permanent
                'reason': f"Severe threat confirmed (score={threat_score:.2f}), permanent isolation required"
            }
        }

        action_info = action_map[level]

        # Determine if auto-execute
        auto_execute = level.value <= self.auto_execution_threshold

        # Determine if requires approval
        requires_approval = level.value >= self.require_approval_above

        # Build escalation path
        escalation_path = self._build_escalation_path(level)

        return ResponseDecision(
            level=level,
            action=action_info['action'],
            reason=action_info['reason'],
            confidence=threat_score,
            auto_execute=auto_execute,
            escalation_path=escalation_path,
            recommended_duration=action_info['duration'],
            requires_approval=requires_approval
        )

    def _build_escalation_path(self, current_level: ResponseLevel) -> List[str]:
        """Build escalation path from current level."""
        all_levels = [
            ResponseLevel.MONITOR,
            ResponseLevel.ALERT,
            ResponseLevel.RATE_LIMIT,
            ResponseLevel.DEPLOY_HONEYPOT,
            ResponseLevel.QUARANTINE,
            ResponseLevel.ISOLATE,
            ResponseLevel.FULL_BLOCK
        ]

        path = []
        for level in all_levels:
            path.append(level.name)
            if level == current_level:
                break

        return path

    def _record_decision(self, source_ip: str, decision: ResponseDecision):
        """Record decision in history for repeat offender detection."""
        if source_ip not in self.response_history:
            self.response_history[source_ip] = []

        self.response_history[source_ip].append({
            'timestamp': datetime.now().isoformat(),
            'level': decision.level.value,
            'action': decision.action,
            'confidence': decision.confidence
        })

        # Keep only last 100 decisions per IP
        if len(self.response_history[source_ip]) > 100:
            self.response_history[source_ip] = self.response_history[source_ip][-100:]

    def check_repeat_offender(self, source_ip: str, window_hours: int = 24) -> bool:
        """
        Check if IP is a repeat offender.

        Args:
            source_ip: IP address to check
            window_hours: Time window in hours

        Returns:
            True if repeat offender
        """
        if source_ip not in self.response_history:
            return False

        cutoff_time = datetime.now() - timedelta(hours=window_hours)

        recent_responses = [
            r for r in self.response_history[source_ip]
            if datetime.fromisoformat(r['timestamp']) > cutoff_time
        ]

        # Consider repeat offender if 3+ responses in window
        return len(recent_responses) >= 3

    def get_response_statistics(self) -> dict:
        """Get response engine statistics."""
        level_counts = {level.name: 0 for level in ResponseLevel}

        total_responses = 0
        for responses in self.response_history.values():
            for response in responses:
                total_responses += 1
                level = response['level']
                level_name = ResponseLevel(level).name
                level_counts[level_name] += 1

        return {
            'total_responses': total_responses,
            'total_devices': len(self.response_history),
            'responses_by_level': level_counts,
            'repeat_offenders': sum(1 for ip in self.response_history if self.check_repeat_offender(ip))
        }

    def recommend_escalation(self, source_ip: str, current_level: ResponseLevel) -> Optional[ResponseLevel]:
        """
        Recommend escalation if device continues malicious activity.

        Args:
            source_ip: IP address
            current_level: Current response level

        Returns:
            Recommended new level or None
        """
        if source_ip not in self.response_history:
            return None

        # Check recent responses in last hour
        cutoff_time = datetime.now() - timedelta(hours=1)
        recent_responses = [
            r for r in self.response_history[source_ip]
            if datetime.fromisoformat(r['timestamp']) > cutoff_time
        ]

        # If multiple responses at same level = escalate
        same_level_count = sum(1 for r in recent_responses if r['level'] == current_level.value)

        if same_level_count >= 3:
            # Recommend escalation
            escalated = self._escalate_for_repeat_offender(current_level)
            if escalated != current_level:
                logger.warning(
                    f"Recommending escalation for {source_ip}: "
                    f"{current_level.name} → {escalated.name} "
                    f"({same_level_count} responses at current level)"
                )
                return escalated

        return None
