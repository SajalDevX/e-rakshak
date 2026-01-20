"""
Identity Fusion Engine

Combines multi-signal fingerprints into a weighted confidence score.
Only devices with confidence >= 0.75 are CONFIRMED; others are UNKNOWN.

Confidence Formula:
confidence = Σ(weight_i × signal_confidence_i) + consistency_bonus
"""

from typing import Dict, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from loguru import logger


# Signal weights (total = 1.00)
SIGNAL_WEIGHTS = {
    'tls_ja3': 0.30,           # Cryptographic - highest confidence
    'dhcp_options': 0.25,      # OS-level fingerprint
    'tcpip_stack': 0.20,       # Passive stack fingerprint
    'dns_correlation': 0.15,   # Cloud endpoint mapping
    'mac_oui': 0.05,           # OUI prefix (easily spoofed)
    'hostname': 0.03,          # Self-reported (untrusted)
    'passive_discovery': 0.02  # SSDP/ONVIF (can be faked)
}

# Consistency bonus if all signals agree
CONSISTENCY_BONUS = 0.10

# Confidence threshold for CONFIRMED status
CONFIDENCE_THRESHOLD = 0.75


@dataclass
class Signal:
    """Individual signal result"""
    signal_type: str
    confidence: float
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    os: Optional[str] = None
    raw_data: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            'signal_type': self.signal_type,
            'confidence': self.confidence,
            'vendor': self.vendor,
            'device_type': self.device_type,
            'os': self.os,
            'raw_data': self.raw_data
        }


@dataclass
class DeviceIdentity:
    """Fused device identity with confidence score"""
    ip: str
    mac: str
    vendor: str = "unknown"
    device_type: str = "unknown"
    os: str = "unknown"
    confidence: float = 0.0
    status: str = "UNKNOWN"  # CONFIRMED or UNKNOWN

    # Individual signal confidences
    signals: Dict[str, Signal] = field(default_factory=dict)

    # Final determination
    identity_confirmed: bool = False  # True if confidence >= 0.75

    # Metadata
    first_seen: str = ""
    last_updated: str = ""
    fingerprint_source: str = ""  # Comma-separated signal types

    def to_dict(self) -> dict:
        return {
            'ip': self.ip,
            'mac': self.mac,
            'vendor': self.vendor,
            'device_type': self.device_type,
            'os': self.os,
            'confidence': self.confidence,
            'status': self.status,
            'signals': {k: v.to_dict() for k, v in self.signals.items()},
            'identity_confirmed': self.identity_confirmed,
            'first_seen': self.first_seen,
            'last_updated': self.last_updated,
            'fingerprint_source': self.fingerprint_source
        }


class IdentityFusionEngine:
    """
    Fuses multi-signal fingerprints into weighted confidence score.

    Process:
    1. Collect signals from multiple sources (TLS, DHCP, TCP/IP, DNS, etc.)
    2. Calculate weighted confidence score
    3. Check signal consistency
    4. Determine final identity (CONFIRMED if confidence >= 0.75)
    """

    def __init__(self):
        """Initialize identity fusion engine"""
        self.signal_weights = SIGNAL_WEIGHTS
        self.consistency_bonus = CONSISTENCY_BONUS
        self.confidence_threshold = CONFIDENCE_THRESHOLD

    def add_signal(self, identity: DeviceIdentity, signal: Signal) -> DeviceIdentity:
        """
        Add a signal to device identity.

        Args:
            identity: Current device identity
            signal: New signal to add

        Returns:
            Updated device identity
        """
        # Store signal
        identity.signals[signal.signal_type] = signal

        # Recalculate fused identity
        return self.fuse_signals(identity)

    def fuse_signals(self, identity: DeviceIdentity) -> DeviceIdentity:
        """
        Fuse all collected signals into final identity.

        Args:
            identity: Device identity with collected signals

        Returns:
            Updated device identity with fused confidence score
        """
        if not identity.signals:
            return identity

        # Calculate weighted confidence
        total_confidence = 0.0

        for signal_type, signal in identity.signals.items():
            weight = self.signal_weights.get(signal_type, 0.0)
            total_confidence += weight * signal.confidence

        # Check signal consistency
        consistency = self._check_signal_consistency(identity.signals)

        if consistency:
            total_confidence += self.consistency_bonus

        # Cap at 1.0
        total_confidence = min(total_confidence, 1.0)

        # Determine final identity from highest confidence signals
        final_vendor, final_device_type, final_os = self._determine_final_identity(identity.signals)

        # Update identity
        identity.vendor = final_vendor
        identity.device_type = final_device_type
        identity.os = final_os
        identity.confidence = total_confidence
        identity.status = "CONFIRMED" if total_confidence >= self.confidence_threshold else "UNKNOWN"
        identity.identity_confirmed = total_confidence >= self.confidence_threshold
        identity.last_updated = datetime.now().isoformat()
        identity.fingerprint_source = ','.join(identity.signals.keys())

        logger.info(f"Device {identity.ip}: Identity fused - {identity.vendor}/{identity.device_type} "
                   f"(confidence={identity.confidence:.2f}, status={identity.status})")

        return identity

    def _check_signal_consistency(self, signals: Dict[str, Signal]) -> bool:
        """
        Check if all signals agree on vendor and device_type.

        Args:
            signals: Dict of signals

        Returns:
            True if consistent, False otherwise
        """
        vendors = set()
        device_types = set()

        for signal in signals.values():
            if signal.vendor:
                vendors.add(signal.vendor.lower())
            if signal.device_type:
                device_types.add(signal.device_type.lower())

        # Consistent if only one unique vendor and device_type
        consistent = len(vendors) <= 1 and len(device_types) <= 1

        if consistent and vendors:
            logger.debug(f"Signal consistency: PASS (all agree on {list(vendors)[0]})")
        else:
            logger.debug(f"Signal consistency: FAIL (vendors={vendors}, types={device_types})")

        return consistent

    def _determine_final_identity(self, signals: Dict[str, Signal]) -> tuple:
        """
        Determine final vendor/device_type/os from signals.

        Strategy: Use highest-weighted signal with non-None value.

        Args:
            signals: Dict of signals

        Returns:
            (vendor, device_type, os)
        """
        # Sort signals by weight (highest first)
        sorted_signals = sorted(
            signals.items(),
            key=lambda x: self.signal_weights.get(x[0], 0.0),
            reverse=True
        )

        vendor = "unknown"
        device_type = "unknown"
        os = "unknown"

        # Get first non-None value for each attribute from highest-weighted signals
        for signal_type, signal in sorted_signals:
            if vendor == "unknown" and signal.vendor:
                vendor = signal.vendor
            if device_type == "unknown" and signal.device_type:
                device_type = signal.device_type
            if os == "unknown" and signal.os:
                os = signal.os

            # Break early if all found
            if vendor != "unknown" and device_type != "unknown" and os != "unknown":
                break

        return vendor, device_type, os

    def calculate_confidence(self, signals: Dict[str, Signal]) -> float:
        """
        Calculate confidence score from signals.

        Args:
            signals: Dict of signals

        Returns:
            Confidence score (0.0 - 1.0)
        """
        total_confidence = 0.0

        for signal_type, signal in signals.items():
            weight = self.signal_weights.get(signal_type, 0.0)
            total_confidence += weight * signal.confidence

        # Consistency bonus
        if self._check_signal_consistency(signals):
            total_confidence += self.consistency_bonus

        return min(total_confidence, 1.0)

    def assign_identity_status(self, confidence: float) -> str:
        """
        Assign device identity status based on confidence threshold.

        Args:
            confidence: Confidence score

        Returns:
            "CONFIRMED" or "UNKNOWN"
        """
        return "CONFIRMED" if confidence >= self.confidence_threshold else "UNKNOWN"
