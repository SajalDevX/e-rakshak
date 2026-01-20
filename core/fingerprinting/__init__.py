"""
E-RAKSHA Multi-Signal Device Fingerprinting Module

This module implements passive device fingerprinting using multiple signals:
- TLS/JA3: Cryptographic fingerprint from TLS ClientHello
- DHCP: Option 55 ordering for OS detection
- TCP/IP Stack: p0f-style passive OS fingerprinting
- DNS: Cloud endpoint correlation

Confidence-scored identity fusion with 0.75 threshold for CONFIRMED status.
"""

from .tls_fingerprinter import TLSFingerprinter
from .dhcp_fingerprinter import DHCPFingerprinter
from .tcpip_fingerprinter import TCPIPFingerprinter
from .dns_correlator import DNSCorrelator
from .identity_fusion import IdentityFusionEngine, DeviceIdentity
from .vendor_databases import VendorDatabaseManager

__all__ = [
    'TLSFingerprinter',
    'DHCPFingerprinter',
    'TCPIPFingerprinter',
    'DNSCorrelator',
    'IdentityFusionEngine',
    'DeviceIdentity',
    'VendorDatabaseManager'
]
