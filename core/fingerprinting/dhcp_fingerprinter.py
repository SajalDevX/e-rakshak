"""
DHCP Option 55 Fingerprinting Module

Extracts DHCP Parameter Request List (Option 55) ordering for OS fingerprinting.
Option 55 ordering is OS-specific and difficult to spoof.

Weight: 0.25 (OS-level fingerprint)
"""

from typing import Dict, Optional, List
from dataclasses import dataclass
from loguru import logger


@dataclass
class DHCPFingerprint:
    """DHCP fingerprint result"""
    option55_order: str  # Comma-separated option order
    hostname: Optional[str] = None
    vendor_class: Optional[str] = None
    os: Optional[str] = None
    device_type: Optional[str] = None
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            'option55_order': self.option55_order,
            'hostname': self.hostname,
            'vendor_class': self.vendor_class,
            'os': self.os,
            'device_type': self.device_type,
            'confidence': self.confidence
        }


class DHCPFingerprinter:
    """
    Extracts DHCP Option 55 (Parameter Request List) for OS fingerprinting.

    Option 55 ordering is OS-specific:
    - Android: "1,3,6,15,31,33,43,44,46,47,121,249,252"
    - iOS: "1,121,3,6,15,28,51,58,59"
    - Embedded Linux (IoT): "1,3,6,12,15,28,42"
    """

    def __init__(self, signature_db_path: str):
        """
        Initialize DHCP fingerprinter.

        Args:
            signature_db_path: Path to DHCP signatures database JSON file
        """
        self.signature_db_path = signature_db_path
        self.signature_db = {}
        self._load_signature_database()

    def _load_signature_database(self):
        """Load DHCP signature database from JSON file"""
        try:
            import json
            from pathlib import Path

            db_file = Path(self.signature_db_path)
            if db_file.exists():
                with open(db_file, 'r') as f:
                    self.signature_db = json.load(f)
                logger.info(f"Loaded {len(self.signature_db)} DHCP signatures from database")
            else:
                logger.warning(f"DHCP signature database not found: {self.signature_db_path}")
                self.signature_db = {}
        except Exception as e:
            logger.error(f"Failed to load DHCP signature database: {e}")
            self.signature_db = {}

    def extract_dhcp_options(self, dhcp_packet) -> Dict:
        """
        Extract DHCP options from DHCP packet.

        Args:
            dhcp_packet: Scapy DHCP packet

        Returns:
            Dict of extracted options
        """
        try:
            from scapy.layers.dhcp import DHCP

            if not hasattr(dhcp_packet, 'options'):
                return {}

            options = {}

            for option in dhcp_packet.options:
                if not isinstance(option, tuple) or len(option) < 2:
                    continue

                opt_name = option[0]
                opt_value = option[1]

                # Option 55: Parameter Request List (CRITICAL for OS fingerprinting)
                if opt_name == 'param_req_list':
                    options['option55_order'] = ','.join(str(o) for o in opt_value)

                # Option 12: Hostname
                elif opt_name == 'hostname':
                    options['hostname'] = opt_value.decode() if isinstance(opt_value, bytes) else str(opt_value)

                # Option 60: Vendor Class Identifier
                elif opt_name == 'vendor_class_id':
                    options['vendor_class'] = opt_value.decode() if isinstance(opt_value, bytes) else str(opt_value)

                # Option 61: Client Identifier
                elif opt_name == 'client_id':
                    options['client_id'] = opt_value

            return options

        except Exception as e:
            logger.debug(f"Failed to extract DHCP options: {e}")
            return {}

    def lookup_signature(self, option55_order: str) -> Dict:
        """
        Lookup OS/device type from Option 55 ordering.

        Args:
            option55_order: Comma-separated option order string

        Returns:
            Signature info dict or empty dict if not found
        """
        return self.signature_db.get(option55_order, {})

    def fingerprint_dhcp_packet(self, dhcp_packet) -> Optional[DHCPFingerprint]:
        """
        Fingerprint DHCP packet and extract OS/device information.

        Args:
            dhcp_packet: Scapy DHCP packet

        Returns:
            DHCP fingerprint or None if no Option 55 found
        """
        try:
            options = self.extract_dhcp_options(dhcp_packet)

            option55_order = options.get('option55_order')
            if not option55_order:
                return None

            # Lookup signature
            signature_info = self.lookup_signature(option55_order)

            fingerprint = DHCPFingerprint(
                option55_order=option55_order,
                hostname=options.get('hostname'),
                vendor_class=options.get('vendor_class'),
                os=signature_info.get('os'),
                device_type=signature_info.get('device_type'),
                confidence=signature_info.get('confidence', 0.0)
            )

            logger.debug(f"DHCP fingerprint: Option55={option55_order}, OS={fingerprint.os}")
            return fingerprint

        except Exception as e:
            logger.error(f"Failed to fingerprint DHCP packet: {e}")
            return None
