"""
TCP/IP Stack Fingerprinting Module (p0f-style)

Passive OS detection via TCP/IP stack characteristics from SYN packets.
Stack characteristics are kernel-level and hard to spoof.

Weight: 0.20 (passive stack fingerprint)
"""

from typing import Dict, Optional
from dataclasses import dataclass
from loguru import logger


@dataclass
class TCPIPFingerprint:
    """TCP/IP stack fingerprint result"""
    ttl: int
    window_size: int
    mss: Optional[int] = None
    window_scale: Optional[int] = None
    options_order: str = ""
    signature: str = ""
    os: Optional[str] = None
    device_type: Optional[str] = None
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            'ttl': self.ttl,
            'window_size': self.window_size,
            'mss': self.mss,
            'window_scale': self.window_scale,
            'options_order': self.options_order,
            'signature': self.signature,
            'os': self.os,
            'device_type': self.device_type,
            'confidence': self.confidence
        }


class TCPIPFingerprinter:
    """
    Passive TCP/IP stack fingerprinting (p0f-style).

    Extracts stack characteristics from SYN packets:
    - TTL: Initial Time-To-Live (Windows: 128, Linux: 64, IoT: 255)
    - Window Size: Initial TCP window
    - MSS: Maximum Segment Size
    - TCP Options Order: Signature sequence (MSS, SACK, TS, NOP, WS)
    """

    # Common initial TTL values
    TTL_VALUES = {
        32: "Very old or embedded",
        64: "Linux/Unix/Mac",
        128: "Windows",
        255: "Embedded/IoT"
    }

    def __init__(self, signature_db_path: str):
        """
        Initialize TCP/IP fingerprinter.

        Args:
            signature_db_path: Path to TCP/IP signatures database JSON file
        """
        self.signature_db_path = signature_db_path
        self.signature_db = {}
        self._load_signature_database()

    def _load_signature_database(self):
        """Load TCP/IP signature database from JSON file"""
        try:
            import json
            from pathlib import Path

            db_file = Path(self.signature_db_path)
            if db_file.exists():
                with open(db_file, 'r') as f:
                    self.signature_db = json.load(f)
                logger.info(f"Loaded {len(self.signature_db)} TCP/IP signatures from database")
            else:
                logger.warning(f"TCP/IP signature database not found: {self.signature_db_path}")
                self.signature_db = {}
        except Exception as e:
            logger.error(f"Failed to load TCP/IP signature database: {e}")
            self.signature_db = {}

    def _extract_mss(self, tcp_layer) -> Optional[int]:
        """Extract MSS (Maximum Segment Size) from TCP options"""
        try:
            if hasattr(tcp_layer, 'options'):
                for opt in tcp_layer.options:
                    if isinstance(opt, tuple) and opt[0] == 'MSS':
                        return opt[1]
        except Exception as e:
            logger.debug(f"Failed to extract MSS: {e}")
        return None

    def _extract_window_scale(self, tcp_layer) -> Optional[int]:
        """Extract Window Scale from TCP options"""
        try:
            if hasattr(tcp_layer, 'options'):
                for opt in tcp_layer.options:
                    if isinstance(opt, tuple) and opt[0] == 'WScale':
                        return opt[1]
        except Exception as e:
            logger.debug(f"Failed to extract Window Scale: {e}")
        return None

    def _extract_options_order(self, tcp_layer) -> str:
        """Extract TCP options order for signature"""
        try:
            if hasattr(tcp_layer, 'options'):
                options = []
                for opt in tcp_layer.options:
                    if isinstance(opt, tuple):
                        options.append(opt[0])
                    elif isinstance(opt, str):
                        options.append(opt)
                return ','.join(str(o) for o in options)
        except Exception as e:
            logger.debug(f"Failed to extract options order: {e}")
        return ""

    def extract_syn_packet(self, ip_layer, tcp_layer) -> Optional[TCPIPFingerprint]:
        """
        Extract TCP/IP fingerprint from SYN packet.

        Args:
            ip_layer: Scapy IP layer
            tcp_layer: Scapy TCP layer

        Returns:
            TCP/IP fingerprint or None if not a SYN packet
        """
        try:
            # Verify this is a SYN packet (SYN flag set, ACK flag not set)
            if not hasattr(tcp_layer, 'flags'):
                return None

            flags = tcp_layer.flags
            if not (flags & 0x02):  # SYN flag
                return None
            if flags & 0x10:  # ACK flag (SYN-ACK, not SYN)
                return None

            # Extract stack characteristics
            ttl = ip_layer.ttl
            window_size = tcp_layer.window
            mss = self._extract_mss(tcp_layer)
            window_scale = self._extract_window_scale(tcp_layer)
            options_order = self._extract_options_order(tcp_layer)

            # Build signature string
            signature = f"ttl={ttl}:mss={mss}:wsize={window_size}:wscale={window_scale}:opts={options_order}"

            # Lookup in signature database
            signature_info = self.lookup_signature(signature)

            fingerprint = TCPIPFingerprint(
                ttl=ttl,
                window_size=window_size,
                mss=mss,
                window_scale=window_scale,
                options_order=options_order,
                signature=signature,
                os=signature_info.get('os'),
                device_type=signature_info.get('device_type'),
                confidence=signature_info.get('confidence', 0.0)
            )

            logger.debug(f"TCP/IP fingerprint: {signature}, OS={fingerprint.os}")
            return fingerprint

        except Exception as e:
            logger.error(f"Failed to extract SYN fingerprint: {e}")
            return None

    def lookup_signature(self, signature: str) -> Dict:
        """
        Lookup OS/device type from TCP/IP signature.

        Args:
            signature: TCP/IP signature string

        Returns:
            Signature info dict or empty dict if not found
        """
        # Exact match
        if signature in self.signature_db:
            return self.signature_db[signature]

        # Fuzzy match on TTL + window size (fallback)
        parts = signature.split(':')
        if len(parts) >= 3:
            ttl_part = parts[0]
            wsize_part = parts[2]
            fuzzy_key = f"{ttl_part}:{wsize_part}"

            for sig, info in self.signature_db.items():
                if sig.startswith(fuzzy_key):
                    # Lower confidence for fuzzy match
                    fuzzy_info = info.copy()
                    fuzzy_info['confidence'] = info.get('confidence', 0.0) * 0.7
                    return fuzzy_info

        return {}

    def process_syn_packet(self, ip_layer, tcp_layer) -> Optional[TCPIPFingerprint]:
        """
        Process SYN packet and extract fingerprint.

        Args:
            ip_layer: Scapy IP layer
            tcp_layer: Scapy TCP layer

        Returns:
            TCP/IP fingerprint or None if not a valid SYN packet
        """
        return self.extract_syn_packet(ip_layer, tcp_layer)
