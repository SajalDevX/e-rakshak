"""
TLS/JA3 Fingerprinting Module

Extracts JA3 fingerprints from TLS ClientHello packets for device identification.
JA3 is a cryptographic fingerprint that's very difficult to spoof.

Weight: 0.30 (highest - cryptographic signal)
"""

import hashlib
import struct
from typing import Dict, Optional, List
from dataclasses import dataclass
from loguru import logger


@dataclass
class TLSClientHello:
    """Parsed TLS ClientHello packet data"""
    version: int
    cipher_suites: List[int]
    extensions: List[int]
    supported_groups: List[int]  # Elliptic curves
    ec_point_formats: List[int]

    def to_dict(self) -> dict:
        return {
            'version': self.version,
            'cipher_suites': self.cipher_suites,
            'extensions': self.extensions,
            'supported_groups': self.supported_groups,
            'ec_point_formats': self.ec_point_formats
        }


@dataclass
class TLSFingerprint:
    """TLS fingerprint result"""
    ja3_hash: str
    ja3_string: str
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            'ja3_hash': self.ja3_hash,
            'ja3_string': self.ja3_string,
            'vendor': self.vendor,
            'device_type': self.device_type,
            'confidence': self.confidence
        }


class TLSFingerprinter:
    """
    Extracts JA3/JA4 fingerprints from TLS ClientHello packets.

    JA3 Hash Formula:
    MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)

    Example:
    TLS1.2,49195-49199-49200,0-10-11-13,23-24-25,0
    → 6734f37431670b3ab4292b8f60f29984 (Amazon Alexa signature)
    """

    # TLS Record Type
    TLS_HANDSHAKE = 0x16

    # TLS Handshake Type
    CLIENT_HELLO = 0x01

    # TLS Versions
    TLS_VERSIONS = {
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3"
    }

    # TLS Extension Types
    EXTENSION_SERVER_NAME = 0x0000
    EXTENSION_SUPPORTED_GROUPS = 0x000a
    EXTENSION_EC_POINT_FORMATS = 0x000b
    EXTENSION_SIGNATURE_ALGORITHMS = 0x000d
    EXTENSION_ALPN = 0x0010

    def __init__(self, vendor_db_path: str):
        """
        Initialize TLS fingerprinter.

        Args:
            vendor_db_path: Path to JA3 vendor database JSON file
        """
        self.vendor_db_path = vendor_db_path
        self.vendor_db = {}
        self._load_vendor_database()

    def _load_vendor_database(self):
        """Load JA3 vendor database from JSON file"""
        try:
            import json
            from pathlib import Path

            db_file = Path(self.vendor_db_path)
            if db_file.exists():
                with open(db_file, 'r') as f:
                    self.vendor_db = json.load(f)
                logger.info(f"Loaded {len(self.vendor_db)} JA3 signatures from database")
            else:
                logger.warning(f"JA3 vendor database not found: {self.vendor_db_path}")
                self.vendor_db = {}
        except Exception as e:
            logger.error(f"Failed to load JA3 vendor database: {e}")
            self.vendor_db = {}

    def extract_client_hello(self, payload: bytes) -> Optional[TLSClientHello]:
        """
        Extract TLS ClientHello from raw packet payload.

        Args:
            payload: Raw TLS packet payload

        Returns:
            Parsed ClientHello or None if not a valid ClientHello
        """
        try:
            # Check minimum length
            if len(payload) < 6:
                return None

            # Parse TLS record header
            record_type = payload[0]
            tls_version = struct.unpack('!H', payload[1:3])[0]
            record_length = struct.unpack('!H', payload[3:5])[0]

            # Verify this is a TLS Handshake
            if record_type != self.TLS_HANDSHAKE:
                return None

            # Parse handshake header
            if len(payload) < 9:
                return None

            handshake_type = payload[5]
            handshake_length = struct.unpack('!I', b'\x00' + payload[6:9])[0]

            # Verify this is a ClientHello
            if handshake_type != self.CLIENT_HELLO:
                return None

            # Parse ClientHello
            offset = 9

            # Client Version
            if offset + 2 > len(payload):
                return None
            client_version = struct.unpack('!H', payload[offset:offset+2])[0]
            offset += 2

            # Skip Random (32 bytes)
            offset += 32

            # Session ID length
            if offset >= len(payload):
                return None
            session_id_length = payload[offset]
            offset += 1 + session_id_length

            # Cipher Suites
            if offset + 2 > len(payload):
                return None
            cipher_suites_length = struct.unpack('!H', payload[offset:offset+2])[0]
            offset += 2

            cipher_suites = []
            for i in range(0, cipher_suites_length, 2):
                if offset + 2 > len(payload):
                    break
                cipher = struct.unpack('!H', payload[offset:offset+2])[0]
                cipher_suites.append(cipher)
                offset += 2

            # Compression Methods
            if offset >= len(payload):
                return None
            compression_length = payload[offset]
            offset += 1 + compression_length

            # Extensions
            extensions = []
            supported_groups = []
            ec_point_formats = []

            if offset + 2 <= len(payload):
                extensions_length = struct.unpack('!H', payload[offset:offset+2])[0]
                offset += 2

                extensions_end = offset + extensions_length
                while offset + 4 <= extensions_end and offset + 4 <= len(payload):
                    ext_type = struct.unpack('!H', payload[offset:offset+2])[0]
                    ext_length = struct.unpack('!H', payload[offset+2:offset+4])[0]
                    offset += 4

                    extensions.append(ext_type)

                    # Parse supported groups (elliptic curves)
                    if ext_type == self.EXTENSION_SUPPORTED_GROUPS and offset + ext_length <= len(payload):
                        groups_length = struct.unpack('!H', payload[offset:offset+2])[0]
                        for i in range(2, min(groups_length + 2, ext_length), 2):
                            if offset + i + 2 <= len(payload):
                                group = struct.unpack('!H', payload[offset+i:offset+i+2])[0]
                                supported_groups.append(group)

                    # Parse EC point formats
                    elif ext_type == self.EXTENSION_EC_POINT_FORMATS and offset + ext_length <= len(payload):
                        formats_length = payload[offset]
                        for i in range(1, min(formats_length + 1, ext_length)):
                            if offset + i < len(payload):
                                ec_point_formats.append(payload[offset + i])

                    offset += ext_length

            return TLSClientHello(
                version=client_version,
                cipher_suites=cipher_suites,
                extensions=extensions,
                supported_groups=supported_groups,
                ec_point_formats=ec_point_formats
            )

        except Exception as e:
            logger.debug(f"Failed to parse TLS ClientHello: {e}")
            return None

    def compute_ja3_hash(self, client_hello: TLSClientHello) -> TLSFingerprint:
        """
        Compute JA3 hash from ClientHello.

        Args:
            client_hello: Parsed ClientHello data

        Returns:
            TLS fingerprint with JA3 hash
        """
        try:
            # Build JA3 string components
            version = str(client_hello.version)

            ciphers = '-'.join(str(c) for c in client_hello.cipher_suites)

            extensions = '-'.join(str(e) for e in client_hello.extensions)

            curves = '-'.join(str(g) for g in client_hello.supported_groups)

            formats = '-'.join(str(f) for f in client_hello.ec_point_formats)

            # Construct JA3 string
            ja3_string = f"{version},{ciphers},{extensions},{curves},{formats}"

            # Compute MD5 hash
            ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

            # Lookup in vendor database
            vendor_info = self.lookup_vendor(ja3_hash)

            return TLSFingerprint(
                ja3_hash=ja3_hash,
                ja3_string=ja3_string,
                vendor=vendor_info.get('vendor'),
                device_type=vendor_info.get('device_type'),
                confidence=vendor_info.get('confidence', 0.0)
            )

        except Exception as e:
            logger.error(f"Failed to compute JA3 hash: {e}")
            return TLSFingerprint(ja3_hash="", ja3_string="", confidence=0.0)

    def lookup_vendor(self, ja3_hash: str) -> Dict:
        """
        Lookup vendor information from JA3 hash.

        Args:
            ja3_hash: JA3 hash string

        Returns:
            Vendor information dict or empty dict if not found
        """
        return self.vendor_db.get(ja3_hash, {})

    def process_tls_packet(self, payload: bytes) -> Optional[TLSFingerprint]:
        """
        Process TLS packet and extract fingerprint.

        Args:
            payload: Raw TLS packet payload

        Returns:
            TLS fingerprint or None if not a valid ClientHello
        """
        client_hello = self.extract_client_hello(payload)

        if client_hello:
            fingerprint = self.compute_ja3_hash(client_hello)
            logger.debug(f"TLS fingerprint: JA3={fingerprint.ja3_hash}, vendor={fingerprint.vendor}")
            return fingerprint

        return None
