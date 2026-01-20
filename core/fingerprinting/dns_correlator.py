"""
DNS Cloud Endpoint Correlation Module

Maps DNS queries to known IoT vendor cloud endpoints for device identification.

Weight: 0.15 (cloud endpoint mapping)
"""

import fnmatch
from typing import Dict, Optional, List, Set
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime
from loguru import logger


@dataclass
class DNSFingerprint:
    """DNS correlation result"""
    domains_queried: List[str]
    vendor: Optional[str] = None
    device_types: List[str] = field(default_factory=list)
    confidence: float = 0.0
    matched_pattern: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            'domains_queried': self.domains_queried,
            'vendor': self.vendor,
            'device_types': self.device_types,
            'confidence': self.confidence,
            'matched_pattern': self.matched_pattern
        }


class DNSCorrelator:
    """
    Maps DNS queries to known IoT vendor cloud endpoints.

    Monitors DNS queries from devices and correlates them to known
    vendor cloud endpoints (Tuya, Hikvision, Ring, Xiaomi, etc.)
    """

    def __init__(self, cloud_endpoints_db_path: str):
        """
        Initialize DNS correlator.

        Args:
            cloud_endpoints_db_path: Path to cloud endpoints database JSON file
        """
        self.cloud_endpoints_db_path = cloud_endpoints_db_path
        self.cloud_endpoints_db = {}
        self._load_cloud_endpoints_database()

        # Track DNS queries per device
        self.device_queries = defaultdict(set)  # {device_ip: set(domains)}

    def _load_cloud_endpoints_database(self):
        """Load cloud endpoints database from JSON file"""
        try:
            import json
            from pathlib import Path

            db_file = Path(self.cloud_endpoints_db_path)
            if db_file.exists():
                with open(db_file, 'r') as f:
                    self.cloud_endpoints_db = json.load(f)
                logger.info(f"Loaded {len(self.cloud_endpoints_db)} cloud endpoint patterns from database")
            else:
                logger.warning(f"Cloud endpoints database not found: {self.cloud_endpoints_db_path}")
                self.cloud_endpoints_db = {}
        except Exception as e:
            logger.error(f"Failed to load cloud endpoints database: {e}")
            self.cloud_endpoints_db = {}

    def record_dns_query(self, device_ip: str, domain: str):
        """
        Record DNS query from device.

        Args:
            device_ip: Source IP address
            domain: Queried domain name
        """
        self.device_queries[device_ip].add(domain)
        logger.debug(f"DNS query recorded: {device_ip} → {domain}")

    def correlate_vendor(self, domains: List[str]) -> Optional[Dict]:
        """
        Correlate domain list to vendor.

        Args:
            domains: List of domains queried by device

        Returns:
            Vendor info dict or None if no match
        """
        for vendor_key, vendor_info in self.cloud_endpoints_db.items():
            domain_patterns = vendor_info.get('domains', [])

            for domain in domains:
                for pattern in domain_patterns:
                    if fnmatch.fnmatch(domain, pattern):
                        return {
                            'vendor': vendor_info.get('vendor'),
                            'device_types': vendor_info.get('device_types', []),
                            'confidence': vendor_info.get('confidence', 0.0),
                            'matched_pattern': pattern
                        }

        return None

    def get_device_fingerprint(self, device_ip: str) -> Optional[DNSFingerprint]:
        """
        Get DNS fingerprint for device based on recorded queries.

        Args:
            device_ip: Device IP address

        Returns:
            DNS fingerprint or None if no queries recorded
        """
        domains = list(self.device_queries.get(device_ip, set()))

        if not domains:
            return None

        # Correlate to vendor
        vendor_info = self.correlate_vendor(domains)

        if vendor_info:
            fingerprint = DNSFingerprint(
                domains_queried=domains,
                vendor=vendor_info.get('vendor'),
                device_types=vendor_info.get('device_types', []),
                confidence=vendor_info.get('confidence', 0.0),
                matched_pattern=vendor_info.get('matched_pattern')
            )

            logger.debug(f"DNS fingerprint: {device_ip} → {fingerprint.vendor}")
            return fingerprint

        # No vendor match
        return DNSFingerprint(
            domains_queried=domains,
            confidence=0.0
        )

    def clear_device_queries(self, device_ip: str):
        """Clear recorded queries for device"""
        if device_ip in self.device_queries:
            del self.device_queries[device_ip]
