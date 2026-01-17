#!/usr/bin/env python3
"""
RAKSHAK Passive Discovery Module
=================================

Discovers static IP devices (cameras, NVRs, DVRs) that don't use DHCP.

Discovery Methods:
- SSDP (UDP 1900): UPnP device announcements
- ONVIF (UDP 3702): IP camera/NVR discovery (WS-Discovery)
- RTSP Probing (TCP 554): Video stream detection
- ARP Listener: Passive ARP who-has/is-at monitoring

This module works best with bridge mode (br0) enabled, as it can see
all Layer-2 broadcast traffic including ARP announcements.

Author: Team RAKSHAK
"""

import socket
import struct
import threading
import time
import uuid
from typing import Dict, Optional, Callable, List, Set
from datetime import datetime
from dataclasses import dataclass, field

from loguru import logger

# Scapy for packet sniffing
try:
    from scapy.all import sniff, ARP, Ether, AsyncSniffer, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available - passive ARP discovery disabled")


@dataclass
class DiscoveredDevice:
    """Device discovered via passive methods."""
    ip: str
    mac: str = "unknown"
    hostname: str = ""
    device_type: str = "unknown"
    manufacturer: str = "unknown"
    discovery_method: str = "passive"
    services: List[Dict] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    raw_response: str = ""


class PassiveDiscovery:
    """
    Passive device discovery for static IP devices.

    Works best with bridge mode enabled (br0) as it can see
    all Layer-2 broadcast traffic including ARP.
    """

    # SSDP multicast address and port
    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900

    # ONVIF/WS-Discovery multicast
    ONVIF_ADDR = "239.255.255.250"
    ONVIF_PORT = 3702

    # RTSP default port
    RTSP_PORT = 554

    # Known camera/NVR manufacturers (for identification)
    MANUFACTURER_HINTS = {
        "hikvision": "Hikvision",
        "dahua": "Dahua",
        "axis": "Axis",
        "samsung": "Samsung",
        "hanwha": "Hanwha",
        "vivotek": "Vivotek",
        "bosch": "Bosch",
        "panasonic": "Panasonic",
        "sony": "Sony",
        "lorex": "Lorex",
        "swann": "Swann",
        "reolink": "Reolink",
        "amcrest": "Amcrest",
        "foscam": "Foscam",
        "uniview": "Uniview",
        "onvif": "ONVIF",
    }

    def __init__(self,
                 interface: str,
                 ssdp_enabled: bool = True,
                 onvif_enabled: bool = True,
                 rtsp_probe_enabled: bool = True,
                 arp_listener_enabled: bool = True,
                 on_device_discovered: Optional[Callable] = None):
        """
        Initialize passive discovery.

        Args:
            interface: Network interface to listen on (br0 recommended)
            ssdp_enabled: Listen for SSDP announcements
            onvif_enabled: Listen for ONVIF/WS-Discovery
            rtsp_probe_enabled: Probe for RTSP streams
            arp_listener_enabled: Listen for ARP traffic
            on_device_discovered: Callback when device found
        """
        self.interface = interface
        self.ssdp_enabled = ssdp_enabled
        self.onvif_enabled = onvif_enabled
        self.rtsp_probe_enabled = rtsp_probe_enabled
        self.arp_listener_enabled = arp_listener_enabled
        self.on_device_discovered = on_device_discovered

        self.is_running = False
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()
        self._threads: List[threading.Thread] = []
        self._arp_sniffer: Optional[AsyncSniffer] = None
        self._probed_ips: Set[str] = set()  # Track IPs we've already probed

        logger.info(f"PassiveDiscovery initialized on {interface}")

    def start(self):
        """Start all passive discovery listeners."""
        if self.is_running:
            return

        self.is_running = True

        # Start SSDP listener
        if self.ssdp_enabled:
            t = threading.Thread(target=self._ssdp_listener, daemon=True, name="SSDP-Listener")
            self._threads.append(t)
            t.start()

        # Start ONVIF listener
        if self.onvif_enabled:
            t = threading.Thread(target=self._onvif_listener, daemon=True, name="ONVIF-Listener")
            self._threads.append(t)
            t.start()

        # Start ARP listener
        if self.arp_listener_enabled and SCAPY_AVAILABLE:
            t = threading.Thread(target=self._arp_listener, daemon=True, name="ARP-Listener")
            self._threads.append(t)
            t.start()

        # Start RTSP prober (periodic)
        if self.rtsp_probe_enabled:
            t = threading.Thread(target=self._rtsp_prober, daemon=True, name="RTSP-Prober")
            self._threads.append(t)
            t.start()

        logger.info("Passive discovery started")

    def stop(self):
        """Stop all passive discovery listeners."""
        self.is_running = False

        # Stop ARP sniffer
        if self._arp_sniffer:
            try:
                self._arp_sniffer.stop()
            except Exception:
                pass

        # Wait for threads
        for t in self._threads:
            t.join(timeout=2)

        self._threads.clear()
        logger.info("Passive discovery stopped")

    def _ssdp_listener(self):
        """Listen for SSDP (UPnP) announcements on UDP 1900."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Try to bind to specific interface (may not work on all systems)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                               self.interface.encode())
            except (AttributeError, OSError):
                pass  # Not supported on this system

            sock.bind(("", self.SSDP_PORT))

            # Join multicast group
            mreq = struct.pack("4sl", socket.inet_aton(self.SSDP_ADDR), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            sock.settimeout(1.0)

            logger.info("SSDP listener started on UDP 1900")

            while self.is_running:
                try:
                    data, addr = sock.recvfrom(4096)
                    self._process_ssdp_response(data.decode('utf-8', errors='ignore'), addr[0])
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.debug(f"SSDP receive error: {e}")

            sock.close()

        except Exception as e:
            logger.error(f"SSDP listener error: {e}")

    def _process_ssdp_response(self, data: str, source_ip: str):
        """Process SSDP response and extract device info."""
        try:
            # Parse SSDP headers
            headers = {}
            for line in data.split("\r\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.upper().strip()] = value.strip()

            # Extract device info
            server = headers.get("SERVER", "")
            location = headers.get("LOCATION", "")
            usn = headers.get("USN", "")
            st = headers.get("ST", "")

            # Determine device type from server string
            device_type = "unknown"
            manufacturer = "unknown"

            server_lower = server.lower()
            location_lower = location.lower()

            # Check for camera/NVR indicators
            if any(hint in server_lower for hint in ["camera", "ipcam", "nvr", "dvr", "rtsp"]):
                device_type = "camera"
            elif any(hint in location_lower for hint in ["camera", "ipcam", "nvr", "dvr"]):
                device_type = "camera"
            elif "roku" in server_lower:
                device_type = "streaming"
                manufacturer = "Roku"
            elif "samsung" in server_lower:
                device_type = "samsung_tv"
                manufacturer = "Samsung"
            elif "dlna" in server_lower or "upnp" in st.lower():
                device_type = "media_server"

            # Identify manufacturer from server string
            for hint, mfr in self.MANUFACTURER_HINTS.items():
                if hint in server_lower or hint in location_lower:
                    manufacturer = mfr
                    if device_type == "unknown":
                        device_type = "camera"
                    break

            self._add_discovered_device(
                ip=source_ip,
                method="ssdp",
                device_type=device_type,
                manufacturer=manufacturer,
                services=[{"name": "ssdp", "port": 1900, "version": server}],
                raw_response=data[:500]
            )

        except Exception as e:
            logger.debug(f"SSDP parse error: {e}")

    def _onvif_listener(self):
        """Listen for ONVIF/WS-Discovery on UDP 3702."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Try to bind to specific interface
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                               self.interface.encode())
            except (AttributeError, OSError):
                pass

            sock.bind(("", self.ONVIF_PORT))

            # Join multicast group
            mreq = struct.pack("4sl", socket.inet_aton(self.ONVIF_ADDR), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            sock.settimeout(1.0)

            logger.info("ONVIF listener started on UDP 3702")

            while self.is_running:
                try:
                    data, addr = sock.recvfrom(8192)
                    self._process_onvif_response(data.decode('utf-8', errors='ignore'), addr[0])
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.debug(f"ONVIF receive error: {e}")

            sock.close()

        except Exception as e:
            logger.error(f"ONVIF listener error: {e}")

    def _process_onvif_response(self, data: str, source_ip: str):
        """Process ONVIF/WS-Discovery response."""
        try:
            # Look for ONVIF device indicators in XML
            device_type = "camera"  # ONVIF is typically cameras/NVRs
            manufacturer = "unknown"

            data_lower = data.lower()

            # Extract manufacturer from XML if possible
            for hint, mfr in self.MANUFACTURER_HINTS.items():
                if hint in data_lower:
                    manufacturer = mfr
                    break

            # Check for NVR vs camera
            if "networkvideotransmitter" in data_lower:
                device_type = "camera"
            elif "networkvideorecorder" in data_lower or "nvr" in data_lower:
                device_type = "nvr"

            self._add_discovered_device(
                ip=source_ip,
                method="onvif",
                device_type=device_type,
                manufacturer=manufacturer,
                services=[{"name": "onvif", "port": 3702, "version": "WS-Discovery"}],
                open_ports=[3702, 80, 554],  # Common ONVIF ports
                raw_response=data[:500]
            )

        except Exception as e:
            logger.debug(f"ONVIF parse error: {e}")

    def _arp_listener(self):
        """Listen for ARP traffic to discover devices passively."""
        if not SCAPY_AVAILABLE:
            return

        try:
            # Suppress Scapy output
            conf.verb = 0

            logger.info(f"ARP listener started on {self.interface}")

            def process_arp(pkt):
                if ARP in pkt:
                    arp = pkt[ARP]

                    # ARP reply (is-at) - device announcing itself
                    if arp.op == 2:  # is-at
                        self._add_discovered_device(
                            ip=arp.psrc,
                            mac=arp.hwsrc,
                            method="arp_reply"
                        )

                    # ARP request (who-has) - device looking for someone
                    elif arp.op == 1:  # who-has
                        # Source is making request, so it's active
                        if arp.psrc != "0.0.0.0":  # Ignore DHCP discover
                            self._add_discovered_device(
                                ip=arp.psrc,
                                mac=arp.hwsrc,
                                method="arp_request"
                            )

            # Use AsyncSniffer for non-blocking operation
            self._arp_sniffer = AsyncSniffer(
                iface=self.interface,
                filter="arp",
                prn=process_arp,
                store=False
            )
            self._arp_sniffer.start()

            # Wait for stop signal
            while self.is_running:
                time.sleep(1)

        except Exception as e:
            logger.error(f"ARP listener error: {e}")

    def _rtsp_prober(self):
        """Periodically probe for RTSP streams on discovered devices."""
        logger.info("RTSP prober started")

        # Send initial discovery probes
        self.send_ssdp_msearch()
        self.send_onvif_probe()

        probe_interval = 60  # Probe every 60 seconds

        while self.is_running:
            # Only probe devices discovered via other methods
            with self._lock:
                devices_to_probe = [
                    ip for ip, dev in self.discovered_devices.items()
                    if (dev.device_type in ["camera", "nvr", "unknown"] and
                        554 not in dev.open_ports and
                        ip not in self._probed_ips)
                ]

            for ip in devices_to_probe:
                if not self.is_running:
                    break

                if self._probe_rtsp(ip):
                    with self._lock:
                        if ip in self.discovered_devices:
                            self.discovered_devices[ip].device_type = "camera"
                            if 554 not in self.discovered_devices[ip].open_ports:
                                self.discovered_devices[ip].open_ports.append(554)
                            self.discovered_devices[ip].services.append({
                                "name": "rtsp", "port": 554, "version": "RTSP/1.0"
                            })
                            logger.info(f"RTSP service found on {ip}:554")

                self._probed_ips.add(ip)

            # Wait for next probe cycle
            for _ in range(probe_interval):
                if not self.is_running:
                    break
                time.sleep(1)

            # Send discovery probes periodically
            if self.is_running:
                self.send_ssdp_msearch()
                self.send_onvif_probe()

    def _probe_rtsp(self, ip: str, timeout: float = 2.0) -> bool:
        """Probe if an IP has RTSP service on port 554."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, self.RTSP_PORT))
            sock.close()

            if result == 0:
                return True
            return False

        except Exception:
            return False

    def _add_discovered_device(self, ip: str, method: str,
                               mac: str = "unknown",
                               device_type: str = "unknown",
                               manufacturer: str = "unknown",
                               services: List[Dict] = None,
                               open_ports: List[int] = None,
                               raw_response: str = ""):
        """Add or update a discovered device."""
        now = datetime.now().isoformat()

        with self._lock:
            if ip in self.discovered_devices:
                # Update existing
                dev = self.discovered_devices[ip]
                dev.last_seen = now
                if mac != "unknown" and dev.mac == "unknown":
                    dev.mac = mac
                if device_type != "unknown" and dev.device_type == "unknown":
                    dev.device_type = device_type
                if manufacturer != "unknown" and dev.manufacturer == "unknown":
                    dev.manufacturer = manufacturer
                if services:
                    for svc in services:
                        if svc not in dev.services:
                            dev.services.append(svc)
                if open_ports:
                    for port in open_ports:
                        if port not in dev.open_ports:
                            dev.open_ports.append(port)
                is_new = False
            else:
                # Create new
                dev = DiscoveredDevice(
                    ip=ip,
                    mac=mac,
                    device_type=device_type,
                    manufacturer=manufacturer,
                    discovery_method=method,
                    services=services or [],
                    open_ports=open_ports or [],
                    first_seen=now,
                    last_seen=now,
                    raw_response=raw_response
                )
                self.discovered_devices[ip] = dev
                is_new = True
                logger.info(f"Passive discovery: {ip} via {method} ({device_type}, {manufacturer})")

        # Notify callback for new devices
        if is_new and self.on_device_discovered:
            try:
                self.on_device_discovered({
                    "ip": ip,
                    "mac": mac,
                    "hostname": "",
                    "device_type": device_type,
                    "manufacturer": manufacturer,
                    "method": method,
                    "services": services or [],
                    "open_ports": open_ports or []
                })
            except Exception as e:
                logger.error(f"Discovery callback error: {e}")

    def get_discovered_devices(self) -> Dict[str, Dict]:
        """Get all discovered devices as dictionaries."""
        with self._lock:
            return {
                ip: {
                    "ip": dev.ip,
                    "mac": dev.mac,
                    "hostname": dev.hostname,
                    "device_type": dev.device_type,
                    "manufacturer": dev.manufacturer,
                    "method": dev.discovery_method,
                    "services": dev.services,
                    "open_ports": dev.open_ports,
                    "first_seen": dev.first_seen,
                    "last_seen": dev.last_seen
                }
                for ip, dev in self.discovered_devices.items()
            }

    def send_ssdp_msearch(self) -> None:
        """Send SSDP M-SEARCH to trigger device responses."""
        try:
            msg = (
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {self.SSDP_ADDR}:{self.SSDP_PORT}\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                "MX: 3\r\n"
                "ST: ssdp:all\r\n"
                "\r\n"
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

            # Try to bind to specific interface
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                               self.interface.encode())
            except (AttributeError, OSError):
                pass

            sock.sendto(msg.encode(), (self.SSDP_ADDR, self.SSDP_PORT))
            sock.close()

            logger.debug("Sent SSDP M-SEARCH")

        except Exception as e:
            logger.error(f"SSDP M-SEARCH error: {e}")

    def send_onvif_probe(self) -> None:
        """Send ONVIF WS-Discovery probe."""
        try:
            msg_id = str(uuid.uuid4())

            probe = f'''<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
    <e:Header>
        <w:MessageID>uuid:{msg_id}</w:MessageID>
        <w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
        <w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
    </e:Header>
    <e:Body>
        <d:Probe>
            <d:Types>dn:NetworkVideoTransmitter</d:Types>
        </d:Probe>
    </e:Body>
</e:Envelope>'''

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

            # Try to bind to specific interface
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                               self.interface.encode())
            except (AttributeError, OSError):
                pass

            sock.sendto(probe.encode(), (self.ONVIF_ADDR, self.ONVIF_PORT))
            sock.close()

            logger.debug("Sent ONVIF probe")

        except Exception as e:
            logger.error(f"ONVIF probe error: {e}")

    def get_device_count(self) -> int:
        """Get count of discovered devices."""
        with self._lock:
            return len(self.discovered_devices)

    def clear_devices(self):
        """Clear all discovered devices."""
        with self._lock:
            self.discovered_devices.clear()
            self._probed_ips.clear()


# Convenience function to create passive discovery from config
def create_passive_discovery_from_config(config_dict: Dict,
                                         interface: str,
                                         callback: Optional[Callable] = None) -> Optional[PassiveDiscovery]:
    """
    Create passive discovery from configuration dictionary.

    Args:
        config_dict: Full configuration dictionary
        interface: Network interface to use
        callback: Callback function for discovered devices

    Returns:
        PassiveDiscovery instance or None if disabled
    """
    network_config = config_dict.get("network", {})
    passive_config = network_config.get("passive_discovery", {})

    if not passive_config.get("enabled", True):
        logger.info("Passive discovery disabled in configuration")
        return None

    return PassiveDiscovery(
        interface=interface,
        ssdp_enabled=passive_config.get("ssdp_enabled", True),
        onvif_enabled=passive_config.get("onvif_enabled", True),
        rtsp_probe_enabled=passive_config.get("rtsp_probe_enabled", True),
        arp_listener_enabled=passive_config.get("arp_listener_enabled", True),
        on_device_discovered=callback
    )


if __name__ == "__main__":
    # Test passive discovery
    import sys

    interface = sys.argv[1] if len(sys.argv) > 1 else "br0"

    def on_device(info):
        print(f"Discovered: {info['ip']} - {info['device_type']} ({info['manufacturer']})")

    discovery = PassiveDiscovery(
        interface=interface,
        on_device_discovered=on_device
    )

    print(f"Starting passive discovery on {interface}...")
    discovery.start()

    try:
        while True:
            time.sleep(10)
            print(f"Discovered devices: {discovery.get_device_count()}")
            for ip, dev in discovery.get_discovered_devices().items():
                print(f"  {ip}: {dev['device_type']} ({dev['manufacturer']}) via {dev['method']}")
    except KeyboardInterrupt:
        print("\nStopping...")
        discovery.stop()
