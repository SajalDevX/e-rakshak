#!/usr/bin/env python3
"""
RAKSHAK Deception Engine - CHAKRAVYUH
=====================================

Circular Defense Trap Network

Inspired by the legendary military formation from Mahabharata,
CHAKRAVYUH creates concentric rings of defense that trap attackers
progressively deeper.

Layers:
1. Detection Ring - Monitor network, identify threats
2. Decoy Ring - Fake devices to attract attackers
3. Trap Ring - High-interaction honeypots
4. Intelligence Ring - Capture TTPs, export data

Features:
- Dynamic honeypot deployment
- Multi-protocol emulation (Telnet, SSH, HTTP)
- Device morphing from real network devices
- Threat intelligence capture

Author: Team RAKSHAK
"""

import os
import socket
import asyncio
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field

from loguru import logger

# Optional async SSH support
try:
    import asyncssh
    ASYNCSSH_AVAILABLE = True
except ImportError:
    ASYNCSSH_AVAILABLE = False


@dataclass
class Honeypot:
    """Represents an active honeypot instance."""
    id: str
    port: int
    protocol: str
    persona: str
    device_type: str
    status: str = "active"
    connections: int = 0
    started_at: str = ""
    last_activity: str = ""
    captured_commands: List[str] = field(default_factory=list)
    captured_credentials: List[Dict] = field(default_factory=list)
    thread: Optional[threading.Thread] = None


@dataclass
class AttackSession:
    """Tracks an attacker session."""
    id: str
    source_ip: str
    source_port: int
    honeypot_id: str
    started_at: str
    last_activity: str
    commands: List[str] = field(default_factory=list)
    credentials_tried: List[Dict] = field(default_factory=list)
    payloads: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0


class DeceptionEngine:
    """
    CHAKRAVYUH - Multi-Layer Deception System

    Coordinates honeypot deployment and attacker engagement.
    """

    def __init__(self, config: dict, llm_honeypot=None, threat_logger=None, gateway=None):
        """
        Initialize the deception engine.

        Args:
            config: Configuration dictionary
            llm_honeypot: LLMHoneypot instance for intelligent responses
            threat_logger: ThreatLogger instance for logging
            gateway: RakshakGateway instance (for traffic redirection in gateway mode)
        """
        self.config = config
        self.llm_honeypot = llm_honeypot
        self.threat_logger = threat_logger
        self.gateway = gateway  # Gateway reference for traffic redirection
        self.deception_config = config.get("deception", {})

        # Honeypot settings
        self.enabled = self.deception_config.get("enabled", True)
        self.max_honeypots = self.deception_config.get("max_honeypots", 10)
        self.default_ports = self.deception_config.get("honeypot_ports", {
            "telnet": 2323,
            "ssh": 2222,
            "http": 8080,
            "mqtt": 1883,
            "rtsp": 5540
        })

        # Active honeypots
        self.honeypots: Dict[str, Honeypot] = {}
        self._honeypots_lock = threading.Lock()

        # Attack sessions
        self.sessions: Dict[str, AttackSession] = {}
        self._sessions_lock = threading.Lock()

        # Honeypot ID counter
        self._honeypot_counter = 0

        # Server threads
        self._server_threads: List[threading.Thread] = []
        self._running = False

        logger.info(f"DeceptionEngine initialized (enabled={self.enabled})")

    def _generate_honeypot_id(self) -> str:
        """Generate unique honeypot ID."""
        self._honeypot_counter += 1
        return f"HP-{self._honeypot_counter:04d}"

    def deploy_honeypot(self, threat_info: dict = None,
                       protocol: str = "telnet",
                       persona: str = "tp_link") -> Optional[Honeypot]:
        """
        Deploy a new honeypot in response to a threat.

        Args:
            threat_info: Information about the detected threat
            protocol: Protocol to emulate (telnet, ssh, http)
            persona: Device persona to use

        Returns:
            Honeypot object or None if deployment failed
        """
        if not self.enabled:
            logger.warning("Deception engine disabled")
            return None

        if len(self.honeypots) >= self.max_honeypots:
            logger.warning(f"Maximum honeypots ({self.max_honeypots}) reached")
            return None

        # Determine port
        port = self.default_ports.get(protocol, 2323)

        # Find available port
        port = self._find_available_port(port)
        if port is None:
            logger.error("No available ports for honeypot")
            return None

        # Create honeypot
        honeypot = Honeypot(
            id=self._generate_honeypot_id(),
            port=port,
            protocol=protocol,
            persona=persona,
            device_type=threat_info.get("target_device", "unknown") if threat_info else "unknown",
            status="starting",
            started_at=datetime.now().isoformat()
        )

        # Start honeypot server
        if protocol == "telnet":
            thread = threading.Thread(
                target=self._run_telnet_honeypot,
                args=(honeypot,),
                daemon=True
            )
        elif protocol == "http":
            thread = threading.Thread(
                target=self._run_http_honeypot,
                args=(honeypot,),
                daemon=True
            )
        else:
            # Default to telnet
            thread = threading.Thread(
                target=self._run_telnet_honeypot,
                args=(honeypot,),
                daemon=True
            )

        honeypot.thread = thread
        thread.start()

        # Store honeypot
        with self._honeypots_lock:
            self.honeypots[honeypot.id] = honeypot

        logger.info(f"Deployed honeypot {honeypot.id} ({protocol}:{port})")

        # Log the deployment
        if self.threat_logger:
            self.threat_logger.log_action(
                threat_id=threat_info.get("id", "unknown") if threat_info else "manual",
                action="deploy_honeypot",
                target=f"{protocol}:{port}",
                status="success",
                details={
                    "honeypot_id": honeypot.id,
                    "persona": persona
                }
            )

        return honeypot

    def deploy_honeypot_with_redirect(self, threat_info: dict,
                                       protocol: str = "telnet",
                                       persona: str = "tp_link") -> Optional[Honeypot]:
        """
        Deploy honeypot AND setup traffic redirection (gateway mode).

        When in gateway mode, this method:
        1. Deploys the honeypot service
        2. Sets up NAT rule to redirect attacker traffic to honeypot

        This enables true "attacker engagement" - the attacker thinks they're
        connecting to the real device, but traffic is silently redirected to
        our honeypot via iptables NAT rules.

        Args:
            threat_info: Threat information dict containing:
                - source_ip: IP address of the attacker
                - target_port: Port the attacker is targeting (default: 23)
                - target_device: Device type being targeted
            protocol: Honeypot protocol (telnet, ssh, http)
            persona: Device persona to emulate

        Returns:
            Honeypot instance if successful, None otherwise
        """
        # Deploy honeypot first
        honeypot = self.deploy_honeypot(
            threat_info=threat_info,
            protocol=protocol,
            persona=persona
        )

        if not honeypot:
            logger.error("Failed to deploy honeypot for redirection")
            return None

        # Setup traffic redirection if gateway is available and in gateway mode
        if self.gateway and hasattr(self.gateway, 'is_gateway_mode') and self.gateway.is_gateway_mode:
            source_ip = threat_info.get("source_ip")
            target_port = threat_info.get("target_port")

            # Determine target port based on protocol if not specified
            if target_port is None:
                port_mapping = {
                    "telnet": 23,
                    "ssh": 22,
                    "http": 80,
                    "https": 443,
                    "mqtt": 1883,
                    "rtsp": 554
                }
                target_port = port_mapping.get(protocol, 23)

            if source_ip:
                # Get gateway IP for local honeypot
                gateway_ip = self.config.get("gateway", {}).get("lan_ip", "192.168.100.1")

                success = self.gateway.redirect_to_honeypot(
                    source_ip=source_ip,
                    original_port=target_port,
                    honeypot_port=honeypot.port,
                    protocol="tcp",
                    honeypot_ip=None  # Local redirect
                )

                if success:
                    # Mark honeypot as having active redirection
                    honeypot.has_redirection = True
                    honeypot.redirect_source = source_ip
                    honeypot.redirect_original_port = target_port

                    logger.warning(
                        f"CHAKRAVYUH: Honeypot {honeypot.id} deployed with NAT redirection: "
                        f"{source_ip}:{target_port} → honeypot:{honeypot.port}"
                    )

                    # Log the engagement
                    if self.threat_logger:
                        self.threat_logger.log_action(
                            threat_id=threat_info.get("id", "unknown"),
                            action="honeypot_redirect",
                            target=f"{source_ip}:{target_port}→:{honeypot.port}",
                            status="success",
                            details={
                                "honeypot_id": honeypot.id,
                                "source_ip": source_ip,
                                "original_port": target_port,
                                "honeypot_port": honeypot.port,
                                "protocol": protocol,
                                "real_redirection": True
                            }
                        )
                else:
                    logger.warning(
                        f"Honeypot {honeypot.id} deployed but NAT redirection failed for {source_ip}"
                    )
                    honeypot.has_redirection = False
            else:
                logger.debug("No source_ip in threat_info, skipping NAT redirection")
                honeypot.has_redirection = False
        else:
            # Standalone mode - no real redirection
            logger.debug(
                f"Honeypot {honeypot.id} deployed (standalone mode - no NAT redirection)"
            )
            honeypot.has_redirection = False

        return honeypot

    def remove_honeypot_redirection(self, honeypot: Honeypot) -> bool:
        """
        Remove NAT redirection rules for a honeypot.

        Called when stopping a honeypot that has active redirection.

        Args:
            honeypot: Honeypot instance to remove redirection for

        Returns:
            True if removal successful or no redirection existed
        """
        if not hasattr(honeypot, 'has_redirection') or not honeypot.has_redirection:
            return True

        if not self.gateway or not hasattr(self.gateway, 'is_gateway_mode'):
            return True

        try:
            source_ip = getattr(honeypot, 'redirect_source', None)
            original_port = getattr(honeypot, 'redirect_original_port', None)

            if source_ip and original_port:
                success = self.gateway.remove_honeypot_redirection(source_ip, original_port)
                if success:
                    honeypot.has_redirection = False
                    logger.info(
                        f"Removed NAT redirection for honeypot {honeypot.id}"
                    )
                return success
            return True

        except Exception as e:
            logger.error(f"Failed to remove honeypot redirection: {e}")
            return False

    def _find_available_port(self, preferred_port: int) -> Optional[int]:
        """Find an available port starting from preferred."""
        for port in range(preferred_port, preferred_port + 100):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("0.0.0.0", port))
                sock.close()
                return port
            except OSError:
                continue
        return None

    def _run_telnet_honeypot(self, honeypot: Honeypot):
        """Run a telnet honeypot server."""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(("0.0.0.0", honeypot.port))
            server_socket.listen(5)
            server_socket.settimeout(1.0)  # Allow checking for shutdown

            honeypot.status = "active"
            logger.info(f"Telnet honeypot {honeypot.id} listening on port {honeypot.port}")

            while honeypot.status == "active":
                try:
                    client_socket, address = server_socket.accept()
                    honeypot.connections += 1
                    honeypot.last_activity = datetime.now().isoformat()

                    # Handle client in thread
                    client_thread = threading.Thread(
                        target=self._handle_telnet_client,
                        args=(honeypot, client_socket, address),
                        daemon=True
                    )
                    client_thread.start()

                except socket.timeout:
                    continue
                except Exception as e:
                    if honeypot.status == "active":
                        logger.error(f"Telnet honeypot error: {e}")

        except Exception as e:
            logger.error(f"Failed to start telnet honeypot: {e}")
            honeypot.status = "failed"
        finally:
            try:
                server_socket.close()
            except:
                pass

    def _handle_telnet_client(self, honeypot: Honeypot, client_socket: socket.socket,
                             address: tuple):
        """Handle a telnet client connection."""
        source_ip, source_port = address
        session_id = f"SES-{source_ip.replace('.', '')}-{source_port}"

        logger.info(f"New telnet connection from {source_ip}:{source_port}")

        # Create session
        session = AttackSession(
            id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            honeypot_id=honeypot.id,
            started_at=datetime.now().isoformat(),
            last_activity=datetime.now().isoformat()
        )

        with self._sessions_lock:
            self.sessions[session_id] = session

        # Log threat
        if self.threat_logger:
            self.threat_logger.log_threat(
                threat_type="honeypot_connection",
                severity="high",
                source_ip=source_ip,
                target_ip="0.0.0.0",
                target_device=f"Honeypot {honeypot.id}",
                source_port=source_port,
                target_port=honeypot.port,
                protocol="telnet",
                detected_by="deception_engine"
            )

        try:
            # Set timeout
            client_socket.settimeout(300)  # 5 minute timeout

            # Get persona from LLM honeypot
            if self.llm_honeypot:
                self.llm_honeypot.set_persona(honeypot.persona)

            # Send banner and login prompt
            banner = self._get_banner(honeypot)
            client_socket.send(banner.encode())

            # Authentication phase
            authenticated = self._handle_authentication(
                client_socket, honeypot, session
            )

            if authenticated:
                # Interactive shell phase
                self._handle_interactive_shell(
                    client_socket, honeypot, session
                )

        except socket.timeout:
            logger.debug(f"Client {source_ip} timed out")
        except ConnectionResetError:
            logger.debug(f"Client {source_ip} disconnected")
        except Exception as e:
            logger.error(f"Error handling telnet client: {e}")
        finally:
            # Update session
            session.last_activity = datetime.now().isoformat()
            start_time = datetime.fromisoformat(session.started_at)
            session.duration_seconds = (datetime.now() - start_time).total_seconds()

            # Store captured data
            honeypot.captured_commands.extend(session.commands)
            honeypot.captured_credentials.extend(session.credentials_tried)

            try:
                client_socket.close()
            except:
                pass

            logger.info(
                f"Session {session_id} ended: {len(session.commands)} commands, "
                f"{session.duration_seconds:.1f}s duration"
            )

    def _get_banner(self, honeypot: Honeypot) -> str:
        """Get login banner for honeypot."""
        if self.llm_honeypot:
            return self.llm_honeypot.get_banner(honeypot.persona)

        # Default banners
        banners = {
            "tp_link": "\r\nTP-LINK Wireless Router WR940N\r\n\r\nLogin: ",
            "wyze_cam": "\r\nWyze Cam v2 - Console\r\n\r\nlogin: ",
            "samsung_tv": "\r\nSamsung Smart TV\r\n\r\nUsername: ",
            "default": "\r\nIoT Device Console\r\n\r\nlogin: "
        }
        return banners.get(honeypot.persona, banners["default"])

    def _handle_authentication(self, client_socket: socket.socket,
                              honeypot: Honeypot, session: AttackSession) -> bool:
        """Handle authentication phase."""
        max_attempts = 3

        for attempt in range(max_attempts):
            try:
                # Get username
                username = self._recv_line(client_socket).strip()
                if not username:
                    continue

                # Send password prompt
                client_socket.send(b"Password: ")

                # Get password (don't echo)
                password = self._recv_line(client_socket).strip()

                # Log credentials
                cred = {"username": username, "password": password}
                session.credentials_tried.append(cred)

                logger.info(f"Login attempt: {username}:{password}")

                # Check credentials
                if self.llm_honeypot:
                    if self.llm_honeypot.check_credentials(username, password, honeypot.persona):
                        client_socket.send(b"\r\nLogin successful.\r\n")
                        return True
                else:
                    # Accept common weak credentials
                    if username in ["root", "admin"] and password in ["admin", "root", "password", "12345"]:
                        client_socket.send(b"\r\nLogin successful.\r\n")
                        return True

                client_socket.send(b"\r\nLogin incorrect.\r\n\r\nLogin: ")

            except Exception as e:
                logger.debug(f"Auth error: {e}")
                break

        return False

    def _handle_interactive_shell(self, client_socket: socket.socket,
                                 honeypot: Honeypot, session: AttackSession):
        """Handle interactive shell session."""
        # Send shell prompt
        prompt = f"\r\n{honeypot.persona}# "
        client_socket.send(prompt.encode())

        while True:
            try:
                # Receive command
                command = self._recv_line(client_socket).strip()

                if not command:
                    client_socket.send(prompt.encode())
                    continue

                # Log command
                session.commands.append(command)
                session.last_activity = datetime.now().isoformat()

                logger.info(f"Honeypot command: {command}")

                # Check for exit
                if command.lower() in ["exit", "quit", "logout"]:
                    client_socket.send(b"\r\nBye.\r\n")
                    break

                # Generate response
                if self.llm_honeypot:
                    response = self.llm_honeypot.generate_response(
                        command,
                        persona_name=honeypot.persona,
                        session_id=session.id
                    )
                else:
                    response = self._default_command_response(command)

                # Send response
                client_socket.send(response.encode())
                client_socket.send(prompt.encode())

            except socket.timeout:
                break
            except Exception as e:
                logger.debug(f"Shell error: {e}")
                break

    def _recv_line(self, sock: socket.socket, max_length: int = 1024) -> str:
        """Receive a line from socket."""
        data = b""
        while True:
            try:
                char = sock.recv(1)
                if not char:
                    break
                if char in [b"\n", b"\r"]:
                    break
                if char not in [b"\x00", b"\xff", b"\xfb", b"\xfc", b"\xfd", b"\xfe"]:
                    data += char
                if len(data) >= max_length:
                    break
            except:
                break
        return data.decode("utf-8", errors="ignore")

    def _default_command_response(self, command: str) -> str:
        """Generate default command response."""
        cmd = command.split()[0] if command.split() else command

        responses = {
            "ls": "bin  etc  home  proc  root  tmp  var\r\n",
            "pwd": "/root\r\n",
            "whoami": "root\r\n",
            "id": "uid=0(root) gid=0(root)\r\n",
            "uname": "Linux\r\n",
            "cat": "cat: No such file or directory\r\n",
            "cd": "",
            "help": "Available: ls, cd, cat, pwd, whoami, id, exit\r\n"
        }

        return responses.get(cmd, f"-sh: {cmd}: not found\r\n")

    def _run_http_honeypot(self, honeypot: Honeypot):
        """Run an HTTP honeypot server."""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(("0.0.0.0", honeypot.port))
            server_socket.listen(5)
            server_socket.settimeout(1.0)

            honeypot.status = "active"
            logger.info(f"HTTP honeypot {honeypot.id} listening on port {honeypot.port}")

            while honeypot.status == "active":
                try:
                    client_socket, address = server_socket.accept()
                    honeypot.connections += 1
                    honeypot.last_activity = datetime.now().isoformat()

                    # Handle in thread
                    client_thread = threading.Thread(
                        target=self._handle_http_client,
                        args=(honeypot, client_socket, address),
                        daemon=True
                    )
                    client_thread.start()

                except socket.timeout:
                    continue
                except Exception as e:
                    if honeypot.status == "active":
                        logger.error(f"HTTP honeypot error: {e}")

        except Exception as e:
            logger.error(f"Failed to start HTTP honeypot: {e}")
            honeypot.status = "failed"
        finally:
            try:
                server_socket.close()
            except:
                pass

    def _handle_http_client(self, honeypot: Honeypot, client_socket: socket.socket,
                           address: tuple):
        """Handle HTTP client connection."""
        source_ip, source_port = address
        logger.info(f"HTTP connection from {source_ip}:{source_port}")

        try:
            # Receive request
            request = client_socket.recv(4096).decode("utf-8", errors="ignore")

            # Log the request
            if self.threat_logger:
                self.threat_logger.log_threat(
                    threat_type="http_probe",
                    severity="medium",
                    source_ip=source_ip,
                    target_ip="0.0.0.0",
                    target_device=f"HTTP Honeypot {honeypot.id}",
                    source_port=source_port,
                    target_port=honeypot.port,
                    protocol="http",
                    payload=request[:200],
                    detected_by="deception_engine"
                )

            # Generate fake response
            response = self._generate_http_response(request, honeypot)
            client_socket.send(response.encode())

        except Exception as e:
            logger.debug(f"HTTP handler error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass

    def _generate_http_response(self, request: str, honeypot: Honeypot) -> str:
        """Generate fake HTTP response."""
        # Fake admin login page
        html = f"""<!DOCTYPE html>
<html>
<head><title>{honeypot.persona} - Admin</title></head>
<body>
<h1>{honeypot.persona} Administration</h1>
<form method="post" action="/login">
    <label>Username: <input type="text" name="username"></label><br>
    <label>Password: <input type="password" name="password"></label><br>
    <input type="submit" value="Login">
</form>
<p>Firmware: {honeypot.device_type}</p>
</body>
</html>"""

        response = (
            "HTTP/1.1 200 OK\r\n"
            f"Server: {honeypot.persona}\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(html)}\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{html}"
        )

        return response

    def engage_attacker(self, threat_info: dict) -> bool:
        """
        Actively engage an attacker by deploying targeted honeypots.

        This is called by KAAL when it decides to engage rather than block.

        In gateway mode:
        - Deploys honeypot with NAT redirection
        - Attacker traffic is transparently redirected to honeypot

        In standalone mode:
        - Deploys honeypot only (attacker must connect directly)

        Args:
            threat_info: Dict containing source_ip, target_device, etc.

        Returns:
            True if engagement successful
        """
        source_ip = threat_info.get("source_ip", "unknown")
        target_device = threat_info.get("target_device", "tp_link")

        logger.info(f"CHAKRAVYUH: Engaging attacker from {source_ip}")

        # Use redirect-enabled deployment in gateway mode
        if self.gateway and hasattr(self.gateway, 'is_gateway_mode') and self.gateway.is_gateway_mode:
            honeypot = self.deploy_honeypot_with_redirect(
                threat_info=threat_info,
                protocol="telnet",
                persona=target_device
            )
            if honeypot:
                logger.warning(
                    f"CHAKRAVYUH: Attacker {source_ip} engaged with honeypot {honeypot.id} "
                    f"(NAT redirect: {getattr(honeypot, 'has_redirection', False)})"
                )
        else:
            # Standalone mode - no redirection
            honeypot = self.deploy_honeypot(
                threat_info=threat_info,
                protocol="telnet",
                persona=target_device
            )

        return honeypot is not None

    def stop_honeypot(self, honeypot_id: str) -> bool:
        """
        Stop a specific honeypot.

        Also removes any NAT redirection rules associated with the honeypot.

        Args:
            honeypot_id: ID of honeypot to stop

        Returns:
            True if honeypot stopped successfully
        """
        with self._honeypots_lock:
            if honeypot_id in self.honeypots:
                honeypot = self.honeypots[honeypot_id]

                # Remove NAT redirection if active
                self.remove_honeypot_redirection(honeypot)

                honeypot.status = "stopped"
                logger.info(f"Stopped honeypot {honeypot_id}")
                return True
        return False

    def stop_all_honeypots(self):
        """
        Stop all active honeypots.

        Also removes all NAT redirection rules.
        """
        with self._honeypots_lock:
            for honeypot in self.honeypots.values():
                # Remove NAT redirection if active
                self.remove_honeypot_redirection(honeypot)
                honeypot.status = "stopped"
        logger.info("Stopped all honeypots and removed NAT redirections")

    def get_active_count(self) -> int:
        """Get count of active honeypots."""
        with self._honeypots_lock:
            return len([h for h in self.honeypots.values() if h.status == "active"])

    def get_honeypot(self, honeypot_id: str) -> Optional[Honeypot]:
        """Get honeypot by ID."""
        return self.honeypots.get(honeypot_id)

    def get_all_honeypots(self) -> List[dict]:
        """Get all honeypots as dicts."""
        with self._honeypots_lock:
            return [
                {
                    "id": h.id,
                    "port": h.port,
                    "protocol": h.protocol,
                    "persona": h.persona,
                    "status": h.status,
                    "connections": h.connections,
                    "started_at": h.started_at,
                    "commands_captured": len(h.captured_commands),
                    "credentials_captured": len(h.captured_credentials)
                }
                for h in self.honeypots.values()
            ]

    def get_captured_intelligence(self) -> dict:
        """Get all captured threat intelligence."""
        with self._honeypots_lock:
            all_commands = []
            all_credentials = []

            for hp in self.honeypots.values():
                all_commands.extend(hp.captured_commands)
                all_credentials.extend(hp.captured_credentials)

        with self._sessions_lock:
            sessions_data = [
                {
                    "id": s.id,
                    "source_ip": s.source_ip,
                    "duration": s.duration_seconds,
                    "commands_count": len(s.commands)
                }
                for s in self.sessions.values()
            ]

        return {
            "total_commands": len(all_commands),
            "unique_commands": len(set(all_commands)),
            "credentials_captured": len(all_credentials),
            "sessions": sessions_data,
            "top_commands": self._get_top_items(all_commands, 10),
            "top_usernames": self._get_top_items(
                [c["username"] for c in all_credentials], 10
            )
        }

    def _get_top_items(self, items: List[str], n: int) -> List[tuple]:
        """Get top N most frequent items."""
        from collections import Counter
        return Counter(items).most_common(n)

    def get_statistics(self) -> dict:
        """Get deception engine statistics."""
        return {
            "enabled": self.enabled,
            "total_honeypots": len(self.honeypots),
            "active_honeypots": self.get_active_count(),
            "total_sessions": len(self.sessions),
            "intelligence": self.get_captured_intelligence()
        }
