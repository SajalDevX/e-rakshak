#!/usr/bin/env python3
"""
RAKSHAK Flask API - DRISHTI Backend
====================================

RESTful API and WebSocket server for the RAKSHAK dashboard.

Features:
- REST endpoints for status, devices, threats
- WebSocket for real-time updates
- CCTNS export API
- Configuration management

Author: Team RAKSHAK
"""

import os
import json
from datetime import datetime
from functools import wraps
from typing import Optional

from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from loguru import logger


# Global SocketIO instance (initialized in create_app)
socketio = None


def create_app(config: dict, orchestrator=None) -> Flask:
    """
    Create and configure Flask application.

    Args:
        config: Application configuration dict
        orchestrator: RakshakOrchestrator instance

    Returns:
        Configured Flask app
    """
    global socketio

    # Create Flask app
    app = Flask(
        __name__,
        template_folder="../dashboard/templates",
        static_folder="../dashboard/static"
    )

    # Configuration
    api_config = config.get("api", {})
    app.config["SECRET_KEY"] = api_config.get("secret_key", "rakshak-secret-key")
    app.config["DEBUG"] = config.get("general", {}).get("debug", False)

    # Enable CORS
    CORS(app, origins=api_config.get("cors_origins", "*"))

    # Initialize SocketIO
    ws_config = api_config.get("websocket", {})
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        ping_interval=ws_config.get("ping_interval", 25),
        ping_timeout=ws_config.get("ping_timeout", 120),
        async_mode="eventlet"
    )

    # Store orchestrator reference
    app.orchestrator = orchestrator
    app.config_data = config

    # Register routes
    register_routes(app)
    register_socket_events(socketio, app)

    logger.info("Flask app created successfully")
    return app


def register_routes(app: Flask):
    """Register all REST API routes."""

    # =========================================================================
    # Dashboard Routes
    # =========================================================================

    @app.route("/")
    def index():
        """Serve main dashboard page."""
        return render_template("index.html")

    @app.route("/static/<path:filename>")
    def serve_static(filename):
        """Serve static files."""
        return send_from_directory(app.static_folder, filename)

    # =========================================================================
    # API Routes - Status
    # =========================================================================

    @app.route("/api/status")
    def get_status():
        """Get system status."""
        if app.orchestrator:
            status = app.orchestrator.get_status()
        else:
            status = {
                "running": False,
                "mode": "not_initialized"
            }

        return jsonify({
            "success": True,
            "data": status,
            "timestamp": datetime.now().isoformat()
        })

    @app.route("/api/health")
    def health_check():
        """Health check endpoint."""
        return jsonify({
            "status": "healthy",
            "service": "RAKSHAK",
            "version": app.config_data.get("general", {}).get("version", "1.0.0"),
            "timestamp": datetime.now().isoformat()
        })

    # =========================================================================
    # API Routes - Devices
    # =========================================================================

    @app.route("/api/devices")
    def get_devices():
        """Get all discovered devices."""
        if not app.orchestrator:
            return jsonify({"success": False, "error": "Not initialized"}), 503

        scanner = app.orchestrator.network_scanner
        devices = scanner.get_all_devices()

        return jsonify({
            "success": True,
            "data": [d.to_dict() for d in devices],
            "count": len(devices),
            "timestamp": datetime.now().isoformat()
        })

    @app.route("/api/devices/<device_ip>")
    def get_device(device_ip: str):
        """Get specific device by IP."""
        if not app.orchestrator:
            return jsonify({"success": False, "error": "Not initialized"}), 503

        scanner = app.orchestrator.network_scanner
        device = scanner.get_device(device_ip)

        if device:
            return jsonify({
                "success": True,
                "data": device.to_dict()
            })
        else:
            return jsonify({
                "success": False,
                "error": "Device not found"
            }), 404

    @app.route("/api/devices/<device_ip>/isolate", methods=["POST"])
    def isolate_device(device_ip: str):
        """Isolate a device."""
        if not app.orchestrator:
            return jsonify({"success": False, "error": "Not initialized"}), 503

        scanner = app.orchestrator.network_scanner
        success = scanner.isolate_device(device_ip)

        if success:
            # Emit WebSocket event (broadcast=True to send to all clients)
            socketio.emit("device_isolated", {
                "ip": device_ip,
                "timestamp": datetime.now().isoformat()
            })

            return jsonify({
                "success": True,
                "message": f"Device {device_ip} isolated"
            })
        else:
            return jsonify({
                "success": False,
                "error": "Device not found"
            }), 404

    @app.route("/api/devices/statistics")
    def get_device_statistics():
        """Get device statistics."""
        if not app.orchestrator:
            return jsonify({"success": False, "error": "Not initialized"}), 503

        scanner = app.orchestrator.network_scanner
        stats = scanner.get_statistics()

        return jsonify({
            "success": True,
            "data": stats
        })

    # =========================================================================
    # API Routes - Zero Trust Enrollment
    # =========================================================================

    @app.route("/api/auth/login", methods=["POST"])
    def login():
        """Authenticate user and return JWT token."""
        from core.api_auth import authenticate_user, generate_token

        data = request.json
        username = data.get("username")
        password = data.get("password")

        auth_result = authenticate_user(username, password)
        if not auth_result:
            return jsonify({"success": False, "error": "Invalid credentials"}), 401

        username, role = auth_result
        token = generate_token(username, role)

        return jsonify({
            "success": True,
            "token": token,
            "username": username,
            "role": role
        })

    @app.route("/api/devices/<device_ip>/enroll", methods=["POST"])
    def initiate_enrollment(device_ip: str):
        """Mark device as pending enrollment."""
        if not app.orchestrator or not hasattr(app.orchestrator, 'trust_manager'):
            return jsonify({"success": False, "error": "Trust manager not available"}), 503

        if not app.orchestrator.trust_manager:
            return jsonify({"success": False, "error": "Trust manager not initialized"}), 503

        trust_manager = app.orchestrator.trust_manager
        success = trust_manager.initiate_enrollment(device_ip)

        if success:
            socketio.emit("device_enrollment_started", {
                "ip": device_ip,
                "timestamp": datetime.now().isoformat()
            })

            return jsonify({
                "success": True,
                "message": f"Enrollment initiated for {device_ip}"
            })

        return jsonify({"success": False, "error": "Failed to initiate enrollment"}), 500

    @app.route("/api/devices/<device_ip>/approve", methods=["POST"])
    def approve_enrollment(device_ip: str):
        """Approve device enrollment and assign to zone."""
        if not app.orchestrator or not hasattr(app.orchestrator, 'trust_manager'):
            return jsonify({"success": False, "error": "Trust manager not available"}), 503

        if not app.orchestrator.trust_manager:
            return jsonify({"success": False, "error": "Trust manager not initialized"}), 503

        data = request.json
        zone = data.get("zone", "main")
        approved_by = data.get("approved_by", "admin")  # TODO: Get from JWT token

        trust_manager = app.orchestrator.trust_manager
        success = trust_manager.approve_enrollment(device_ip, zone, approved_by)

        if success:
            # Update in-memory device cache with new zone
            scanner = app.orchestrator.network_scanner
            device = scanner.get_device(device_ip)
            if device:
                device.zone = zone
                device.enrollment_status = "enrolled"
                scanner.update_device(device)
                logger.info(f"Updated in-memory cache: {device_ip} zone={zone}")

            socketio.emit("device_enrolled", {
                "ip": device_ip,
                "zone": zone,
                "timestamp": datetime.now().isoformat()
            })

            return jsonify({
                "success": True,
                "message": f"Device {device_ip} enrolled to {zone} zone"
            })

        return jsonify({"success": False, "error": "Failed to approve enrollment"}), 500

    @app.route("/api/zones/statistics")
    def get_zone_statistics():
        """Get device count per zone."""
        if not app.orchestrator or not hasattr(app.orchestrator, 'trust_manager'):
            return jsonify({"success": False, "error": "Trust manager not available"}), 503

        if not app.orchestrator.trust_manager:
            return jsonify({"success": False, "error": "Trust manager not initialized"}), 503

        trust_manager = app.orchestrator.trust_manager
        stats = trust_manager.get_zone_statistics()

        return jsonify({
            "success": True,
            "data": stats
        })

    # =========================================================================
    # API Routes - Threats
    # =========================================================================

    @app.route("/api/threats")
    def get_threats():
        """Get recent threats."""
        if not app.orchestrator:
            return jsonify({"success": False, "error": "Not initialized"}), 503

        limit = request.args.get("limit", 50, type=int)
        logger = app.orchestrator.threat_logger
        threats = logger.get_recent_threats(limit)

        return jsonify({
            "success": True,
            "data": threats,
            "count": len(threats),
            "timestamp": datetime.now().isoformat()
        })

    @app.route("/api/threats/statistics")
    def get_threat_statistics():
        """Get threat statistics."""
        if not app.orchestrator:
            return jsonify({"success": False, "error": "Not initialized"}), 503

        logger = app.orchestrator.threat_logger
        stats = logger.get_statistics()

        return jsonify({
            "success": True,
            "data": stats
        })

    @app.route("/api/threats/export/cctns", methods=["POST"])
    def export_cctns():
        """Export threats to CCTNS format."""
        if not app.orchestrator:
            return jsonify({"success": False, "error": "Not initialized"}), 503

        logger = app.orchestrator.threat_logger
        filepath = logger.export_cctns()

        return jsonify({
            "success": True,
            "filepath": filepath,
            "message": "CCTNS export created"
        })

    @app.route("/api/threats/export/json", methods=["POST"])
    def export_json():
        """Export threats to JSON format."""
        if not app.orchestrator:
            return jsonify({"success": False, "error": "Not initialized"}), 503

        logger = app.orchestrator.threat_logger
        filepath = logger.export_json()

        return jsonify({
            "success": True,
            "filepath": filepath,
            "message": "JSON export created"
        })

    # =========================================================================
    # API Routes - Actions
    # =========================================================================

    @app.route("/api/actions")
    def get_actions():
        """Get recent actions."""
        if not app.orchestrator:
            return jsonify({"success": False, "error": "Not initialized"}), 503

        limit = request.args.get("limit", 50, type=int)
        logger = app.orchestrator.threat_logger
        actions = logger.get_recent_actions(limit)

        return jsonify({
            "success": True,
            "data": actions,
            "count": len(actions)
        })

    # =========================================================================
    # API Routes - Honeypots
    # =========================================================================

    @app.route("/api/honeypots")
    def get_honeypots():
        """Get all honeypots."""
        if not app.orchestrator:
            return jsonify({"success": False, "error": "Not initialized"}), 503

        engine = app.orchestrator.deception_engine
        honeypots = engine.get_all_honeypots()

        return jsonify({
            "success": True,
            "data": honeypots,
            "count": len(honeypots)
        })

    @app.route("/api/honeypots/deploy", methods=["POST"])
    def deploy_honeypot():
        """Deploy a new honeypot."""
        if not app.orchestrator:
            return jsonify({"success": False, "error": "Not initialized"}), 503

        data = request.json or {}
        protocol = data.get("protocol", "telnet")
        persona = data.get("persona", "tp_link")

        engine = app.orchestrator.deception_engine
        honeypot = engine.deploy_honeypot(
            protocol=protocol,
            persona=persona
        )

        if honeypot:
            # Emit WebSocket event (broadcast=True to send to all clients)
            socketio.emit("honeypot_deployed", {
                "id": honeypot.id,
                "port": honeypot.port,
                "protocol": protocol
            })

            return jsonify({
                "success": True,
                "data": {
                    "id": honeypot.id,
                    "port": honeypot.port,
                    "protocol": honeypot.protocol,
                    "persona": honeypot.persona
                }
            })
        else:
            return jsonify({
                "success": False,
                "error": "Failed to deploy honeypot"
            }), 500

    @app.route("/api/honeypots/<honeypot_id>/stop", methods=["POST"])
    def stop_honeypot(honeypot_id: str):
        """Stop a honeypot."""
        if not app.orchestrator:
            return jsonify({"success": False, "error": "Not initialized"}), 503

        engine = app.orchestrator.deception_engine
        success = engine.stop_honeypot(honeypot_id)

        if success:
            return jsonify({
                "success": True,
                "message": f"Honeypot {honeypot_id} stopped"
            })
        else:
            return jsonify({
                "success": False,
                "error": "Honeypot not found"
            }), 404

    @app.route("/api/honeypots/intelligence")
    def get_intelligence():
        """Get captured threat intelligence."""
        if not app.orchestrator:
            return jsonify({"success": False, "error": "Not initialized"}), 503

        engine = app.orchestrator.deception_engine
        intel = engine.get_captured_intelligence()

        return jsonify({
            "success": True,
            "data": intel
        })

    # =========================================================================
    # API Routes - Agent
    # =========================================================================

    @app.route("/api/agent/status")
    def get_agent_status():
        """Get AI agent status."""
        if not app.orchestrator:
            return jsonify({"success": False, "error": "Not initialized"}), 503

        agent = app.orchestrator.agentic_defender
        stats = agent.get_statistics()

        return jsonify({
            "success": True,
            "data": stats
        })

    # =========================================================================
    # API Routes - Configuration
    # =========================================================================

    @app.route("/api/config")
    def get_config():
        """Get current configuration (sanitized)."""
        # Remove sensitive data
        safe_config = {
            "general": app.config_data.get("general", {}),
            "simulation": {
                "enabled": app.config_data.get("simulation", {}).get("enabled", True)
            },
            "network": {
                "scan_interval": app.config_data.get("network", {}).get("scan_interval", 60)
            },
            "deception": {
                "enabled": app.config_data.get("deception", {}).get("enabled", True),
                "max_honeypots": app.config_data.get("deception", {}).get("max_honeypots", 10)
            }
        }

        return jsonify({
            "success": True,
            "data": safe_config
        })

    @app.route("/api/config/language", methods=["POST"])
    def set_language():
        """Set dashboard language."""
        data = request.json or {}
        language = data.get("language", "en")

        if language in ["en", "hi"]:
            app.config_data["general"]["language"] = language
            return jsonify({
                "success": True,
                "language": language
            })
        else:
            return jsonify({
                "success": False,
                "error": "Invalid language"
            }), 400

    # =========================================================================
    # API Routes - Demo/Simulation
    # =========================================================================

    @app.route("/api/simulate/threat", methods=["POST"])
    def simulate_threat():
        """Simulate a threat for demo purposes."""
        if not app.orchestrator:
            return jsonify({"success": False, "error": "Not initialized"}), 503

        from core.threat_logger import SimulatedThreatGenerator

        # Get real devices from network scanner
        real_devices = []
        if hasattr(app.orchestrator, 'scanner') and app.orchestrator.scanner:
            devices = app.orchestrator.scanner.get_all_devices()
            real_devices = [{"ip": d.ip, "hostname": d.hostname or d.device_type, "name": d.hostname or d.device_type} for d in devices]

        # Get optional attack type from request
        data = request.get_json() or {}
        attack_type = data.get("attack_type")  # e.g., "brute_force", "dos_attack", etc.

        generator = SimulatedThreatGenerator(app.config_data, real_devices=real_devices)
        threat = generator.generate_threat(attack_type=attack_type)

        # Log the threat
        logger = app.orchestrator.threat_logger
        event = logger.log_threat(
            threat_type=threat["type"],
            severity=threat["severity"],
            source_ip=threat["source_ip"],
            target_ip=threat["target_ip"],
            target_device=threat["target_device"],
            source_port=threat["source_port"],
            target_port=threat["target_port"],
            protocol=threat["protocol"],
            packets_count=threat["packets_count"],
            duration_seconds=threat["duration_seconds"],
            detected_by="simulation"
        )

        # Emit WebSocket event (broadcast=True to send to all clients)
        socketio.emit("threat_detected", {
            "threat": event.to_dict(),
            "timestamp": datetime.now().isoformat()
        })

        return jsonify({
            "success": True,
            "data": event.to_dict()
        })

    # =========================================================================
    # Error Handlers
    # =========================================================================

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({
            "success": False,
            "error": "Not found"
        }), 404

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500


def register_socket_events(socketio: SocketIO, app: Flask):
    """Register WebSocket event handlers."""

    @socketio.on("connect")
    def handle_connect():
        """Handle client connection."""
        logger.debug("WebSocket client connected")
        emit("connected", {
            "message": "Connected to RAKSHAK",
            "timestamp": datetime.now().isoformat()
        })

    @socketio.on("disconnect")
    def handle_disconnect():
        """Handle client disconnection."""
        logger.debug("WebSocket client disconnected")

    @socketio.on("subscribe")
    def handle_subscribe(data):
        """Handle subscription to specific event types."""
        event_type = data.get("type", "all")
        logger.debug(f"Client subscribed to: {event_type}")
        emit("subscribed", {"type": event_type})

    @socketio.on("request_status")
    def handle_status_request():
        """Handle status request."""
        if app.orchestrator:
            status = app.orchestrator.get_status()
            emit("status_update", status)

    @socketio.on("request_devices")
    def handle_devices_request():
        """Handle devices request."""
        if app.orchestrator:
            devices = app.orchestrator.network_scanner.get_all_devices()
            emit("devices_update", {
                "devices": [d.to_dict() for d in devices]
            })


# Utility function to emit events from outside Flask context
def emit_alert(message: str, threat: dict = None, severity: str = "medium"):
    """Emit alert to all connected clients."""
    global socketio
    if socketio:
        socketio.emit("alert", {
            "message": message,
            "threat": threat,
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        })


def emit_threat_detected(threat: dict):
    """Emit threat detected event."""
    global socketio
    if socketio:
        socketio.emit("threat_detected", {
            "threat": threat,
            "timestamp": datetime.now().isoformat()
        })


def emit_action_taken(action: dict):
    """Emit action taken event."""
    global socketio
    if socketio:
        socketio.emit("action_taken", {
            "action": action,
            "timestamp": datetime.now().isoformat()
        })
