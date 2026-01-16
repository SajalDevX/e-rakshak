"""
RAKSHAK API Module
==================

Flask REST API and WebSocket server for DRISHTI dashboard.
"""

from .app import create_app, socketio, emit_alert, emit_threat_detected, emit_action_taken

__all__ = [
    "create_app",
    "socketio",
    "emit_alert",
    "emit_threat_detected",
    "emit_action_taken"
]
