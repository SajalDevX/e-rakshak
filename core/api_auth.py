#!/usr/bin/env python3
"""
RAKSHAK API Authentication Module
==================================

JWT-based authentication and Role-Based Access Control (RBAC).

Features:
- JWT token generation and validation
- Role-based access control
- Permission checking
- Token expiration

Author: Team RAKSHAK
"""

import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
from typing import Callable, Optional

from loguru import logger


class Role:
    """User roles for RBAC"""
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


# TODO: Load from environment variable in production
SECRET_KEY = "rakshak-secret-key-change-in-production"
TOKEN_EXPIRATION_HOURS = 24


def generate_token(username: str, role: str) -> str:
    """
    Generate JWT token for user.

    Args:
        username: Username
        role: User role (admin, operator, viewer)

    Returns:
        JWT token string
    """
    payload = {
        "username": username,
        "role": role,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRATION_HOURS)
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    logger.info(f"Generated token for {username} (role: {role})")
    return token


def decode_token(token: str) -> Optional[dict]:
    """
    Decode and validate JWT token.

    Args:
        token: JWT token string

    Returns:
        Decoded payload dict or None if invalid
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload

    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return None

    except jwt.InvalidTokenError:
        logger.warning("Invalid token")
        return None


def check_role_permission(user_role: str, required_role: str) -> bool:
    """
    Check if user role has permission for required role.

    Role hierarchy:
    - admin: Can perform all actions
    - operator: Can view and modify, but not admin tasks
    - viewer: Can only view

    Args:
        user_role: User's role
        required_role: Required role for action

    Returns:
        True if user has permission, False otherwise
    """
    hierarchy = {
        Role.ADMIN: [Role.ADMIN, Role.OPERATOR, Role.VIEWER],
        Role.OPERATOR: [Role.OPERATOR, Role.VIEWER],
        Role.VIEWER: [Role.VIEWER]
    }

    allowed_roles = hierarchy.get(user_role, [])
    return required_role in allowed_roles


def require_auth(required_role: Optional[str] = None) -> Callable:
    """
    Decorator to require authentication and optionally check role.

    Usage:
        @require_auth()  # Any authenticated user
        @require_auth(required_role=Role.OPERATOR)  # Operator or admin
        @require_auth(required_role=Role.ADMIN)  # Admin only

    Args:
        required_role: Optional required role

    Returns:
        Decorator function
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Get token from Authorization header
            auth_header = request.headers.get("Authorization")

            if not auth_header or not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing or invalid authorization header"}), 401

            token = auth_header.split(" ")[1]

            # Decode and validate token
            payload = decode_token(token)

            if not payload:
                return jsonify({"error": "Invalid or expired token"}), 401

            # Check role permission if required
            if required_role:
                user_role = payload.get("role")

                if not check_role_permission(user_role, required_role):
                    return jsonify({
                        "error": "Insufficient permissions",
                        "required_role": required_role,
                        "user_role": user_role
                    }), 403

            # Attach user info to request
            request.user = payload

            return f(*args, **kwargs)

        return wrapper
    return decorator


def authenticate_user(username: str, password: str) -> Optional[tuple]:
    """
    Authenticate user with username and password.

    TODO: Replace with proper user database lookup
    Currently uses hardcoded credentials for demo.

    Args:
        username: Username
        password: Password

    Returns:
        Tuple of (username, role) if valid, None otherwise
    """
    # Hardcoded users for demo (replace with database lookup)
    users = {
        "admin": {"password": "rakshak123", "role": Role.ADMIN},
        "operator": {"password": "operator123", "role": Role.OPERATOR},
        "viewer": {"password": "viewer123", "role": Role.VIEWER}
    }

    user_data = users.get(username)

    if user_data and user_data["password"] == password:
        logger.info(f"User {username} authenticated successfully")
        return username, user_data["role"]

    logger.warning(f"Failed authentication attempt for {username}")
    return None


class APIAuthManager:
    """
    Centralized API authentication manager.

    Handles token generation, validation, and user management.
    """

    def __init__(self, secret_key: str = SECRET_KEY):
        """
        Initialize API auth manager.

        Args:
            secret_key: Secret key for JWT signing
        """
        self.secret_key = secret_key
        self.active_tokens = set()  # Track active tokens (optional)

        logger.info("APIAuthManager initialized")

    def login(self, username: str, password: str) -> Optional[dict]:
        """
        Authenticate user and generate token.

        Args:
            username: Username
            password: Password

        Returns:
            Dict with token and user info, or None if authentication fails
        """
        auth_result = authenticate_user(username, password)

        if not auth_result:
            return None

        username, role = auth_result
        token = generate_token(username, role)

        # Track active token (optional)
        self.active_tokens.add(token)

        return {
            "token": token,
            "username": username,
            "role": role,
            "expires_in": TOKEN_EXPIRATION_HOURS * 3600  # seconds
        }

    def logout(self, token: str) -> bool:
        """
        Logout user by invalidating token.

        Args:
            token: JWT token to invalidate

        Returns:
            True if successful, False otherwise
        """
        if token in self.active_tokens:
            self.active_tokens.remove(token)
            logger.info("User logged out successfully")
            return True

        return False

    def validate_token(self, token: str) -> Optional[dict]:
        """
        Validate token and return user info.

        Args:
            token: JWT token

        Returns:
            User info dict or None
        """
        return decode_token(token)

    def is_token_active(self, token: str) -> bool:
        """
        Check if token is active.

        Args:
            token: JWT token

        Returns:
            True if active, False otherwise
        """
        return token in self.active_tokens
