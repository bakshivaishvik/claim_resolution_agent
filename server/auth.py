import os
import jwt
from functools import wraps
from datetime import datetime, timezone, timedelta
from flask import request, jsonify, redirect, url_for, g
from server.security import JWT_SECRET_KEY
from server.database import get_db_connection

JWT_ALGORITHM = "HS256"

def create_jwt_token(user_id: int, username: str, role: str, full_name: str, expires_hours: int = 24) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "full_name": full_name,
        "iat": now,
        "exp": now + timedelta(hours=expires_hours)
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def decode_jwt_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def get_current_user_from_request():
    token = None
    # Check Authorization Header: Bearer <token>
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    # Check Cookies
    if not token and "jwt_token" in request.cookies:
        token = request.cookies.get("jwt_token")

    if not token:
        # Default active demo user from cookie or session if available
        demo_user = request.cookies.get("demo_active_user")
        if demo_user:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, role, full_name FROM users WHERE username = ?", (demo_user,))
            row = cursor.fetchone()
            conn.close()
            if row:
                return dict(row)
        return None

    decoded = decode_jwt_token(token)
    if decoded:
        return {
            "id": decoded.get("sub"),
            "username": decoded.get("username"),
            "role": decoded.get("role"),
            "full_name": decoded.get("full_name")
        }
    return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user_from_request()
        if not user:
            if request.is_json:
                return jsonify({"error": "AUTHENTICATION_REQUIRED", "message": "Missing or invalid JWT token"}), 401
            return redirect(url_for("login_page"))
        g.user = user
        return f(*args, **kwargs)
    return decorated_function

def roles_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user_from_request()
            if not user:
                if request.is_json:
                    return jsonify({"error": "AUTHENTICATION_REQUIRED", "message": "Login required"}), 401
                return redirect(url_for("login_page"))
            user_role = user.get("role", "")
            # ADMIN has superset privileges
            if user_role != "ADMIN" and user_role not in allowed_roles:
                if request.is_json:
                    return jsonify({"error": "PERMISSION_DENIED", "message": f"Role '{user_role}' not authorized. Requires: {list(allowed_roles)}"}), 403
                return jsonify({"error": "Forbidden: Insufficient privileges"}), 403
            g.user = user
            return f(*args, **kwargs)
        return decorated_function
    return decorator
