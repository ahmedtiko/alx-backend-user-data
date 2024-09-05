#!/usr/bin/env python3
"""Module of session authenticating views.
"""
import os
from typing import Tuple
from flask import abort, jsonify, request

from models.user import User
from api.v1.views import app_views
from api.v1.app import auth  # Moved to the top for cleaner imports

@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login() -> Tuple[str, int]:
    """POST /api/v1/auth_session/login
    Return:
      - JSON representation of a User object.
    """
    not_found_res = {"error": "no user found for this email"}
    email = request.form.get('email')
    
    # Check if email is provided and valid
    if not email or len(email.strip()) == 0:
        return jsonify({"error": "email missing"}), 400
    
    password = request.form.get('password')
    
    # Check if password is provided and valid
    if not password or len(password.strip()) == 0:
        return jsonify({"error": "password missing"}), 400
    
    try:
        users = User.search({'email': email})
    except Exception:
        return jsonify(not_found_res), 404
    
    if len(users) == 0:
        return jsonify(not_found_res), 404
    
    user = users[0]  # Get the first user found
    
    # Check if password is valid
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401
    
    # Create a session ID for the user
    session_id = auth.create_session(user.id)
    
    res = jsonify(user.to_json())
    
    # Get session name from environment or use a default value
    session_name = os.getenv("SESSION_NAME", "session_id")
    
    # Set session ID in the response cookie
    res.set_cookie(session_name, session_id)
    
    return res

@app_views.route('/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def logout() -> Tuple[str, int]:
    """DELETE /api/v1/auth_session/logout
    Return:
      - An empty JSON object.
    """
    is_destroyed = auth.destroy_session(request)
    
    if not is_destroyed:
        abort(404)
    
    return jsonify({}), 200
