#!/usr/bin/env python3
""" Module of Users views
"""
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User
from os import getenv


@app_views.route('/auth_session/login/', methods=['POST'],
                 strict_slashes=False)
def authenticate_session():
    """ POST /api/v1/auth_session/login/
    JSON body:
      - email
      - password
    Return:
      - User object JSON represented
      - 400 if can't create session
    """

    rj = None
    error_msg = None
    rj = request.form
    if error_msg is None and rj.get("email", "") == "":
        error_msg = "email missing"
    if error_msg is None and rj.get("password", "") == "":
        error_msg = "password missing"
    if error_msg is None:
        email = rj.get("email")
        password = rj.get('password')
        user = User.search({'email': email})
        if user:
            user = user[0]
            if user.is_valid_password(password):
                from api.v1.app import auth
                session_id = auth.create_session(user.id)
                out = jsonify(user.to_json())
                out.set_cookie(getenv('SESSION_NAME'), session_id)
                return out, 200
            else:
                return jsonify({"error": "wrong password"}), 401
        return jsonify({"error": "no user found for this email"}), 404
    return jsonify({'error': error_msg}), 400


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def delete_session():
    """ DELETE /api/v1/auth_session/logout
    Return:
      - empty JSON is the User has been correctly deleted
      - 404 if the User ID doesn't exist
    """
    from api.v1.app import auth
    if auth.destroy_session(request):
        return jsonify({}), 200
    else:
        abort(404)
