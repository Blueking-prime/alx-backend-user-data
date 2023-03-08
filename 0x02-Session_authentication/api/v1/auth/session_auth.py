#!/usr/bin/env python3
'''manage the API authentication'''
from flask import request
from uuid import uuid4
from models.user import User
from api.v1.auth.auth import Auth
from base64 import b64decode
from typing import Tuple, TypeVar


class SessionAuth(Auth):
    '''Session Authentication class'''
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        '''Creates a session ID for a user_id'''
        if user_id is None or type(user_id) is not str:
            return None
        session_id = str(uuid4())
        SessionAuth.user_id_by_session_id.update({session_id: user_id})
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        '''Returns a User ID based on a Session ID'''
        if session_id is None or type(session_id) is not str:
            return None
        return SessionAuth.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        '''returns a User instance based on a cookie value'''
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        return User.get(user_id)

    def destroy_session(self, request=None):
        '''deletes the user session / logout'''
        if request:
            if session_id := self.session_cookie(request):
                if self.user_id_for_session_id(session_id):
                    self.user_id_by_session_id.pop(session_id)
                    return True
        return False
