#!/usr/bin/env python3
'''manage the API authentication'''
from flask import request
from typing import List, TypeVar
from os import getenv


class Auth():
    '''Base Auth class'''

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        '''Determine if user requires auth'''
        if path is None:
            return True
        if excluded_paths is None or len(excluded_paths) == 0:
            return True

        if path not in excluded_paths and path + '/' not in excluded_paths:
            return True
        else:
            return False

    def authorization_header(self, request=None) -> str:
        '''The authorization header for the request'''
        if request.headers.get('Authorization'):
            return request.headers.get('Authorization')
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        '''The current user'''
        return None

    def session_cookie(self, request=None):
        '''returns a cookie value from a request'''
        if request is None:
            return None
        session_id = getenv('SESSION_NAME')
        return request.cookies.get(session_id)
