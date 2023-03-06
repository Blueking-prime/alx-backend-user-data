#!/usr/bin/env python3
'''manage the API authentication'''
from flask import request
from models.user import User
from api.v1.auth.auth import Auth
from base64 import b64decode
from typing import Tuple, TypeVar


class BasicAuth(Auth):
    '''Basic Auth class'''

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        '''returns the Base64 part of the Authorization header'''
        if authorization_header is None:
            return None
        if type(authorization_header) is not str:
            return None
        if authorization_header.startswith('Basic '):
            return authorization_header.split(' ')[1]
        else:
            return None

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str) \
            -> str:
        '''returns the decoded value of a Base64 string'''
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) is not str:
            return None
        try:
            return b64decode(base64_authorization_header).decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str) \
            -> Tuple[str, str]:
        '''returns the username and password'''
        if decoded_base64_authorization_header is None:
            return None, None
        if type(decoded_base64_authorization_header) is not str:
            return None, None
        if decoded_base64_authorization_header.find(':') != -1:
            return (decoded_base64_authorization_header.split(':')[0],
                    decoded_base64_authorization_header.split(':')[1])
        else:
            return None, None

    def user_object_from_credentials(self, user_email: str, user_pwd: str) \
            -> TypeVar('User'):
        '''returns the user instance from email and password'''
        if user_email is None or type(user_email) is not str:
            return None
        if user_pwd is None or type(user_pwd) is not str:
            return None
        if User.search({'email': user_email}) == []:
            return None
        else:
            user = User.search({'email': user_email})[0]
            if user.is_valid_password(user_pwd):
                return user
            else:
                return None

    def current_user(self, request=None) -> TypeVar('User'):
        '''retrieves the User instance for a request'''
        auth_header = self.authorization_header(request)
        extract_header = self.extract_base64_authorization_header(auth_header)
        decode_head = self.decode_base64_authorization_header(extract_header)
        extract_credentials = self.extract_user_credentials(decode_head)
        user = self.user_object_from_credentials(extract_credentials[0],
                                                 extract_credentials[1])
        return user
