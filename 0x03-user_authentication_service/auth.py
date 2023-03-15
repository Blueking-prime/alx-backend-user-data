#!/usr/bin/env python3
'''Contains all the authentication stuff'''
from bcrypt import hashpw, gensalt, checkpw
from uuid import uuid4
from typing import Union
from db import DB, User, NoResultFound


def _hash_password(password: str) -> bytes:
    '''Hashes a password'''
    return hashpw(bytes(password, 'utf-8'), gensalt())


def _generate_uuid() -> str:
    '''Generates a UUID and converts it to a string'''
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        '''Creates a user'''
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            h_password = _hash_password(password)
            user = self._db.add_user(email, h_password.decode())
            return user
        else:
            raise ValueError('User {} already exists'.format(email))

    def valid_login(self, email: str, password: str) -> bool:
        '''Try to log in the user'''
        try:
            user = self._db.find_user_by(email=email)
            return checkpw(bytes(password, 'utf-8'),
                           bytes(user.hashed_password, 'utf-8'))
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        '''returns the session id for a given email'''
        try:
            user = self._db.find_user_by(email=email)
            self._db.update_user(user.id, session_id=_generate_uuid())
            user = self._db.find_user_by(email=email)
            return user.session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        '''Returns a user with the session id'''
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        '''Destroys a user's session'''
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        '''Gets a user's reset token'''
        try:
            user = self._db.find_user_by(email=email)
            token = _generate_uuid()
            self._db.update_user(user.id, reset_token=token)
            return token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        '''Updates a users password'''
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            h_password = _hash_password(password).decode()
            self._db.update_user(user.id, hashed_password=h_password,
                                 reset_token=None)
        except NoResultFound:
            raise ValueError
