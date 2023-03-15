#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from user import Base, User
from sqlalchemy.orm.exc import NoResultFound


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        '''Adds a new user'''
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        self.__session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        '''takes arbitrary keyword arguments, returns the first row found'''
        res = self._session.query(User).filter_by(**kwargs).first()
        if res is None:
            raise NoResultFound
        else:
            return res

    def update_user(self, user_id: int, **kwargs) -> None:
        '''Updates a users data'''
        user = self.find_user_by(id=user_id)
        if 'id' in kwargs:
            if type(kwargs['id']) != str:
                raise ValueError
            user.id = kwargs['id']

        if 'email' in kwargs:
            if type(kwargs['email']) != str:
                raise ValueError
            user.email = kwargs['email']

        if 'hashed_password' in kwargs:
            if type(kwargs['hashed_password']) != str:
                raise ValueError
            user.hashed_password = kwargs['hashed_password']

        if 'session_id' in kwargs:
            if type(kwargs['session_id']) != str \
                    and kwargs['session_id'] is not None:
                raise ValueError
            user.session_id = kwargs['session_id']

        if 'reset_token' in kwargs:
            if type(kwargs['reset_token']) != str \
                    and kwargs['reset_token'] is not None:
                raise ValueError
            user.reset_token = kwargs['reset_token']

        self.__session.commit()
