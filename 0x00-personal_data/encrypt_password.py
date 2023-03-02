#!/usr/bin/env python3
'''Password encrypter'''
import bcrypt


def hash_password(password: str) -> bytes:
    '''Hashes password to return a bytestring'''
    return bcrypt.hashpw(bytes(password, 'utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    '''Checks if a password is valid'''
    return bcrypt.checkpw(bytes(password, 'utf-8'), hashed_password)
