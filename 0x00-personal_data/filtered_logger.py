#!/usr/bin/env python3
'''Filters out sensitive data'''
import re
import logging
from mysql.connector import connection, connect
from os import getenv
from typing import List, Tuple, Union


PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


def filter_datum(fields: Union[List[str], Tuple[str]], redaction: str,
                 message: str, separator: str) -> str:
    '''returns the log message obfuscated'''
    m = message.split(separator)
    for i in fields:
        m = [re.sub(i + '=.*', i + '=' + redaction, j) for j in m]
    return separator.join(m)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: Union[List, Tuple]):
        '''Initialize formatter'''
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        '''Formats a string while redacting sensitive information'''
        message = super(RedactingFormatter, self).format(record)
        message = filter_datum(self.fields, self.REDACTION,
                               message, self.SEPARATOR)
        message = '; '.join(message.split(';'))
        return message


def get_logger() -> logging.Logger:
    '''Creates a logger'''
    user_data = logging.Logger('user_data', logging.INFO)
    user_data.propagate = False
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))
    user_data.addHandler(handler)

    return user_data


def get_db() -> connection.MySQLConnection:
    '''Returns a mysql connector'''
    username = getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    password = getenv('PERSONAL_DATA_DB_PASSWORD', '')
    host = getenv('PERSONAL_DATA_DB_HOST', 'localhost')
    db_name = getenv('PERSONAL_DATA_DB_NAME')

    db = connect(user=username, password=password,
                 host=host, database=db_name)
    return db


def main() -> None:
    '''Main function'''
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    logger = get_logger()
    fields = cursor.column_names
    for row in cursor:
        row_data = []
        for k, v in zip(fields, row):
            row_data.append(f'{k}={v}; ')
        logger.info(''.join(row_data).strip())
    cursor.close()
    db.close()


if __name__ == '__main__':
    main()
