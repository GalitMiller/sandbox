# -*- coding: utf-8 -*-

from MySQLdb.constants.ER import DUP_ENTRY
from sqlalchemy.exc import IntegrityError
from subprocess import Popen, PIPE

from app import app


def execute_script(filename):
    cmd = [
        'mysql',
        '-u', app.config['DB_USER'],
    ]

    password = app.config['DB_PASSWORD']
    if password:
        cmd.extend([
            '-p', password,
        ])

    process = Popen(cmd, stdout=PIPE, stdin=PIPE)
    process.communicate("source {0}".format(filename))


def raise_db_error(error):
    if isinstance(error, IntegrityError):
        code, message = error.orig

        if code == DUP_ENTRY:
            raise ValueError(message)

    raise error
