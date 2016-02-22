# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from flask.ext.script import Command
from MySQLdb.constants import ER
from sqlalchemy.exc import OperationalError

from .db_create import CreateDatabase
from .db_drop import DropDatabase


class RecreateDatabase(Command):
    """
    Drop existing DB and create new empty one.
    """
    name = "recreate"

    def run(self):
        try:
            DropDatabase().run()
        except OperationalError as e:
            code, message = e.orig
            if code != ER.DB_DROP_EXISTS:
                raise e

        CreateDatabase().run()
