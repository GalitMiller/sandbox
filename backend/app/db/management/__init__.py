# -*- coding: utf-8 -*-
"""
Perform operations on DB.
"""

from flask.ext.migrate import MigrateCommand as db

from .db_create import CreateDatabase
from .db_drop import DropDatabase
from .db_prepopulate import PrepopulateDatabase
from .db_recreate import RecreateDatabase

__all__ = ['db', ]


db.add_command(CreateDatabase.name, CreateDatabase)
db.add_command(DropDatabase.name, DropDatabase)
db.add_command(RecreateDatabase.name, RecreateDatabase)
db.add_command(PrepopulateDatabase.name, PrepopulateDatabase)
