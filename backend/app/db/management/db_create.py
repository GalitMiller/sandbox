# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from flask.ext.script import Command
from sqlalchemy_utils import create_database
from alembic.config import Config
from alembic import command

from app import app
from app.db import db


SQLALCHEMY_DATABASE_URI = app.config['SQLALCHEMY_DATABASE_URI']


class CreateDatabase(Command):
    """
    Create empty DB and tables from scratch.
    """
    name = "create"

    def run(self):
        create_database(SQLALCHEMY_DATABASE_URI)
        db.create_all(bind=None)

        # Load the Alembic configuration and generate the
        # version table, "stamping" it with the most recent rev:
        alembic_cfg = Config("migrations/alembic.ini")
        command.stamp(alembic_cfg, "head")
