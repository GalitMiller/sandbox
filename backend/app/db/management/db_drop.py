# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from flask.ext.script import Command
from sqlalchemy_utils import drop_database

from app import app


class DropDatabase(Command):
    """
    Totally destroy DB.
    """
    name = "drop"

    def run(self):
        drop_database(app.config['SQLALCHEMY_DATABASE_URI'])
