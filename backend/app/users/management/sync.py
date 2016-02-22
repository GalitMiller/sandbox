# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from flask.ext.script import Command
from isotopic_logging import autoprefix_injector
from unipath import Path

from app import users
from app.db import db
from app.db.utils import execute_script
from app.users.constants import USER_ROLES
from app.users.models import User, SnorbyUser


LOG = logging.getLogger(__name__)


class SyncSetup(Command):
    """
    Setup mechanisms for synchronization of users between 'bricata' DB and
    primary DB.
    """
    name = "sync_setup"

    def run(self):
        filename = Path(users.__file__).absolute().parent.child(
            'sql', 'triggers', 'sync_users.sql'
        )
        execute_script(filename)


class SyncUsers(Command):
    """
    Drop all existing users from primary DB and fetch them from 'bricata' DB.
    """
    name = "sync"

    def run(self):
        # TODO: do not delete objects with same ID: update them instead
        with autoprefix_injector():
            self._delete_existing()
            self._grab_new()

    def _delete_existing(self):
        count = User.query.delete()

        with autoprefix_injector() as inj:
            LOG.debug(inj.mark(
                "Deleted {0} user(s).".format(count)))

    def _grab_new(self):
        with autoprefix_injector() as inj:
            users = SnorbyUser.query

            count = users.count()
            LOG.info(inj.mark(
                "Grabbing {0} users(s)...".format(count)))

            try:
                for user in users:
                    kwargs = dict(
                        id=user.id,
                        email=user.email,
                        login=self._email_to_login(user.email),
                        name=user.name,
                        password=user.encrypted_password,
                        active=user.enabled,
                    )
                    if user.admin:
                        kwargs['role'] = USER_ROLES.ADMIN

                    db.session.add(User(**kwargs))

                db.session.commit()
            except Exception as e:
                db.session.rollback()
                LOG.error(inj.mark(
                    "Failed to grab users: {e}".format(e=e)))
            else:
                LOG.info(inj.mark(
                    "Users were grabbed successfully"))

    @staticmethod
    def _email_to_login(email):
        return email.split('@', 1)[0]
