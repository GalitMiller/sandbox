# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from flask.ext.script import Command, Option

from app.db import db
from app.users.constants import USER_ROLES
from app.users.models import User
from app.utils.encoding import smart_str


LOG = logging.getLogger(__name__)


class CreateUser(Command):
    """
    Create new user in application database.
    """
    name = "create"

    option_list = (
        Option(
            '-l', '--login',
            help="Login name for user.",
            required=True,
        ),
        Option(
            '-p', '--password',
            help="User password.",
            required=True,
        ),
        Option(
            '-n', '--name',
            help="User name.",
            required=True,
        ),
        Option(
            '-e', '--email',
            help="User email.",
            required=True,
        ),
        Option(
            '-r', '--role',
            help="User role.",
            choices=USER_ROLES._asdict().values(),
            default=USER_ROLES.ANALYST,
        ),
        Option(
            '-a', '--active',
            help="Is user active. Default value: \"true\".",
            type=bool,
            default=True,
        )
    )

    def run(self, login, password, name, email, role, active):
        login = smart_str(login).strip()
        password = smart_str(password).strip()
        name = smart_str(name).strip()
        email = smart_str(email).strip()
        role = smart_str(role).strip()

        user = User(
            login=login,
            password=password,
            name=name,
            email=email,
            role=role,
            active=active,
        )

        db.session.add(user)
        db.session.commit()

        LOG.debug("User '{login}' is created (id={id})."
                  .format(login=login, id=user.id))

        return user
