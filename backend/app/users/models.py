# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import warnings

from werkzeug.security import (
    generate_password_hash, check_password_hash,
)

from app.db import db
from app.utils.encoding import smart_str, smart_bytes

from .constants import USER_ROLES


class SnorbyUser(db.Model):
    __tablename__ = 'users'
    __bind_key__ = 'snorby'

    id = db.Column(
        db.Integer,
        primary_key=True,
        nullable=False,
    )
    name = db.Column(
        db.Unicode(50),
    )
    email = db.Column(
        db.Unicode(255),
        nullable=False,
        unique=True,
    )
    encrypted_password = db.Column(
        db.Unicode(128),
        nullable=False,
    )
    enabled = db.Column(
        db.Boolean,
        default=True,
    )
    admin = db.Column(
        db.Boolean,
        default=False,
    )

    def __repr__(self):
        return smart_bytes("<SnorbyUser '{0}'>".format(self.email))


class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(
        db.Integer,
        primary_key=True,
        nullable=False,
    )
    login = db.Column(
        db.Unicode(255),
        index=True,
        unique=True,
        nullable=False,
    )
    password = db.Column(
        db.Unicode(255),
        nullable=False,
    )
    name = db.Column(
        db.Unicode(255),
        nullable=False,
    )
    role = db.Column(
        db.Enum(*USER_ROLES._asdict().values()),
        default=USER_ROLES.ANALYST,
    )
    email = db.Column(
        db.Unicode(255),
        nullable=False,
        unique=True,
    )
    active = db.Column(
        db.Boolean,
        default=True,
    )

    @classmethod
    def make_unique_login(cls, login):
        warnings.warn("make_unique_login() is deprecated and removed in "
                      "project based on Django", DeprecationWarning)

        if cls.query.filter_by(login=login).first() is None:
            return login

        version = 2
        while True:
            new_login = login + smart_str(version)
            if cls.query.filter_by(login=new_login).first() is None:
                break
            version += 1

        return new_login

    def get_id(self):
        return smart_str(self.id)

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def is_active(self):
        return self.active

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return smart_bytes("<User '{0}'>".format(self.login))
