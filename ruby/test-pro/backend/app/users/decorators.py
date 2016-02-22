# -*- coding: utf-8 -*-

from functools import wraps

from flask import abort
from flask.ext.login import current_user

from .preprocessors import login_required_preprocessor


def api_login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):
        """
        Load user automatically from DB using bricata cookie, like SQLAlchemy
        does for DB API.
        """
        login_required_preprocessor()

        if current_user.is_authenticated():
            return function(*args, **kwargs)
        else:
            abort(401)

    return wrapper
