# -*- coding: utf-8 -*-

from functools import update_wrapper


def no_autoflush(scoped_session):

    def decorate(fn):
        def go(*args, **kwargs):
            session = scoped_session()
            autoflush = session.autoflush
            session.autoflush = False
            try:
                return fn(*args, **kwargs)
            finally:
                session.autoflush = autoflush

        return update_wrapper(go, fn)

    return decorate
