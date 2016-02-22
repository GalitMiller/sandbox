# -*- coding: utf-8 -*-

from datetime import datetime

from flask import current_app
from flask.ext.login import current_user
from flask.sessions import SecureCookieSessionInterface

from app.utils.http import make_cookie


class BricataSecureCookieSessionInterface(SecureCookieSessionInterface):
    """
    Extend life of _bricata_session cookie.
    """

    def open_session(self, app, request):
        """
        Load _bricata_session cookie to return it later.
        """
        session = (super(BricataSecureCookieSessionInterface, self)
                   .open_session(app, request))
        session.bricata_cookie = request.cookies.get('_bricata_session')
        return session

    def save_session(self, app, session, response):
        """
        Update time of life for _bricata_session without any modification of
        cookie.
        """
        # if not session.bricata_cookie and current_user.is_authenticated():
        #     session.bricata_cookie = make_session_cookie(current_user.id)

        cookie = (None
                  if current_user.is_anonymous() else
                  session.bricata_cookie)
        set_session_cookie(response, '_bricata_session', cookie)

        (super(BricataSecureCookieSessionInterface, self)
         .save_session(app, session, response))


def make_session_cookie(user_id):
    """
    Make mock bricata session cookie for development purposes.
    """
    return make_cookie({
        'session_id': "ae70f6a7210296859914885d9235fa8f",
        '_csrf_token': "N9+Lwuz20EUUldFbj3/Oou+wBRdiDYQxLRthv/Qkijk=",
        'warden.user.user.key': [
            "User",
            [user_id, ],
            "$2a$10$4T9lVqCA9BfrS02TpEZX1.",
        ],
    })


def set_session_cookie(response, name, value=None):
    expire_at = (datetime.utcnow() + current_app.permanent_session_lifetime
                 if value else
                 0)
    response.set_cookie(name,
                        value or '',
                        expires=expire_at,
                        httponly=True,
                        path="/")
