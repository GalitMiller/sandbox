# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
import re

from base64 import b64decode

from flask import request, json
from flask.ext.login import current_user, login_user, logout_user
from flask.ext.restless import ProcessingException

from .models import User


LOG = logging.getLogger(__name__)


def login_required_preprocessor(*args, **kwargs):
    """
    Auth function used by APIManager. Check if user already logged in.
    """
    # FIXME: this is part of integration with Bricata RoR code:
    # TODO: refactor
    load_user_from_bricata_cookie()

    if not current_user.is_authenticated():
        raise ProcessingException(description="Not authenticated!", code=401)


def load_user_from_bricata_cookie():
    """
    Login user using data from _bricata_session cookie, which is set by Ruby on
    Rails app.

    This is cheap and insecure session checking for integration with Bricata
    RoR app for demo only. See https://gist.github.com/ewr/2029404
    """
    # TODO: use more smaller try...except blocks instead huge one to make
    #       debugging more easier
    try:
        # Load cookie without digest
        cookie = request.cookies.get('_bricata_session').split("--")[0]
        cookie = re.sub('%3D', '=', cookie)  # Unescape URL encoding

        # Decode RoR cookie
        bricata_session = json.loads(b64decode(cookie))

        # TODO: FIXME: validate cookie checksum using same mechanism and secret
        #       key as RoR.

        # Get user from cookie
        user_id = bricata_session['warden.user.user.key'][1][0]

        user = User.query.get(int(user_id))
        login_user(user)
    except Exception as e:
        logout_user()
        LOG.debug("Authentication failed: bad _bricata_session cookie: {e}"
                  .format(e=e))
        raise ProcessingException("Unauthorized", 401)
    else:
        LOG.debug("Current user: '{0}'".format(current_user.login))
