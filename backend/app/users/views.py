# -*- coding: utf-8 -*-

from flask import redirect, request, url_for
from flask.ext.login import (
    current_user, login_user, login_required, logout_user,
)
from werkzeug.local import LocalProxy

from app import app, api_manager
from app.core.views.api import api_url, api_url_prefix, APISuccess
from app.core.views.cache import never_cache

from .decorators import api_login_required
from .models import SnorbyUser, User
from .serializers import (
    SNORBY_USER_INCLUDE_COLUMNS, USER_INCLUDE_COLUMNS,
    user_serializer
)


api_manager.create_api(
    model=SnorbyUser,
    collection_name='snorby_users',
    include_columns=SNORBY_USER_INCLUDE_COLUMNS,
    methods=['GET', ],
    url_prefix=api_url_prefix(version=1),
)
api_manager.create_api(
    model=User,
    collection_name='users',
    include_columns=USER_INCLUDE_COLUMNS,
    methods=['GET', 'POST', 'DELETE', 'PUT', ],
    url_prefix=api_url_prefix(version=1),
)


@app.route(api_url('/current_user', version=1), methods=['GET', ])
@never_cache
@api_login_required
def current_user_profile():
    user = (current_user._get_current_object()
            if isinstance(current_user, LocalProxy)
            else current_user)
    return APISuccess(user_serializer(user))


@app.route('/users/login', methods=['GET', 'POST'])
def login():
    """
    Mock login implementation, for testing purposes. Real users will use
    Bricata login page.
    """
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(login=username).first()

        if user:
            remember_me = request.form.get('remember_me', False)
            login_user(user, remember=remember_me)

            url = redirect(request.args.get('next') or url_for('index'))
            response = app.make_response(url)

            return response

    return """
        <form action="" method="post">

          <p><input type="text" name="username" title="Username"></p>
          <p>
            <input type="checkbox" id="remember_me" name="remember_me">
            <label for="remember_me">Remember me</label>
          </p>
          <p><input type="submit" value="Login"></p>
        </form>
    """


@app.route('/users/logout')
@login_required
def logout():
    logout_user()
    url = redirect(request.args.get('next') or url_for('index'))
    response = app.make_response(url)
    return response
