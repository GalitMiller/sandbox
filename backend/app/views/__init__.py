# -*- coding: utf-8 -*-

from app import app, api_manager
from app.db import db
from app.users.preprocessors import login_required_preprocessor

from app.policies import views as policy_views
from app.sensors import views as sensor_views
from app.signatures import views as signature_views
from app.users import views as user_views

from . import error_handlers, web


# TODO: switch to blueprints

api_manager.init_app(
    app,
    flask_sqlalchemy_db=db,
    preprocessors={
        'GET_SINGLE': [login_required_preprocessor, ],
        'GET_MANY': [login_required_preprocessor, ],
        'POST': [login_required_preprocessor, ],
        'PATCH_MANY': [login_required_preprocessor, ],
        'DELETE': [login_required_preprocessor, ],
        'DELETE_MANY': [login_required_preprocessor, ],
    },
)
