# -*- coding: utf-8 -*-

from flask.ext.restless.helpers import to_dict
from functools import partial


SNORBY_USER_INCLUDE_COLUMNS = ['id', 'name', 'email', 'enabled', 'admin', ]
snorby_user_serializer = partial(to_dict, include=SNORBY_USER_INCLUDE_COLUMNS)

USER_INCLUDE_COLUMNS = ['id', 'login', 'name', 'email', 'role', 'active', ]
user_serializer = partial(to_dict, include=USER_INCLUDE_COLUMNS)
