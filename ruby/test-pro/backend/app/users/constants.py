# -*- coding: utf-8 -*-

from app.utils.constants import create_constants


USER_ROLES = create_constants('USER_ROLES', (

    # Analyst user account for readonly user access
    'analyst',

    # Operator user account for policy configuration, event viewing, and
    # policy updates
    'operator',

    # Administrative user account for full access to creating users,
    # configuration, and policy updates.
    'admin',
))
