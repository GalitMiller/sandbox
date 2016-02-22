# -*- coding: utf-8 -*-

from collections import namedtuple

from app.utils.constants import create_constants


POLICY_TYPES = namedtuple('POLICY_TYPES', [
    'PRO_ACCEL_CATEGORIES', 'PRO_ACCEL_ALL', 'PRO_ACCEL_HIGH',
    'PRO_ACCEL_HIGH_N_MEDIUM', 'PRO_ACCEL_LOW', 'PRO_ACCEL_CUSTOM',
])(
    'proAccelCategories', 'proAccelAll', 'proAccelHigh',
    'proAccelHighMedium', 'proAccelLow', 'proAccelCustom',
)

POLICY_DEPLOYMENT_ACTIONS = create_constants('POLICY_DEPLOYMENT_ACTIONS', (
    'alert', 'block',
))
