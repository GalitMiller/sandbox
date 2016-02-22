# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from slugify import slugify

from app.config import RULES_PRIMARY_FILE_EXTENSION
from app.utils.text import generate_prefixed_filename


LOG = logging.getLogger(__name__)


def generate_policy_rules_filename(policy):
    prefix = slugify("policy " + policy.name,
                     to_lower=True,
                     separator='_')
    return generate_prefixed_filename(prefix, RULES_PRIMARY_FILE_EXTENSION)
