# -*- coding: utf-8 -*-

import re

from .grammar import RULE_GRAMMAR


rule_matcher = re.compile(RULE_GRAMMAR, re.VERBOSE)
