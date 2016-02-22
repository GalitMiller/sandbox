# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import operator

from functools import partial

from app.config import SNORBY_DB_NAME
from app.db import db
from app.utils.memoize import memoize
from app.utils.six.moves import map
from app.utils.transforms import objects_to_string_stream

from .constants import SEVERITY_LEVEL_TO_PRIORITY_MAP


def signature_references_from_infos(reference_infos):
    """
    Convert list of 'RuleReferenceInfo' to list of 'SignatureReference'.
    """
    from .models import SignatureReference
    return map(SignatureReference.from_info, reference_infos)


severity_level_to_priority = SEVERITY_LEVEL_TO_PRIORITY_MAP.get


@memoize
def priority_to_severity_level(priority):
    """
    Returns priority based on severity level.
    """
    assert priority > 0, "Priority must be greater than 0."

    priority = min(priority, SEVERITY_LEVEL_TO_PRIORITY_MAP.LOW)

    for severity_level, value in SEVERITY_LEVEL_TO_PRIORITY_MAP.items():
        if value == priority:
            return severity_level


signatures_to_rules = partial(
    objects_to_string_stream,
    converter=operator.methodcaller('to_rule'),
    delimiter="\n\n",
)

signature_reference_types_to_strings = partial(
    objects_to_string_stream,
    converter=operator.methodcaller('to_string'),
)

signature_class_types_to_strings = partial(
    objects_to_string_stream,
    converter=operator.methodcaller('to_string'),
)


def snorby_signature_ids_by_sid(sid):
    """
    This helper executes raw SQL. It would be better to define a SQLAlchemy
    model named 'SnorbySignature' and to use it. But both Snorby's and our
    tables for signatures are named as 'signature'. SQLAlchemy does not know
    how to work with tables which have same name even if they are binded to
    different databases. So, to define SQLAlchemy model for Snorby's
    signatures, we will need to change name of our table (we do not modify
    Snorby's DB under any circumstances) and create a migration for that. Such
    approach is a real overkill for such little helper.
    """
    query = (
        "select signature.sig_id "
        "from {db_name}.signature "
        "where signature.sig_sid = '{sid}';"
        .format(db_name=SNORBY_DB_NAME, sid=sid)
    )
    rows = db.engine.execute(query)
    return map(operator.itemgetter(0), rows)
