# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from flask.ext.script import Command, Option

from app.db import db
from app.signatures.models import SignatureSeverity
from app.utils.encoding import smart_str


LOG = logging.getLogger(__name__)


class CreateSignatureSeverity(Command):
    """
    Create new signature severity.
    """
    name = "create"

    option_list = (
        Option(
            '-n', '--name',
            help="Severity name.",
            required=True,
        ),
        Option(
            '-t', '--text-color',
            help="Text color.",
            default="#FFF",
            dest="text_color",
        ),
        Option(
            '-b', '--bg-color',
            help="Background color.",
            default="#DDD",
            dest="bg_color",
        ),
        Option(
            '-w', '--weight',
            help="Weight. Default: 1.",
            type=int,
            default=1,
        ),
        Option(
            '--is-predefined',
            help="Defines whether this severity is predefined. Predefined "
                 "severities cannot be deleted by UI users. Default: false.",
            dest='is_predefined',
            action='store_true',
        ),
    )

    def run(self, name, text_color, bg_color, weight, is_predefined):
        name = smart_str(name).strip()
        text_color = smart_str(text_color).strip()
        bg_color = smart_str(bg_color).strip()

        severity = SignatureSeverity(
            name=name,
            text_color=text_color,
            bg_color=bg_color,
            weight=weight,
            is_predefined=is_predefined,
        )
        db.session.add(severity)
        db.session.commit()

        LOG.debug("Signature severity '{name}' is created (id={id})."
                  .format(name=name, id=severity.id))

        return severity
