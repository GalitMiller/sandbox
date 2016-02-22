# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from flask.ext.script import Command, Option

from app.db import db
from app.signatures.models import SignatureClassType
from app.utils.encoding import smart_str


LOG = logging.getLogger(__name__)


class CreateSignatureClassType(Command):
    """
    Create new signature class type.
    """
    name = "create"

    option_list = (
        Option(
            '-n', '--name',
            help="Type name.",
            required=True,
        ),
        Option(
            '-s', '--short-name',
            help="Type short name.",
            dest='short_name',
            required=True,
        ),
        Option(
            '-p', '--priority',
            help="Priority. Default: 1.",
            type=int,
            default=1,
        ),
    )

    def run(self, name, short_name, priority):
        name = smart_str(name).strip()
        short_name = smart_str(short_name).strip()

        class_type = SignatureClassType(
            name=name,
            short_name=short_name,
            priority=priority,
        )
        db.session.add(class_type)
        db.session.commit()

        LOG.debug("Signature class type '{name}' is created (id={id})."
                  .format(name=name, id=class_type.id))

        return class_type
