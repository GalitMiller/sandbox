# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from flask.ext.script import Command, Option

from app.db import db
from app.signatures.models import SignatureReferenceType
from app.utils.encoding import smart_str


LOG = logging.getLogger(__name__)


class CreateReferenceType(Command):
    """
    Create new reference type for signature references.
    """
    name = "create"

    option_list = (
        Option(
            '-n', '--name',
            help="Type name.",
            required=True,
        ),
        Option(
            '-p', '--url-prefix',
            help="URL prefix",
            dest='url_prefix',
        ),
    )

    def run(self, name, url_prefix):
        name = smart_str(name).strip()

        if url_prefix is not None:
            url_prefix = smart_str(url_prefix).strip()

        reference_type = SignatureReferenceType(
            name=name,
            url_prefix=url_prefix,
        )
        db.session.add(reference_type)
        db.session.commit()

        LOG.debug("Signature reference type '{name}' is created (id={id})."
                  .format(name=name, id=reference_type.id))

        return reference_type
