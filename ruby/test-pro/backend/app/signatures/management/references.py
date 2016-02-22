# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from flask.ext.script import Command, Option

from app.db import db
from app.signatures.models import SignatureReference
from app.utils.encoding import smart_str


LOG = logging.getLogger(__name__)


class CreateReference(Command):
    """
    Create new reference for a signature.
    """
    name = "create"

    option_list = (
        Option(
            '-s', '--signature',
            help="Signature this reference belongs to (signature ID).",
            dest='signature_id',
            type=int,
            required=True,
        ),
        Option(
            '-t', '--reference-type',
            help="SignatureReference type (type ID).",
            dest='reference_type_id',
            type=int,
            required=True,
        ),
        Option(
            '-v', '--value',
            help="SignatureReference value",
            required=True,
        ),
    )

    def run(self, signature_id, reference_type_id, value):
        value = smart_str(value).strip()

        reference = SignatureReference(
            signature_id=signature_id,
            reference_type_id=reference_type_id,
            value=value,
        )
        db.session.add(reference)
        db.session.commit()

        LOG.debug(
            "Signature reference of type '{type_name}' is created with value "
            "'{value}' for signature '{signature_name}' (id={id})."
            .format(type_name=reference.reference_type.name,
                    signature_name=reference.signature.name,
                    value=value,
                    id=reference.id))

        return reference
