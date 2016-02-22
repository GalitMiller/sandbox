# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from flask.ext.script import Command, Option

from app.db import db
from app.signatures.models import SignatureProtocol
from app.utils.encoding import smart_str


LOG = logging.getLogger(__name__)


class CreateSignatureProtocol(Command):
    """
    Create new signature protocol.
    """
    name = "create"

    option_list = (
        Option(
            '-n', '--name',
            help="Protocol name.",
            required=True,
        ),
    )

    def run(self, name):
        name = smart_str(name).strip()

        protocol = SignatureProtocol(name=name)
        db.session.add(protocol)
        db.session.commit()

        LOG.debug("Signature protocol '{name}' is created (id={id})."
                  .format(name=name, id=protocol.id))

        return protocol
