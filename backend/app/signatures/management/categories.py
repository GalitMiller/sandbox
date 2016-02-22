# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from flask.ext.script import Command, Option

from app.db import db
from app.signatures.models import SignatureCategory
from app.utils.encoding import smart_str


LOG = logging.getLogger(__name__)


class CreateSignatureCategory(Command):
    """
    Create new signature category.
    """
    name = "create"

    option_list = (
        Option(
            '-n', '--name',
            help="Category name.",
            required=True,
        ),
    )

    def run(self, name, description=None):
        name = smart_str(name).strip()

        if description is not None:
            description = smart_str(description).strip()

        category = SignatureCategory(name=name, description=description)
        db.session.add(category)
        db.session.commit()

        LOG.debug("Signature category '{name}' is created (id={id})."
                  .format(name=name, id=category.id))

        return category
