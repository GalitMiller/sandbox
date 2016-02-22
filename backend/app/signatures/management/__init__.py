# -*- coding: utf-8 -*-
"""
Perform signature-related operations.
"""

from flask.ext.script import Manager

from .categories import CreateSignatureCategory
from .class_types import CreateSignatureClassType
from .protocols import CreateSignatureProtocol
from .reference_types import CreateReferenceType
from .references import CreateReference
from .severities import CreateSignatureSeverity
from .signatures import CreateSignature, ImportSignatures, GenerateSignatures


__all__ = [
    'categories', 'class_types', 'severities', 'references', 'reference_types',
    'protocols', 'CreateSignature', 'ImportSignatures', 'GenerateSignatures',
]
__namespace__ = "signatures"


categories = Manager(usage="Manage signature categories.")
categories.add_command(CreateSignatureCategory.name, CreateSignatureCategory)

class_types = Manager(usage="Manage signature class types.")
class_types.add_command(CreateSignatureClassType.name,
                        CreateSignatureClassType)

severities = Manager(usage="Manage signature severities.")
severities.add_command(CreateSignatureSeverity.name, CreateSignatureSeverity)

references = Manager(usage="Manage signature references.")
references.add_command(CreateReference.name, CreateReference)

reference_types = Manager(usage="Manage signature reference types.")
reference_types.add_command(CreateReferenceType.name, CreateReferenceType)

protocols = Manager(usage="Manage signature protocols.")
protocols.add_command(CreateSignatureProtocol.name, CreateSignatureProtocol)
