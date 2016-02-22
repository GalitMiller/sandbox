# -*- coding: utf-8 -*-

from schematics.exceptions import BaseError


class AnalysisError(BaseError):
    pass


class SignatureAnalysisError(AnalysisError):
    pass


class SignatureClassTypeAnalysisError(AnalysisError):
    pass


class SignatureReferenceTypeAnalysisError(AnalysisError):
    pass


class InvalidFileError(Exception):
    pass


class InvalidRulesFileError(InvalidFileError):
    pass


class InvalidRuleClassTypesFileError(InvalidFileError):
    pass


class InvalidRuleReferenceTypesFileError(InvalidFileError):
    pass
