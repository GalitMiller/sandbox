# -*- coding: utf-8 -*-

import abc
import logging
import string

from isotopic_logging import autoprefix_injector
from schematics.exceptions import ValidationError

from app.utils.encoding import smart_str
from app.utils import six
from app.utils.six.moves import filter, map
from app.utils.transforms import to_string_list

from .grammar import COMMENT_LITERAL
from .objects import (
    RuleInfo, RuleReferenceTypeInfo, RuleClassTypeInfo, RuleParsingResult,
    RuleClassTypeParsingResult, RuleReferenceTypeParsingResult,
)


LOG = logging.getLogger(__name__)


class StreamParser(six.with_metaclass(abc.ABCMeta, object)):
    """
    Returns iterable, where each item is an instance of class defined by
    'result_class' property produced per each string source.
    """

    def __call__(self, stream):
        with autoprefix_injector():
            lines = map(string.strip, stream)
            lines = filter(self._is_meaningful_line, lines)
            return map(self._parse_single_line, lines)

    @abc.abstractmethod
    def parse_line(self, line):
        pass

    @abc.abstractproperty
    def result_class(self):
        pass

    @staticmethod
    def _is_meaningful_line(line):
        return line and not line.startswith(COMMENT_LITERAL)

    def _parse_single_line(self, line):
        result = self.result_class()
        result.source = line

        try:
            result.info = self.parse_line(line)
        except ValidationError as e:
            messages = to_string_list(e.messages)
            reason = '\n'.join(messages)
            self._on_error(line, reason=reason)

            result.messages = e.messages
        except Exception as e:
            reason = smart_str(e)
            self._on_error(line, reason=reason)

            result.messages = [reason, ]
        else:
            result.is_valid = True
        finally:
            return result

    @staticmethod
    def _on_error(line, reason):
        with autoprefix_injector() as inj:
            LOG.error(inj.mark(
                "Failed to parse line '{line}'. Reason:\n{reason}"
                .format(line=line, reason=reason)))


parse_rule_string = RuleInfo.from_string
parse_rule_reference_type_string = RuleReferenceTypeInfo.from_string
parse_rule_class_type_string = RuleClassTypeInfo.from_string


class RuleStreamParser(StreamParser):
    parse_line = parse_rule_string
    result_class = RuleParsingResult


class RuleReferenceTypeStreamParser(StreamParser):
    parse_line = parse_rule_reference_type_string
    result_class = RuleReferenceTypeParsingResult


class RuleClassTypeStreamParser(StreamParser):
    parse_line = parse_rule_class_type_string
    result_class = RuleClassTypeParsingResult


parse_rule_stream = RuleStreamParser()
parse_rule_reference_type_stream = RuleReferenceTypeStreamParser()
parse_rule_class_type_stream = RuleClassTypeStreamParser()
