# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
import operator
import random
import string

from schematics import types
from schematics.exceptions import ValidationError
from schematics.models import Model

from app.utils.encoding import smart_bytes
from app.utils.exceptions import NON_FIELD_ERROR
from app.utils.six.moves import filter, map, range
from app.utils.transforms import to_string_list

from ..constants import DIRECTIONS, RULE_ACTIONS
from ..utils import generate_sid

from .grammar import (
    ANY_LITERAL, OPTIONS_START_LITERAL, OPTIONS_END_LITERAL,
    OPTION_DELIMITER_LITERAL,
)
from .helpers import rule_matcher


LOG = logging.getLogger(__name__)


class RuleOption(Model):
    key = types.StringType(
        required=True,
    )
    value = types.BaseType()

    def to_string(self):
        return ("{0}:{1}".format(self.key, self.value)
                if self.value is not None
                else self.key)

    @classmethod
    def from_string(cls, s):
        try:
            key, value = s.split(':', 1)
        except ValueError:
            key, value = s.strip(), None
        else:
            key, value = key.strip(), value.strip()
        finally:
            return cls(dict(key=key, value=value))

    def __repr__(self):
        return smart_bytes("<RuleOption '{key}={value}'>".format(**self))


class RuleOptionList(list):

    @classmethod
    def from_string(cls, s):
        chunks = s.split(OPTION_DELIMITER_LITERAL)
        chunks = map(string.strip, chunks)
        chunks = filter(bool, chunks)

        options = map(RuleOption.from_string, chunks)
        return cls(options)

    def to_string(self):
        if self:
            values = map(operator.methodcaller('to_string'), self)
            values = (OPTION_DELIMITER_LITERAL + " ").join(values)
            values = values + OPTION_DELIMITER_LITERAL
        else:
            values = ""

        return values

    def values(self):
        return list(self.itervalues())

    def itervalues(self):
        return map(operator.attrgetter('value'), self)


class RuleReferenceInfo(Model):
    type_name = types.StringType(
        required=True,
        min_length=1,
    )
    value = types.StringType(
        required=True,
        min_length=1,
    )

    @classmethod
    def from_string(cls, s):
        type_name, value = s.split(',', 1)

        info = cls({
            'type_name': type_name.strip(),
            'value': value.strip(),
        })
        info.validate()

        return info

    def to_string(self):
        return "{type_name},{value}".format(**self)

    def __repr__(self):
        return smart_bytes("<RuleReferenceInfo '{type_name}:{value}'>"
                           .format(**self))

    def __hash__(self):
        s = (self.type_name + self.value).lower()
        return hash(s)


class RuleReferenceInfoList(list):

    @classmethod
    def from_strings(cls, strings):
        return cls(map(RuleReferenceInfo.from_string, strings))

    def to_strings(self):
        return map(operator.methodcaller('to_string'), self)


class RuleReferenceInfoListType(types.BaseType):

    container_class = RuleReferenceInfoList

    def __init__(self, *args, **kwargs):
        super(RuleReferenceInfoListType, self).__init__(
            default=self.container_class(), *args, **kwargs
        )

    def _mock(self, context=None):
        return [
            RuleReferenceInfo.get_mock_object()
            for x in range(random.randint(0, 10))
        ]

    def to_primitive(self, value, context=None):
        if value:
            mapper = operator.methodcaller('to_primitive', context=context)
            return list(map(mapper, value))
        else:
            return value

    def to_native(self, value, context=None):
        return self.container_class(map(RuleReferenceInfo, value))

    def validate_contents(self, value):
        for item in value:
            item.validate()


class RuleReferenceTypeInfo(Model):
    name = types.StringType(
        required=True,
        min_length=1,
        max_length=255,
    )
    url_prefix = types.StringType(
        required=True,
        min_length=1,
        max_length=255,
    )

    @classmethod
    def from_string(cls, s):
        meaningful_part = s.split(": ", 1)[1]
        name, url_prefix = meaningful_part.split()

        info = cls({
            'name': name.strip(),
            'url_prefix': url_prefix.strip(),
        })
        info.validate()

        return info

    def to_string(self):
        return "config reference: {name:<9} {url_prefix}".format(**self)

    def __repr__(self):
        return smart_bytes("<RuleReferenceTypeInfo '{name}:{url_prefix}'>"
                           .format(**self))


class RuleClassTypeInfo(Model):
    name = types.StringType(
        required=True,
        min_length=1,
        max_length=255,
    )
    short_name = types.StringType(
        required=True,
        min_length=1,
        max_length=255,
    )
    priority = types.IntType(
        required=True,
        min_value=1,
        max_value=255,
    )

    @classmethod
    def from_string(cls, s):
        meaningful_part = s.split(": ", 1)[1]
        short_name, name, priority = meaningful_part.split(',')

        info = cls({
            'name': name,
            'short_name': short_name,
            'priority': priority,
        })
        info.validate()

        return info

    def to_string(self):
        return ("config classification: {short_name},{name},{priority}"
                .format(**self))

    def __repr__(self):
        return smart_bytes("<RuleClassTypeInfo '{short_name}'>".format(**self))


class RuleInfo(Model):
    action = types.StringType(
        choices=RULE_ACTIONS._asdict().values(),
        required=True,
    )
    protocol = types.StringType(
        required=True,
    )
    src_host = types.StringType()
    src_port = types.StringType()
    dst_host = types.StringType()
    dst_port = types.StringType()
    is_bidirectional = types.BooleanType(
        default=False,
    )
    message = types.StringType(
        required=True,
        min_length=1,
    )
    flow_control = types.StringType()
    content_control = types.StringType()
    class_type = types.StringType()
    priority = types.IntType(
        min_value=1,
        max_value=255,
    )
    sid = types.LongType(
        required=True,
    )
    gid = types.IntType(
        min_value=1,
        max_value=255,
    )
    revision = types.IntType(
        min_value=1,
    )
    reference_infos = RuleReferenceInfoListType()

    @classmethod
    def get_mock_object(cls, context=None, overrides=None):
        result = super(RuleInfo, cls).get_mock_object(context, overrides)
        result.sid = generate_sid()

        if result.flow_control:
            result.flow_control = "flow: " + result.flow_control + ";"

        if result.content_control:
            result.content_control = "content: " + result.content_control + ";"

        return result

    @classmethod
    def from_string(cls, s):
        from .preprocessors import preprocess_rule_parsed_data

        match = rule_matcher.match(s)
        if not match:
            raise ValidationError({
                NON_FIELD_ERROR: ["Invalid rule format.", ]
            })

        data = match.groupdict()
        preprocess_rule_parsed_data(data)

        info = cls(data)
        info.validate()

        return info

    def to_string(self):

        def _append_option(key, value):
            if value is not None:
                option = RuleOption({'key': key, 'value': value})
                value = option.to_string() + OPTION_DELIMITER_LITERAL
                raw_options.append(value)

        raw_options = []

        _append_option('msg', "\"{0}\"".format(self.message))

        if self.flow_control:
            raw_options.append(self.flow_control)

        if self.content_control:
            raw_options.append(self.content_control)

        for value in self.reference_infos.to_strings():
            _append_option('reference', value)

        _append_option('classtype', self.class_type)
        _append_option('priority', self.priority)
        _append_option('sid', self.sid)
        _append_option('gid', self.gid)
        _append_option('rev', self.revision)

        direction = (DIRECTIONS.BIDIRECTIONAL if self.is_bidirectional else
                     DIRECTIONS.UNIDIRECTIONAL)

        raw_options = (OPTIONS_START_LITERAL
                       + " ".join(raw_options)
                       + OPTIONS_END_LITERAL)

        return " ".join([
            self.action,
            self.protocol,
            self.src_host or ANY_LITERAL,
            self.src_port or ANY_LITERAL,
            direction,
            self.dst_host or ANY_LITERAL,
            self.dst_port or ANY_LITERAL,
            raw_options,
        ])

    def __repr__(self):
        return smart_bytes("<RuleInfo '{sid}'>".format(**self))


class ParsingResult(Model):
    """
    Base class for storing result of parsing of a single string.
    """
    source = types.StringType()
    is_valid = types.BooleanType(
        default=False,
    )
    info = types.BaseType()
    messages = types.BaseType()

    def __init__(self, *args, **kwargs):
        super(ParsingResult, self).__init__(*args, **kwargs)
        if not self.messages:
            self.messages = []

    def to_primitive(self):
        primitive = {
            'source': self.source,
            'is_valid': self.is_valid,
        }

        if self.messages:
            primitive['messages'] = to_string_list(self.messages)

        return primitive


class RuleParsingResult(ParsingResult):
    pass


class RuleClassTypeParsingResult(ParsingResult):
    pass


class RuleReferenceTypeParsingResult(ParsingResult):
    pass
