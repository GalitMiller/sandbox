# -*- coding: utf-8 -*-

import collections
import itertools

from .encoding import smart_str
from .six import string_types, iteritems
from .six.moves import map


def flatten_values(values):
    """
    Used to flatten values mainly returned by SQLAlchemy.
    """
    return list(itertools.chain(*values))


def to_string_list(value, delimiter=" - "):
    """
    Process object recursively and convert its contents to a flat list of
    strings.
    """
    if (
        isinstance(value, collections.Iterable)
        and not isinstance(value, string_types)
    ):
        if isinstance(value, dict):
            result = []

            for k, v in iteritems(value):
                k = smart_str(k)
                values = to_string_list(v)
                if k:
                    result.extend([
                        "{0}{1}{2}".format(k, delimiter, x)
                        for x in values
                    ])
                else:
                    result.extend(values)

            return result
        else:
            return flatten_values(map(to_string_list, value))
    else:
        return [smart_str(value), ]


def objects_to_string_stream(objects, converter, delimiter="\n"):
    return (converter(x) + delimiter for x in objects)
