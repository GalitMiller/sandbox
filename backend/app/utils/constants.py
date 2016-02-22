# -*- coding: utf-8 -*-

from collections import namedtuple


def create_constants(container_name, values):
    fields = ' '.join([x.upper() for x in values])
    return namedtuple(container_name, fields)(*values)
