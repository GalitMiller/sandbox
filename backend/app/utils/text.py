# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import datetime

from slugify import slugify

from .memoize import memoize


def slug_to_name(value):
    return slugify(value, separator=' ', to_lower=True).capitalize()


@memoize
def get_date_format(separator):
    return separator.join(["%Y", "%m", "%d", "%H", "%M", "%S"])


def generate_filename(extension, separator='_'):
    date_format = get_date_format(separator)
    date_str = datetime.datetime.utcnow().strftime(date_format)
    return "{date}.{extension}".format(date=date_str, extension=extension)


def generate_prefixed_filename(prefix, extension, separator='_'):
    prefix = slugify(prefix, separator=separator)
    filename = generate_filename(extension, separator)
    return "{0}{1}{2}".format(prefix, separator, filename)
