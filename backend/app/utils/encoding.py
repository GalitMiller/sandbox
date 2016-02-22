# -*- coding: utf-8 -*-

import datetime

from decimal import Decimal

from app.utils import six


_PROTECTED_TYPES = six.integer_types + (
    type(None), float, Decimal, datetime.datetime, datetime.date,
    datetime.time,
)


def is_protected_type(obj):
    """Determine if the object instance is of a protected type.

    Objects of protected types are preserved as-is when passed to
    smart_str(strings_only=True).
    """
    return isinstance(obj, _PROTECTED_TYPES)


def smart_str(s, encoding='utf-8', strings_only=False, errors='strict'):
    """
    Returns a text object representing 's' — unicode on Python 2 and str on
    Python 3.

    If strings_only is True, don't convert (some) non-string-like objects.
    """
    # Handle the common case first for performance reasons.
    if isinstance(s, six.text_type):
        return s
    if strings_only and is_protected_type(s):
        return s
    try:
        if not isinstance(s, six.string_types):
            if six.PY3:
                if isinstance(s, bytes):
                    s = six.text_type(s, encoding, errors)
                else:
                    s = six.text_type(s)
            elif hasattr(s, '__unicode__'):
                s = six.text_type(s)
            else:
                s = six.text_type(bytes(s), encoding, errors)
        else:
            # Note: We use .decode() here, instead of six.text_type(s,
            # encoding, errors), so that if s is a SafeBytes, it ends up being
            # a SafeText at the end.
            s = s.decode(encoding, errors)
    except UnicodeDecodeError:
        if not isinstance(s, Exception):
            raise
        else:
            # If we get to here, the caller has passed in an Exception
            # subclass populated with non-ASCII bytestring data without a
            # working unicode method. Try to handle this without raising a
            # further exception by individually forcing the exception args
            # to unicode.
            s = ' '.join(smart_str(arg, encoding, strings_only, errors)
                         for arg in s)
    return s


def smart_bytes(s, encoding='utf-8', strings_only=False, errors='strict'):
    """
    Returns a bytestring version of 's', encoded as specified in 'encoding'.

    If strings_only is True, don't convert (some) non-string-like objects.
    """
    # Handle the common case first for performance reasons.
    if isinstance(s, bytes):
        if encoding == 'utf-8':
            return s
        else:
            return s.decode('utf-8', errors).encode(encoding, errors)

    if strings_only and is_protected_type(s):
        return s

    if isinstance(s, six.memoryview):
        return bytes(s)

    if not isinstance(s, six.string_types):
        try:
            if six.PY3:
                return six.text_type(s).encode(encoding)
            else:
                return bytes(s)
        except UnicodeEncodeError:
            if isinstance(s, Exception):
                # An Exception subclass containing non-ASCII data that doesn't
                # know how to print itself properly. We shouldn't raise a
                # further exception.
                return b' '.join(smart_bytes(arg, encoding, strings_only, errors)
                                 for arg in s)
            return six.text_type(s).encode(encoding, errors)
    else:
        return s.encode(encoding, errors)
