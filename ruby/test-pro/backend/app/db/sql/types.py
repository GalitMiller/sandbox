# -*- coding: utf-8 -*-

from sqlalchemy.sql.sqltypes import Boolean


class OmnivorousBoolean(Boolean):
    """
    Converts any native value to boolean.
    """

    def result_processor(self, dialect, coltype):
        if dialect.supports_native_boolean:
            return None
        else:
            return lambda x: bool(x)
