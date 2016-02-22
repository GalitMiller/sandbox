# -*- coding: utf-8 -*-

from re import escape

from app.utils.regex import re_choices

from ..constants import RULE_ACTIONS, DIRECTIONS


ANY_LITERAL = 'any'

COMMENT_LITERAL = '#'
EXCLUSION_LITERAL = '!'

SEQUENCE_START_LITERAL, SEQUENCE_END_LITERAL = '[', ']'
LIST_DELIMITER_LITERAL = ','
RANGE_DELIMITER_LITERAL = ':'

OPTIONS_START_LITERAL, OPTIONS_END_LITERAL = '(', r')'
OPTION_DELIMITER_LITERAL = ';'


IPv4_GRAMMAR = """
(?:
    (?:[01]?\d\d?|2[0-4]\d|25[0-5])\.
){3}
(?:
    [01]?\d\d?|2[0-4]\d|25[0-5]
)
(?:
    /(?:16|24)
)?
"""

VARIABLE_GRAMMAR = """
\$[^\$\s]+
"""

# TODO: define more datailed grammar
HOST_SEQUENCE_GRAMMAR = """
(?:
    {start}.*{end}
    |
    .*
)
""".format(
    start=escape(SEQUENCE_START_LITERAL),
    end=escape(SEQUENCE_END_LITERAL),
)

HOST_GRAMMAR = """
(?:
    (?:{exclusion}\s?)?{values}|{any}
)
""".format(
    exclusion=escape(EXCLUSION_LITERAL),
    values=re_choices(
        IPv4_GRAMMAR,
        VARIABLE_GRAMMAR,
        HOST_SEQUENCE_GRAMMAR
    ),
    any=escape(ANY_LITERAL),
)

# TODO: define more datailed grammar
PORT_SEQUENCE_GRAMMAR = """
(?:
    {start}.*{end}
    |
    .*
)
""".format(
    start=escape(SEQUENCE_START_LITERAL),
    end=escape(SEQUENCE_END_LITERAL),
)

PORT_GRAMMAR = """
(?:
    (?:{exclusion}\s?)?{values}|{any}
)
""".format(
    exclusion=escape(EXCLUSION_LITERAL),
    values=re_choices(
        """
        [0-9]{1,4}
        |[1-5][0-9]{4}
        |6[0-4][0-9]{3}
        |65[0-4][0-9]{2}
        |655[0-2][0-9]
        |6553[0-5]
        """,
        VARIABLE_GRAMMAR,
        PORT_SEQUENCE_GRAMMAR,
    ),
    any=escape(ANY_LITERAL),
)

DIRECTION_GRAMMAR = re_choices(*DIRECTIONS._asdict().values())

OPTION_GRAMMAR = """
\w+
(?::\s?.+)?
{delimiter}
""".format(
    delimiter=escape(OPTION_DELIMITER_LITERAL),
)

RULE_GRAMMAR = """
^
(?P<action>{actions})
\s+
(?P<protocol>\w+)
\s+
(?P<src_host>{host})
\s+
(?P<src_port>{port})
\s+
(?P<direction>{directions})
\s+
(?P<dst_host>{host})
\s+
(?P<dst_port>{port})
\s+
{options_start}
  (?P<options>
    ({option})+
   )
{options_end}
$
""".format(
    actions=re_choices(*RULE_ACTIONS._asdict().values()),
    host=HOST_GRAMMAR,
    port=PORT_GRAMMAR,
    directions=DIRECTION_GRAMMAR,
    option=OPTION_GRAMMAR,
    options_start=escape(OPTIONS_START_LITERAL),
    options_end=escape(OPTIONS_END_LITERAL),
)
