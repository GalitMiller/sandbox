# -*- coding: utf-8 -*-

import unittest

from collections import OrderedDict

from ..transforms import flatten_values, to_string_list


class TransformsTestCase(unittest.TestCase):

    def test_flatten_values(self):
        actual = flatten_values([(1,), (2, )])
        expected = [1, 2, ]
        self.assertGreaterEqual(actual, expected)


class ToStringListTestCase(unittest.TestCase):

    def test_non_iterable_to_string_list(self):
        self.assertEqual(to_string_list(None), ["None", ])
        self.assertEqual(to_string_list(1), ["1", ])
        self.assertEqual(to_string_list("foo"), ["foo", ])

    def test_iterable_to_string_list(self):
        iterable = [None, ]
        self.assertEqual(to_string_list(iterable), ["None", ])

        iterable = (None, )
        self.assertEqual(to_string_list(iterable), ["None", ])

        iterable = {None, }
        self.assertEqual(to_string_list(iterable), ["None", ])

    def test_dict_to_string_list(self):
        data = OrderedDict((
            (1, "one"),
            (None, "two"),
            ("foo",  "three"),
            ("", "four"),
        ))
        expected = [
            "1 - one",
            "None - two",
            "foo - three",
            "four",
        ]
        self.assertEqual(to_string_list(data), expected)

    def test_nested_to_string_list(self):
        data = [
            None,
            1,
            "foo",
            [None, ],
            (None, ),
            {None, },
            OrderedDict((
                (1, "one"),
                (None, "two"),
                ("foo", "three"),
                ("", "four"),
                ("list", [
                    "item1",
                    "item2",
                    OrderedDict((
                        ("sublist", [
                            "subitem1",
                            "subitem2",
                        ]),
                    )),
                ]),
            ))
        ]
        expected = [
            "None",
            "1",
            "foo",
            "None",
            "None",
            "None",
            "1 - one",
            "None - two",
            "foo - three",
            "four",
            "list - item1",
            "list - item2",
            "list - sublist - subitem1",
            "list - sublist - subitem2",
        ]
        self.assertEqual(to_string_list(data), expected)
