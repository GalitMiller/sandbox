# -*- coding: utf-8 -*-

import unittest

from freezegun import freeze_time

from ..utils import generate_sid_base


class UtilsTestCase(unittest.TestCase):

    @freeze_time("2015-04-20")
    def test_generate_sid(self):
        self.assertEqual(generate_sid_base(), 2015042000)
