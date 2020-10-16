#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the common utilities.
"""

from sysinv.common import utils
from sysinv.tests import base


class TestCommonUtilities(base.TestCase):
    def test_format_hex_grouped(self):
        TEST_MASKS = [
            {'value': 0xabcdef1234, 'sep': ',', 'chunk': 8,
             'expect': 'ab,cdef1234'},
            {'value': 0xabcdef1234, 'sep': ',', 'chunk': 4,
             'expect': 'ab,cdef,1234'},
            {'value': 0xabcdef1234, 'sep': ',', 'chunk': 2,
             'expect': 'ab,cd,ef,12,34'},
            {'value': 0xabcdef1234567890, 'sep': ',', 'chunk': 8,
             'expect': 'abcdef12,34567890'},
            {'value': 0xabcdef1234567890cab, 'sep': ',', 'chunk': 8,
             'expect': 'abc,def12345,67890cab'},
            {'value': 0xabcdef1234, 'sep': ':', 'chunk': 4,
             'expect': 'ab:cdef:1234'},
            {'value': 0x300000003, 'sep': ',', 'chunk': 8, 'expect':
             '3,00000003'},
            {'value': 0x8008, 'sep': ',', 'chunk': 8,
             'expect': '8008'},
            {'value': 0x8008, 'sep': ',', 'chunk': 2,
             'expect': '80,08'},
            {'value': 0x3, 'sep': ',', 'chunk': 8,
             'expect': '3'},
            {'value': 0x0, 'sep': ',', 'chunk': 8,
             'expect': '0'},
        ]
        for t in TEST_MASKS:
            result = utils.format_hex_grouped(
                        t['value'], sep=t['sep'], chunk=t['chunk'])
            self.assertEqual(result, t['expect'])
