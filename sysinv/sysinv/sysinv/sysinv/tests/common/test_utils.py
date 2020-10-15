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

    def test_is_valid_domain_or_ip(self):
            SAMPLE_VALIDATION_URLS = (
                # Valid URL
                ('localhost', True),  # localhost
                ('localhost:5000', True),
                ('localhost/mirror/k8s.gcr.io', True),
                ('localhost:5000/mirror/k8s.gcr.io', True),
                ('10.10.10.1', True),  # IPv4
                ('10.10.10.1:5000', True),
                ('10.10.10.1/mirror/k8s.gcr.io', True),
                ('10.10.10.1:5000/mirror/k8s.gcr.io', True),
                ('2001:0db8:85a3:0000:0000:8a2e:0370:7334', True),  # IPv6
                ('[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:5000', True),
                ('[2001:0db8:85a3:0000:0000:8a2e:0370:7334]/mirror/k8s.gcr.io', True),
                ('[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:5000/mirror/k8s.gcr.io', True),
                ('g.com', True),  # domain
                ('www.g.com', True),
                ('g.com:5000', True),
                ('g.com/mirror/k8s.gcr.io', True),
                ('g.com:5000/mirror/k8s.gcr.io', True),
                ('g.com//mirror/k8s.gcr.io', True),
                ('has-dash.com', True),
                # Invalid URL
                ('localhost:22:5000', False),  # extra conlon
                ('10.10.10.10.1', False),  # IPv4 with extra segment
                ('10.10.10.1.', False),
                ('2001:0db8:85a3:0000:0000:8a2e:0370:7334:5000', False),  # IPv6 withextra segment
                ('.com', False),  # Domain name without enough labels
                ('mis-type,comma', False),
                ('extra space.com', False),  # Extra space in the middle
                ('has_trailing.com', False),
                ('hastrailing_.com', False),
                (' frontspace.com', False),
                ('backspace .com', False)
            )
            for url in SAMPLE_VALIDATION_URLS:
                self.assertEqual(utils.is_valid_domain_or_ip(url[0]), url[1])
