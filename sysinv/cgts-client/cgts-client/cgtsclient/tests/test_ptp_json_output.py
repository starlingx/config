# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import os
import sys

from cgtsclient.common import utils
from cgtsclient.tests import utils as test_utils
from six.moves import cStringIO as StringIO
from unittest import mock


class TruncateJsonTest(test_utils.BaseTestCase):

    def setUp(self):
        super(TruncateJsonTest, self).setUp()
        # Reset hint flag between tests
        utils._truncate_json_str._hint_shown = False

    def test_short_value_unchanged(self):
        """Values <= max_len pass through unchanged."""
        val = '{"key": "value"}'
        self.assertEqual(utils._truncate_json_str(val, max_len=100), val)

    def test_long_non_json_unchanged(self):
        """Long values that are not valid JSON pass through unchanged."""
        val = "x" * 200
        self.assertEqual(utils._truncate_json_str(val, max_len=100), val)

    def test_long_dict_repr_no_embedded_json_unchanged(self):
        """Python dict repr without embedded JSON passes through."""
        val = "{'global': [" + "'param=val', " * 50 + "]}"
        self.assertGreater(len(val), 100)
        self.assertEqual(utils._truncate_json_str(val, max_len=100), val)

    def test_long_json_truncated(self):
        """Valid JSON object > max_len is truncated."""
        config = {"global": {"key_%d" % i: "val" for i in range(50)}}
        val = json.dumps(config)
        self.assertGreater(len(val), 100)
        result = utils._truncate_json_str(val, max_len=100)
        self.assertTrue(result.endswith("..."))
        self.assertEqual(len(result), 103)  # 100 + "..."

    def test_long_json_not_starting_with_brace_unchanged(self):
        """Valid JSON that doesn't start with '{' is not truncated."""
        val = json.dumps(["item"] * 100)
        self.assertGreater(len(val), 100)
        self.assertEqual(utils._truncate_json_str(val, max_len=100), val)

    def test_embedded_json_truncated(self):
        """String containing name={...json...} pattern is truncated."""
        inner = json.dumps({"k": "v" * 200})
        val = "{'config_json': ['config_json=%s']}" % inner
        self.assertGreater(len(val), 100)
        result = utils._truncate_json_str(val, max_len=100)
        self.assertTrue(result.endswith("..."))

    def test_hint_shown_once(self):
        """Stderr hint is printed only once across multiple calls."""
        utils._truncate_json_str._hint_shown = False
        val = json.dumps({"k": "v" * 200})

        saved_stderr = sys.stderr
        try:
            sys.stderr = capture = StringIO()
            utils._truncate_json_str(val, max_len=100)
            utils._truncate_json_str(val, max_len=100)
        finally:
            sys.stderr = saved_stderr

        hints = capture.getvalue().count("Note:")
        self.assertEqual(hints, 1)

    def test_truncate_json_for_table(self):
        """Formatter factory works with object attribute access."""
        utils._truncate_json_str._hint_shown = False

        class FakeObj:
            value = json.dumps({"k": "v" * 200})

        formatter = utils.truncate_json_for_table('value', max_len=100)
        result = formatter(FakeObj())
        self.assertTrue(result.endswith("..."))

    def test_truncate_json_value_direct(self):
        """Direct value formatter works."""
        utils._truncate_json_str._hint_shown = False
        val = json.dumps({"k": "v" * 200})
        result = utils.truncate_json_value(val, max_len=100)
        self.assertTrue(result.endswith("..."))

    def test_truncate_json_value_none(self):
        """None value returns empty string."""
        result = utils.truncate_json_value(None, max_len=100)
        self.assertEqual(result, '')


class AutoDecodeJsonTest(test_utils.BaseTestCase):

    def test_decode_json_string_in_dict(self):
        """JSON string values starting with '{' are decoded."""
        data = {'value': '{"global": {"mode": "SW"}}'}
        result = utils._auto_decode_json_values(data)
        self.assertIsInstance(result['value'], dict)
        self.assertEqual(result['value']['global']['mode'], 'SW')

    def test_non_json_string_unchanged(self):
        """Non-JSON string values pass through."""
        data = {'value': 'domainNumber=24'}
        result = utils._auto_decode_json_values(data)
        self.assertEqual(result['value'], 'domainNumber=24')

    def test_list_of_dicts(self):
        """List input processes each dict."""
        data = [
            {'name': 'config_json',
             'value': '{"channels": {}}'},
            {'name': 'domainNumber', 'value': '24'}
        ]
        result = utils._auto_decode_json_values(data)
        self.assertIsInstance(result[0]['value'], dict)
        self.assertEqual(result[1]['value'], '24')

    def test_nested_dict_recursion(self):
        """Nested dicts are processed recursively."""
        data = {'params': {'inner': '{"a": 1}'}}
        result = utils._auto_decode_json_values(data)
        self.assertIsInstance(result['params']['inner'], dict)

    def test_name_value_json_in_list(self):
        """List items with 'name={json}' pattern are decoded."""
        data = ['config_json={"global": {"mode": "SW"}}']
        result = utils._auto_decode_json_values(data)
        self.assertIsInstance(result[0], dict)
        self.assertEqual(result[0]['global']['mode'], 'SW')

    def test_name_value_non_json_unchanged(self):
        """List items with 'name=value' but no JSON stay as strings."""
        data = ['domainNumber=24', 'network_transport=L2']
        result = utils._auto_decode_json_values(data)
        self.assertEqual(result[0], 'domainNumber=24')
        self.assertEqual(result[1], 'network_transport=L2')

    def test_name_value_json_in_dict_value(self):
        """Dict value with 'name={json}' pattern is decoded."""
        data = {'param': 'config_json={"a": 1}'}
        result = utils._auto_decode_json_values(data)
        self.assertIsInstance(result['param'], dict)
        self.assertEqual(result['param']['a'], 1)


class OutputAsJsonTest(test_utils.BaseTestCase):

    def _make_args(self, to_json=False, to_file=False):
        args = mock.Mock()
        args.to_json = to_json
        args.to_file = to_file
        return args

    def test_no_flags_returns_false(self):
        """Returns False when neither flag is set."""
        args = self._make_args()
        result = utils.output_as_json({'key': 'val'}, args, 'test')
        self.assertFalse(result)

    def test_to_json_prints_to_stdout(self):
        """--to-json prints pretty JSON to stdout."""
        args = self._make_args(to_json=True)
        data = {'name': 'inst1', 'value': '{"a": 1}'}

        saved_stdout = sys.stdout
        try:
            sys.stdout = output = StringIO()
            result = utils.output_as_json(data, args, 'test-cmd')
        finally:
            sys.stdout = saved_stdout

        self.assertTrue(result)
        parsed = json.loads(output.getvalue())
        # auto-decode: value should be a dict now
        self.assertIsInstance(parsed['value'], dict)
        self.assertEqual(parsed['value']['a'], 1)

    def test_to_json_decodes_name_value_json(self):
        """--to-json decodes 'name={json}' strings in lists."""
        args = self._make_args(to_json=True)
        data = {'parameters': {'config_json': [
            'config_json={"global": {"mode": "SW"}}']}}

        saved_stdout = sys.stdout
        try:
            sys.stdout = output = StringIO()
            utils.output_as_json(data, args, 'test-cmd')
        finally:
            sys.stdout = saved_stdout

        parsed = json.loads(output.getvalue())
        decoded = parsed['parameters']['config_json'][0]
        self.assertIsInstance(decoded, dict)
        self.assertEqual(decoded['global']['mode'], 'SW')

    def test_to_file_creates_file(self):
        """--to-file writes JSON file and prints path."""
        args = self._make_args(to_file=True)
        data = {'name': 'inst1'}

        saved_stdout = sys.stdout
        try:
            sys.stdout = output = StringIO()
            result = utils.output_as_json(data, args, 'test-cmd')
        finally:
            sys.stdout = saved_stdout

        self.assertTrue(result)
        filepath = output.getvalue().strip()
        self.assertIn('/tmp/test-cmd_', filepath)
        self.assertIn('.json', filepath)
        # Extract path from "JSON saved to: /tmp/..."
        filepath = filepath.replace('JSON saved to: ', '')
        # Verify file content
        with open(filepath, 'r') as f:
            parsed = json.loads(f.read())
        self.assertEqual(parsed['name'], 'inst1')
        # Cleanup
        os.unlink(filepath)

    def test_to_json_list_output(self):
        """--to-json with list data outputs JSON array."""
        args = self._make_args(to_json=True)
        data = [{'uuid': 'abc', 'name': 'inst1'}]

        saved_stdout = sys.stdout
        try:
            sys.stdout = output = StringIO()
            utils.output_as_json(data, args, 'test-list')
        finally:
            sys.stdout = saved_stdout

        parsed = json.loads(output.getvalue())
        self.assertIsInstance(parsed, list)
        self.assertEqual(parsed[0]['name'], 'inst1')
