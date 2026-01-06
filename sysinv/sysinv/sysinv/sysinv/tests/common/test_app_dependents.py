#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for app_dependents.py
"""

import testtools

from unittest.mock import MagicMock
from sysinv.common import app_dependents
from sysinv.common import constants


class BaseAppTestCase(testtools.TestCase):
    APP_NAME = "foo"
    CURRENT_VERSION = "25.09-1"
    UPDATE_CANDIDATE_VERSION = "26.09-1"

    def make_mock_app(self, name, version, app_metadata=None):
        mock_app = MagicMock()
        mock_app.name = name
        mock_app.app_version = version
        mock_app.app_metadata = app_metadata or {}
        return mock_app

    def setUp(self):
        super().setUp()
        self.dbapi = MagicMock()
        self.app_name = self.APP_NAME
        self.current_app_version = self.CURRENT_VERSION
        self.update_candidate_app_version = self.UPDATE_CANDIDATE_VERSION


class MatchDependencyTestCase(testtools.TestCase):

    def setUp(self):
        super().setUp()
        self.app_list = [
            ('foo', '25.09-1'),
            ('bar', '25.09-2'),
            ('baz', '25.09-3'),
            ('qux', '25.09-4')
        ]

    def test_match_dependency_exact_match(self):
        app_tuple = ('foo', r'25\.09-1')
        result = app_dependents.match_dependency(self.app_list, app_tuple)
        assert result is True

    def test_match_dependency_regex_match(self):
        app_tuple = ('foo', r'25\.09-\d')
        result = app_dependents.match_dependency(self.app_list, app_tuple)
        assert result is True

    def test_match_dependency_no_match_name(self):
        app_tuple = ('notfound', r'.*')
        result = app_dependents.match_dependency(self.app_list, app_tuple)
        assert result is False

    def test_match_dependency_no_match_version(self):
        app_tuple = ('foo', r'99\.99-\d')
        result = app_dependents.match_dependency(self.app_list, app_tuple)
        assert result is False

    def test_match_dependency_empty_list(self):
        app_tuple = ('foo', r'.*')
        result = app_dependents.match_dependency([], app_tuple)
        assert result is False

    def test_match_dependency_partial_regex(self):
        app_tuple = ('bar', r'25\.09-2')
        result = app_dependents.match_dependency(self.app_list, app_tuple)
        assert result is True

    def test_match_dependency_multiple_candidates(self):
        # Add a duplicate name with a different version
        app_list = self.app_list + [('foo', '99.99-1')]
        app_tuple = ('foo', r'25\.09-\d')
        result = app_dependents.match_dependency(app_list, app_tuple)
        assert result is True

    def test_match_dependency_version_regex(self):
        # Test the specific regex: 25\.09-\d+
        app_tuple = ('baz', r'25\.09-\d+')
        result = app_dependents.match_dependency(self.app_list, app_tuple)
        assert result is True


class GetDependentAppsMissingTestCase(BaseAppTestCase):
    # No need for make_mock_app here, use the one from BaseAppTestCase
    # Use self.dbapi in tests instead of local dbapi
    def test_get_dependent_apps_missing_no_deps(self):
        self.dbapi.kube_app_get_all_by_status.return_value = []
        app_metadata = {}
        result = app_dependents.get_dependent_apps_missing(app_metadata, self.dbapi)
        assert not result

    def test_get_dependent_apps_missing_single_missing_dep(self):
        self.dbapi.kube_app_get_all_by_status.return_value = []
        app_metadata = {
            app_dependents.constants.APP_METADATA_DEPENDENT_APPS: [
                {'name': 'foo', 'version': r'25\.09-1'}
            ]
        }
        result = app_dependents.get_dependent_apps_missing(app_metadata, self.dbapi)
        assert result == [{'name': 'foo', 'version': r'25\.09-1'}]

    def test_get_dependent_apps_missing_dep_already_applied(self):
        applied_app = self.make_mock_app('foo', '25.09-1')
        self.dbapi.kube_app_get_all_by_status.return_value = [applied_app]
        app_metadata = {
            app_dependents.constants.APP_METADATA_DEPENDENT_APPS: [
                {'name': 'foo', 'version': r'25\.09-\d+'}
            ]
        }
        result = app_dependents.get_dependent_apps_missing(app_metadata, self.dbapi)
        assert not result

    def test_get_dependent_apps_missing_action_ignore(self):
        self.dbapi.kube_app_get_all_by_status.return_value = []
        app_metadata = {
            app_dependents.constants.APP_METADATA_DEPENDENT_APPS: [
                {
                    'name': 'foo',
                    'version': r'25\.09-\d+',
                    'action': constants.APP_METADATA_DEPENDENT_APPS_ACTION_IGNORE
                }
            ]
        }
        result = app_dependents.get_dependent_apps_missing(app_metadata, self.dbapi)
        assert not result

    def test_get_dependent_apps_missing_action_ignore_included(self):
        self.dbapi.kube_app_get_all_by_status.return_value = []
        app_metadata = {
            app_dependents.constants.APP_METADATA_DEPENDENT_APPS: [
                {
                    'name': 'foo',
                    'version': r'25\.09-\d+',
                    'action': constants.APP_METADATA_DEPENDENT_APPS_ACTION_IGNORE
                }
            ]
        }
        result = app_dependents.get_dependent_apps_missing(
            app_metadata, self.dbapi, include_apps_action_ignore=True
        )
        assert result == [
            {
                "name": "foo",
                "version": r"25\.09-\d+",
                "action": constants.APP_METADATA_DEPENDENT_APPS_ACTION_IGNORE,
            }
        ]

    def test_get_dependent_apps_missing_action_error(self):
        self.dbapi.kube_app_get_all_by_status.return_value = []
        app_metadata = {
            app_dependents.constants.APP_METADATA_DEPENDENT_APPS: [
                {
                    'name': 'foo',
                    'version': r'25\.09-\d+',
                    'action': constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR
                }
            ]
        }
        result = app_dependents.get_dependent_apps_missing(app_metadata, self.dbapi)
        assert result == [
            {
                "name": "foo",
                "version": r"25\.09-\d+",
                "action": constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR,
            }
        ]

    def test_get_dependent_apps_missing_action_warn(self):
        self.dbapi.kube_app_get_all_by_status.return_value = []
        app_metadata = {
            app_dependents.constants.APP_METADATA_DEPENDENT_APPS: [
                {
                    'name': 'foo',
                    'version': r'25\.09-\d+',
                    'action': constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN
                }
            ]
        }
        result = app_dependents.get_dependent_apps_missing(app_metadata, self.dbapi)
        assert result == [
            {
                "name": "foo",
                "version": r"25\.09-\d+",
                "action": constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN,
            }
        ]

    def test_get_dependent_apps_missing_action_apply(self):
        self.dbapi.kube_app_get_all_by_status.return_value = []
        app_metadata = {
            app_dependents.constants.APP_METADATA_DEPENDENT_APPS: [
                {
                    'name': 'foo',
                    'version': r'25\.09-\d+',
                    'action': constants.APP_METADATA_DEPENDENT_APPS_ACTION_APPLY
                }
            ]
        }
        result = app_dependents.get_dependent_apps_missing(app_metadata, self.dbapi)
        assert result == [
            {
                "name": "foo",
                "version": r"25\.09-\d+",
                "action": constants.APP_METADATA_DEPENDENT_APPS_ACTION_APPLY,
            }
        ]

    def test_get_dependent_apps_missing_mutually_exclusive_with_actions(self):
        self.dbapi.kube_app_get_all_by_status.return_value = []
        mock_dependent_apps = [[
            {
                'name': 'foo',
                'version': r'25\.09-\d+',
                'action': constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR
            },
            {
                'name': 'bar',
                'version': r'25\.09-\d+',
                'action': constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN
            },
            {
                'name': 'baz',
                'version': r'25\.09-\d+',
                'action': constants.APP_METADATA_DEPENDENT_APPS_ACTION_APPLY
            }
        ]]
        app_metadata = {
            app_dependents.constants.APP_METADATA_DEPENDENT_APPS: mock_dependent_apps
        }
        result = app_dependents.get_dependent_apps_missing(app_metadata, self.dbapi)
        assert result == mock_dependent_apps

    def test_get_dependent_apps_missing_mutually_exclusive_some_applied_with_actions(self):
        applied_app = self.make_mock_app('bar', '25.09-2')
        self.dbapi.kube_app_get_all_by_status.return_value = [applied_app]
        mock_dependent_apps = [[
            {
                'name': 'foo',
                'version': r'25\.09-\d+',
                'action': constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR
            },
            {
                'name': 'bar',
                'version': r'25\.09-\d+',
                'action': constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN
            },
            {
                'name': 'baz',
                'version': r'25\.09-\d+',
                'action': constants.APP_METADATA_DEPENDENT_APPS_ACTION_APPLY
            }
        ]]
        app_metadata = {
            app_dependents.constants.APP_METADATA_DEPENDENT_APPS: mock_dependent_apps
        }
        result = app_dependents.get_dependent_apps_missing(app_metadata, self.dbapi)
        # Should not include the mutually exclusive group since one is satisfied
        assert not result

    def test_get_dependent_apps_missing_mutually_exclusive_all_missing(self):
        self.dbapi.kube_app_get_all_by_status.return_value = []
        app_metadata = {
            app_dependents.constants.APP_METADATA_DEPENDENT_APPS: [
                [
                    {'name': 'foo', 'version': r'25\.09-\d+'},
                    {'name': 'bar', 'version': r'25\.09-\d+'}
                ]
            ]
        }
        result = app_dependents.get_dependent_apps_missing(app_metadata, self.dbapi)
        assert result == [[
            {'name': 'foo', 'version': r'25\.09-\d+'},
            {'name': 'bar', 'version': r'25\.09-\d+'}
        ]]

    def test_get_dependent_apps_missing_mutually_exclusive_one_applied(self):
        applied_app = self.make_mock_app('foo', '25.09-1')
        self.dbapi.kube_app_get_all_by_status.return_value = [applied_app]
        app_metadata = {
            app_dependents.constants.APP_METADATA_DEPENDENT_APPS: [
                [
                    {'name': 'foo', 'version': r'25\.09-\d+'},
                    {'name': 'bar', 'version': r'25\.09-\d+'}
                ]
            ]
        }
        result = app_dependents.get_dependent_apps_missing(app_metadata, self.dbapi)
        # Should not include the mutually exclusive group since one is satisfied
        assert not result

    def test_get_dependent_apps_missing_mutually_exclusive_some_applied(self):
        applied_app1 = self.make_mock_app('bar', '25.09-2')
        applied_app2 = self.make_mock_app('bar', '25.09-3')
        self.dbapi.kube_app_get_all_by_status.return_value = [applied_app1, applied_app2]
        app_metadata = {
            app_dependents.constants.APP_METADATA_DEPENDENT_APPS: [
                [
                    {'name': 'foo', 'version': r'25\.09-\d+'},
                    {'name': 'bar', 'version': r'25\.09-\d+'},
                    {'name': 'baz', 'version': r'25\.09-\d+'}
                ]
            ]
        }
        result = app_dependents.get_dependent_apps_missing(app_metadata, self.dbapi)
        # Should not include the mutually exclusive group since one is satisfied
        assert not result

    def test_get_dependent_apps_missing_mutually_exclusive_all_applied(self):
        applied_app1 = self.make_mock_app('foo', '25.09-2')
        applied_app2 = self.make_mock_app('bar', '25.09-3')
        self.dbapi.kube_app_get_all_by_status.return_value = [applied_app1, applied_app2]
        app_metadata = {
            app_dependents.constants.APP_METADATA_DEPENDENT_APPS: [
                [
                    {'name': 'foo', 'version': r'25\.09-\d+'},
                    {'name': 'bar', 'version': r'25\.09-\d+'}
                ]
            ]
        }
        result = app_dependents.get_dependent_apps_missing(app_metadata, self.dbapi)
        assert not result


class FormatMissingAppsOutputTestCase(testtools.TestCase):
    def test_empty_list(self):
        result = app_dependents.format_missing_apps_output([])
        assert result == ""

    def test_single_app(self):
        app_list = [{'name': 'foo', 'version': r'25\.09-\d+'}]
        result = app_dependents.format_missing_apps_output(app_list)
        assert result == "foo (compatible version(s): 25\\.09-\\d+)"

    def test_multiple_apps(self):
        app_list = [
            {'name': 'foo', 'version': r'25\.09-\d+'},
            {'name': 'bar', 'version': r'25\.09-2'}
        ]
        result = app_dependents.format_missing_apps_output(app_list)
        assert result == (
            "foo (compatible version(s): 25\\.09-\\d+), "
            "bar (compatible version(s): 25\\.09-2)"
        )

    def test_mutually_exclusive_group(self):
        app_list = [[
            {'name': 'foo', 'version': r'25\.09-\d+'},
            {'name': 'bar', 'version': r'25\.09-2'}
        ]]
        result = app_dependents.format_missing_apps_output(app_list)
        assert result == (
            "foo (compatible version(s): 25\\.09-\\d+) or bar (compatible version(s): 25\\.09-2)"
        )

    def test_mixed_apps_and_mutually_exclusive(self):
        app_list = [
            {'name': 'foo', 'version': r'25\.09-\d+'},
            [
                {'name': 'bar', 'version': r'25\.09-2'},
                {'name': 'baz', 'version': r'25\.09-3'}
            ],
            {'name': 'qux', 'version': r'25\.09-4'}
        ]
        result = app_dependents.format_missing_apps_output(app_list)
        assert result == (
            "foo (compatible version(s): 25\\.09-\\d+), "
            "bar (compatible version(s): 25\\.09-2) or baz (compatible version(s): 25\\.09-3), "
            "qux (compatible version(s): 25\\.09-4)"
        )

    def test_mutually_exclusive_group_single_element(self):
        app_list = [[{'name': 'foo', 'version': r'25\.09-\d+'}]]
        result = app_dependents.format_missing_apps_output(app_list)
        assert result == "foo (compatible version(s): 25\\.09-\\d+)"


class IsActionMatchTestCase(testtools.TestCase):
    def test_action_exact_match(self):
        assert app_dependents.is_action_match(
            constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR,
            constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR
        ) is True

    def test_action_type_warn_and_action_none(self):
        assert app_dependents.is_action_match(
            None,
            constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN
        ) is True

    def test_action_type_warn_and_action_warn(self):
        assert app_dependents.is_action_match(
            constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN,
            constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN
        ) is True

    def test_action_type_error_and_action_none(self):
        assert app_dependents.is_action_match(
            None,
            constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR
        ) is False

    def test_action_type_apply_and_action_none(self):
        assert app_dependents.is_action_match(
            None,
            constants.APP_METADATA_DEPENDENT_APPS_ACTION_APPLY
        ) is False

    def test_action_type_ignore_and_action_none(self):
        assert app_dependents.is_action_match(
            None,
            constants.APP_METADATA_DEPENDENT_APPS_ACTION_IGNORE
        ) is False

    def test_action_type_warn_and_action_other(self):
        assert app_dependents.is_action_match(
            constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR,
            constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN
        ) is False

    def test_action_type_error_and_action_warn(self):
        assert app_dependents.is_action_match(
            constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN,
            constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR
        ) is False


class GetDependentAppsByActionTestCase(testtools.TestCase):
    def test_empty_list(self):
        result = app_dependents.get_dependent_apps_by_action(
            [], constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR)
        assert not result

    def test_single_dict_matching_action(self):
        deps = [
            {
                "name": "foo",
                "version": r"25\.09-\d+",
                "action": constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR,
            }
        ]
        result = app_dependents.get_dependent_apps_by_action(
            deps, constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR
        )
        assert result == [{'name': 'foo', 'version': r'25\.09-\d+'}]

    def test_single_dict_non_matching_action(self):
        deps = [
            {
                "name": "foo",
                "version": r"25\.09-\d+",
                "action": constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN,
            }
        ]
        result = app_dependents.get_dependent_apps_by_action(
            deps, constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR
        )
        assert not result

    def test_single_dict_action_none_warn(self):
        deps = [{"name": "foo", "version": r"25\.09-\d+"}]
        result = app_dependents.get_dependent_apps_by_action(
            deps, constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN
        )
        assert result == [{"name": "foo", "version": r"25\.09-\d+"}]

    def test_single_dict_action_none_error(self):
        deps = [{"name": "foo", "version": r"25\.09-\d+"}]
        result = app_dependents.get_dependent_apps_by_action(
            deps, constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR
        )
        assert not result

    def test_mutually_exclusive_group_all_match(self):
        deps = [
            [
                {
                    "name": "foo",
                    "version": r"25\.09-\d+",
                    "action": constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR,
                },
                {
                    "name": "bar",
                    "version": r"25\.09-2",
                    "action": constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR,
                },
            ]
        ]
        result = app_dependents.get_dependent_apps_by_action(
            deps, constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR
        )
        assert result == [
            [
                {"name": "foo", "version": r"25\.09-\d+"},
                {"name": "bar", "version": r"25\.09-2"},
            ]
        ]

    def test_mutually_exclusive_group_some_match(self):
        deps = [
            [
                {
                    "name": "foo",
                    "version": r"25\.09-\d+",
                    "action": constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR,
                },
                {
                    "name": "bar",
                    "version": r"25\.09-2",
                    "action": constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN,
                },
            ]
        ]
        result = app_dependents.get_dependent_apps_by_action(
            deps, constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR
        )
        assert result == [[{"name": "foo", "version": r"25\.09-\d+"}]]

    def test_mutually_exclusive_group_none_match(self):
        deps = [
            [
                {
                    "name": "foo",
                    "version": r"25\.09-\d+",
                    "action": constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN,
                },
                {
                    "name": "bar",
                    "version": r"25\.09-2",
                    "action": constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN,
                },
            ]
        ]
        result = app_dependents.get_dependent_apps_by_action(
            deps, constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR
        )
        assert not result

    def test_mixed_dict_and_group(self):
        deps = [
            {
                "name": "foo",
                "version": r"25\.09-\d+",
                "action": constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR,
            },
            [
                {
                    "name": "bar",
                    "version": r"25\.09-2",
                    "action": constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR,
                },
                {
                    "name": "baz",
                    "version": r"25\.09-3",
                    "action": constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN,
                },
            ],
        ]
        result = app_dependents.get_dependent_apps_by_action(
            deps, constants.APP_METADATA_DEPENDENT_APPS_ACTION_ERROR
        )
        assert result == [
            {"name": "foo", "version": r"25\.09-\d+"},
            [{"name": "bar", "version": r"25\.09-2"}],
        ]

    def test_mutually_exclusive_group_action_none_warn(self):
        deps = [
            [
                {"name": "foo", "version": r"25\.09-\d+"},  # action None
                {
                    "name": "bar",
                    "version": r"25\.09-2",
                    "action": constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN,
                },
            ]
        ]
        result = app_dependents.get_dependent_apps_by_action(
            deps, constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN
        )
        assert result == [
            [
                {"name": "foo", "version": r"25\.09-\d+"},
                {"name": "bar", "version": r"25\.09-2"},
            ]
        ]


class HasCircularDependencyTestCase(BaseAppTestCase):
    def setUp(self):
        super().setUp()
        self.rpc_app = self.make_mock_app(self.APP_NAME, self.CURRENT_VERSION)
        self.upload_apps_succeeded_list = [{"name": "bar"}, {"name": "baz"}]

    def test_no_dependent_apps_metadata(self):
        # db_app.app_metadata does not contain dependent apps
        db_app = self.make_mock_app("bar", "25.09-2", {})
        self.dbapi.kube_app_get.return_value = db_app
        result = app_dependents.has_circular_dependency(
            self.rpc_app, self.upload_apps_succeeded_list, self.dbapi
        )
        assert result is False

    def test_no_missing_dependent_apps(self):
        # dependent_apps_missing_list is empty
        db_app = self.make_mock_app(
            "bar",
            "25.09-2",
            {
                app_dependents.constants.APP_METADATA_DEPENDENT_APPS: [
                    {"name": "foo", "version": r"25\.09-\d+"}
                ]
            },
        )
        self.dbapi.kube_app_get.return_value = db_app
        # Patch get_dependent_apps_missing to return []
        orig = app_dependents.get_dependent_apps_missing
        app_dependents.get_dependent_apps_missing = MagicMock(return_value=[])
        result = app_dependents.has_circular_dependency(
            self.rpc_app, self.upload_apps_succeeded_list, self.dbapi
        )
        assert result is False
        app_dependents.get_dependent_apps_missing = orig

    def test_no_apply_type_dependencies(self):
        # get_dependent_apps_by_action returns []
        db_app = self.make_mock_app(
            "bar",
            "25.09-2",
            {
                app_dependents.constants.APP_METADATA_DEPENDENT_APPS: [
                    {"name": "foo", "version": r"25\.09-\d+"}
                ]
            },
        )
        self.dbapi.kube_app_get.return_value = db_app
        app_dependents.get_dependent_apps_missing = MagicMock(
            return_value=[{"name": "foo", "version": r"25\.09-\d+"}]
        )
        app_dependents.get_dependent_apps_by_action = MagicMock(return_value=[])
        result = app_dependents.has_circular_dependency(
            self.rpc_app, self.upload_apps_succeeded_list, self.dbapi
        )
        assert result is False

    def test_circular_dependency_found(self):
        # get_dependent_apps_by_action returns a dep that matches rpc_app
        db_app = self.make_mock_app(
            "bar",
            "25.09-2",
            {
                app_dependents.constants.APP_METADATA_DEPENDENT_APPS: [
                    {
                        "name": "foo",
                        "version": r"25\.09-1",
                        "action": app_dependents.constants.APP_METADATA_DEPENDENT_APPS_ACTION_APPLY,
                    }
                ]
            },
        )
        self.dbapi.kube_app_get.return_value = db_app
        app_dependents.get_dependent_apps_missing = MagicMock(
            return_value=[
                {
                    "name": "foo",
                    "version": r"25\.09-1",
                    "action": app_dependents.constants.APP_METADATA_DEPENDENT_APPS_ACTION_APPLY,
                }
            ]
        )
        app_dependents.get_dependent_apps_by_action = MagicMock(
            return_value=[{"name": "foo", "version": r"25\.09-1"}]
        )
        result = app_dependents.has_circular_dependency(
            self.rpc_app, self.upload_apps_succeeded_list, self.dbapi
        )
        assert result is True

    def test_circular_dependency_not_found_due_to_version(self):
        # get_dependent_apps_by_action returns a dep with non-matching version
        db_app = self.make_mock_app(
            "bar",
            "25.09-2",
            {
                app_dependents.constants.APP_METADATA_DEPENDENT_APPS: [
                    {
                        "name": "foo",
                        "version": r"99\.99-1",
                        "action": app_dependents.constants.APP_METADATA_DEPENDENT_APPS_ACTION_APPLY,
                    }
                ]
            },
        )
        self.dbapi.kube_app_get.return_value = db_app
        app_dependents.get_dependent_apps_missing = MagicMock(
            return_value=[
                {
                    "name": "foo",
                    "version": r"99\.99-1",
                    "action": app_dependents.constants.APP_METADATA_DEPENDENT_APPS_ACTION_APPLY,
                }
            ]
        )
        app_dependents.get_dependent_apps_by_action = MagicMock(
            return_value=[{"name": "foo", "version": r"99\.99-1"}]
        )
        result = app_dependents.has_circular_dependency(
            self.rpc_app, self.upload_apps_succeeded_list, self.dbapi
        )
        assert result is False


class IsBlockingDependencyTestCase(testtools.TestCase):
    def test_blocks_when_update_candidate_does_not_match_but_current_matches(self):
        dep = {'name': 'foo', 'version': r'25\.09-\d+'}
        app_name = 'foo'
        current_app_version = '25.09-1'
        update_candidate_app_version = '26.09-1'
        # update_candidate does not match regex, but current does, and name matches
        assert app_dependents.is_blocking_dependency(
            dep, app_name, current_app_version, update_candidate_app_version
        ) is True

    def test_does_not_block_when_update_candidate_matches(self):
        dep = {'name': 'foo', 'version': r'25\.09-\d+'}
        app_name = 'foo'
        current_app_version = '25.09-1'
        update_candidate_app_version = '25.09-2'
        # update_candidate matches regex, so should not block
        assert app_dependents.is_blocking_dependency(
            dep, app_name, current_app_version, update_candidate_app_version
        ) is False

    def test_does_not_block_when_name_does_not_match(self):
        dep = {'name': 'bar', 'version': r'25\.09-\d+'}
        app_name = 'foo'
        current_app_version = '25.09-1'
        update_candidate_app_version = '26.09-1'
        # name does not match, so should not block
        assert app_dependents.is_blocking_dependency(
            dep, app_name, current_app_version, update_candidate_app_version
        ) is False

    def test_does_not_block_when_current_version_does_not_match(self):
        dep = {'name': 'foo', 'version': r'25\.09-\d+'}
        app_name = 'foo'
        current_app_version = '24.01-1'
        update_candidate_app_version = '26.09-1'
        # current version does not match regex, so should not block
        assert app_dependents.is_blocking_dependency(
            dep, app_name, current_app_version, update_candidate_app_version
        ) is False

    def test_does_not_block_when_both_versions_do_not_match(self):
        dep = {'name': 'foo', 'version': r'25\.09-\d+'}
        app_name = 'foo'
        current_app_version = '24.01-1'
        update_candidate_app_version = '24.01-2'
        # neither version matches regex, so should not block
        assert app_dependents.is_blocking_dependency(
            dep, app_name, current_app_version, update_candidate_app_version
        ) is False


class GetBlockingParentDependenciesTestCase(BaseAppTestCase):
    def test_no_applied_apps(self):
        self.dbapi.kube_app_get_all_by_status.return_value = []
        result = app_dependents.get_blocking_parent_dependencies(
            self.app_name, self.current_app_version, self.update_candidate_app_version, self.dbapi
        )
        assert not result

    def test_no_dependent_apps_metadata(self):
        applied_app = self.make_mock_app("parent", "1.0", {})
        self.dbapi.kube_app_get_all_by_status.return_value = [applied_app]
        result = app_dependents.get_blocking_parent_dependencies(
            self.app_name, self.current_app_version, self.update_candidate_app_version, self.dbapi
        )
        assert not result

    def test_single_blocking_dependency(self):
        dep = {'name': self.app_name, 'version': r'25\.09-\d+'}
        applied_app = self.make_mock_app(
            "parent", "1.0",
            {constants.APP_METADATA_DEPENDENT_APPS: [dep]}
        )
        self.dbapi.kube_app_get_all_by_status.return_value = [applied_app]
        # update_candidate_app_version does not match dep['version'], but current_app_version does
        result = app_dependents.get_blocking_parent_dependencies(
            self.app_name, self.current_app_version, self.update_candidate_app_version, self.dbapi
        )
        assert result == [{'name': 'parent', 'version': '1.0'}]

    def test_single_non_blocking_dependency_due_to_update_candidate(self):
        dep = {'name': self.app_name, 'version': r'26\.01-\d+'}
        applied_app = self.make_mock_app(
            "parent", "1.0",
            {constants.APP_METADATA_DEPENDENT_APPS: [dep]}
        )
        self.dbapi.kube_app_get_all_by_status.return_value = [applied_app]
        # update_candidate_app_version matches dep['version'], so should not block
        result = app_dependents.get_blocking_parent_dependencies(
            self.app_name, self.current_app_version, "26.09-1", self.dbapi
        )
        assert not result

    def test_single_non_blocking_dependency_due_to_name(self):
        dep = {'name': "bar", 'version': r'25\.09-\d+'}
        applied_app = self.make_mock_app(
            "parent", "1.0",
            {constants.APP_METADATA_DEPENDENT_APPS: [dep]}
        )
        self.dbapi.kube_app_get_all_by_status.return_value = [applied_app]
        result = app_dependents.get_blocking_parent_dependencies(
            self.app_name, self.current_app_version, self.update_candidate_app_version, self.dbapi
        )
        assert not result

    def test_single_non_blocking_dependency_due_to_current_version(self):
        dep = {'name': self.app_name, 'version': r'99\.99-\d+'}
        applied_app = self.make_mock_app(
            "parent", "1.0",
            {constants.APP_METADATA_DEPENDENT_APPS: [dep]}
        )
        self.dbapi.kube_app_get_all_by_status.return_value = [applied_app]
        result = app_dependents.get_blocking_parent_dependencies(
            self.app_name, self.current_app_version, self.update_candidate_app_version, self.dbapi
        )
        assert not result

    def test_mutually_exclusive_blocking_dependency(self):
        dep1 = {'name': self.app_name, 'version': r'25\.09-\d+'}
        dep2 = {'name': "bar", 'version': r'25\.09-\d+'}
        applied_app = self.make_mock_app(
            "parent", "1.0",
            {constants.APP_METADATA_DEPENDENT_APPS: [[dep1, dep2]]}
        )
        self.dbapi.kube_app_get_all_by_status.return_value = [applied_app]
        result = app_dependents.get_blocking_parent_dependencies(
            self.app_name, self.current_app_version, self.update_candidate_app_version, self.dbapi
        )
        assert result == [{'name': 'parent', 'version': '1.0'}]

    def test_mutually_exclusive_non_blocking_dependency(self):
        dep1 = {'name': "bar", 'version': r'25\.09-\d+'}
        dep2 = {'name': "baz", 'version': r'25\.09-\d+'}
        applied_app = self.make_mock_app(
            "parent", "1.0",
            {constants.APP_METADATA_DEPENDENT_APPS: [[dep1, dep2]]}
        )
        self.dbapi.kube_app_get_all_by_status.return_value = [applied_app]
        result = app_dependents.get_blocking_parent_dependencies(
            self.app_name, self.current_app_version, self.update_candidate_app_version, self.dbapi
        )
        assert not result

    def test_multiple_applied_apps_some_blocking(self):
        dep1 = {'name': self.app_name, 'version': r'25\.09-\d+'}
        dep2 = {'name': "bar", 'version': r'25\.09-\d+'}
        app1 = self.make_mock_app(
            "parent1", "1.0",
            {constants.APP_METADATA_DEPENDENT_APPS: [dep1]}
        )
        app2 = self.make_mock_app(
            "parent2", "2.0",
            {constants.APP_METADATA_DEPENDENT_APPS: [dep2]}
        )
        self.dbapi.kube_app_get_all_by_status.return_value = [app1, app2]
        result = app_dependents.get_blocking_parent_dependencies(
            self.app_name, self.current_app_version, self.update_candidate_app_version, self.dbapi
        )
        assert result == [{'name': 'parent1', 'version': '1.0'}]

    def test_dependency_with_none_name(self):
        dep = {'name': None, 'version': r'25\.09-\d+'}
        applied_app = self.make_mock_app(
            "parent", "1.0",
            {constants.APP_METADATA_DEPENDENT_APPS: [dep]}
        )
        self.dbapi.kube_app_get_all_by_status.return_value = [applied_app]
        result = app_dependents.get_blocking_parent_dependencies(
            self.app_name, self.current_app_version, self.update_candidate_app_version, self.dbapi
        )
        assert not result


class ValidateParentExceptionsTestCase(testtools.TestCase):
    def test_all_blocking_parents_have_exceptions(self):
        blocking_parent_list = [
            {'name': 'foo', 'version': '25.09-1'},
            {'name': 'bar', 'version': '25.09-2'}
        ]
        dependent_parent_exceptions = [
            {'name': 'foo', 'version': r'25\.09-\d+'},
            {'name': 'bar', 'version': r'25\.09-2'}
        ]
        result = app_dependents.validate_parent_exceptions(
            blocking_parent_list, dependent_parent_exceptions
        )
        assert result is True

    def test_some_blocking_parents_missing_exceptions(self):
        blocking_parent_list = [
            {'name': 'foo', 'version': '25.09-1'},
            {'name': 'bar', 'version': '25.09-2'}
        ]
        dependent_parent_exceptions = [
            {'name': 'foo', 'version': r'25\.09-\d+'}
        ]
        result = app_dependents.validate_parent_exceptions(
            blocking_parent_list, dependent_parent_exceptions
        )
        assert result is False

    def test_no_blocking_parents(self):
        blocking_parent_list = []
        dependent_parent_exceptions = [
            {'name': 'foo', 'version': r'25\.09-\d+'}
        ]
        result = app_dependents.validate_parent_exceptions(
            blocking_parent_list, dependent_parent_exceptions
        )
        assert result is True

    def test_no_exceptions(self):
        blocking_parent_list = [
            {'name': 'foo', 'version': '25.09-1'}
        ]
        dependent_parent_exceptions = []
        result = app_dependents.validate_parent_exceptions(
            blocking_parent_list, dependent_parent_exceptions
        )
        assert result is False

    def test_version_regex_match(self):
        blocking_parent_list = [
            {'name': 'foo', 'version': '25.09-5'}
        ]
        dependent_parent_exceptions = [
            {'name': 'foo', 'version': r'25\.09-\d+'}
        ]
        result = app_dependents.validate_parent_exceptions(
            blocking_parent_list, dependent_parent_exceptions
        )
        assert result is True

    def test_version_regex_no_match(self):
        blocking_parent_list = [
            {'name': 'foo', 'version': '26.09-1'}
        ]
        dependent_parent_exceptions = [
            {'name': 'foo', 'version': r'25\.09-\d+'}
        ]
        result = app_dependents.validate_parent_exceptions(
            blocking_parent_list, dependent_parent_exceptions
        )
        assert result is False

    def test_multiple_exceptions_for_one_blocking_parent(self):
        blocking_parent_list = [
            {'name': 'foo', 'version': '25.09-1'}
        ]
        dependent_parent_exceptions = [
            {'name': 'foo', 'version': r'24\.01-\d+'},
            {'name': 'foo', 'version': r'25\.09-\d+'}
        ]
        result = app_dependents.validate_parent_exceptions(
            blocking_parent_list, dependent_parent_exceptions
        )
        assert result is True

    def test_name_mismatch(self):
        blocking_parent_list = [
            {'name': 'foo', 'version': '25.09-1'}
        ]
        dependent_parent_exceptions = [
            {'name': 'bar', 'version': r'25\.09-\d+'}
        ]
        result = app_dependents.validate_parent_exceptions(
            blocking_parent_list, dependent_parent_exceptions
        )
        assert result is False
