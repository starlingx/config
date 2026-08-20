#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Shared test helpers for cgts-client pytest tests.

Provides common factory functions and decorators used
across all shell and coverage test modules.
"""
from unittest import mock

from cgtsclient.common import base


def _make_resource(**kwargs):
    """Create a fake Resource with given attributes.

    Args:
        **kwargs: Attribute key-value pairs for the
            resource.

    Returns:
        A cgtsclient Resource instance with the given
        attributes set and loaded=True.
    """
    return base.Resource(
        mock.MagicMock(), kwargs, loaded=True
    )


def _make_args(**kwargs):
    """Create a fake args namespace for shell commands.

    Args:
        **kwargs: Attribute key-value pairs to set on
            the mock args object.

    Returns:
        A MagicMock with the given attributes, plus
        nowrap=False, column=[], and format=None.
    """
    args = mock.MagicMock()
    for key, val in kwargs.items():
        setattr(args, key, val)
    args.nowrap = False
    args.column = []
    args.format = None
    args.to_json = kwargs.get('to_json', False)
    args.to_file = kwargs.get('to_file', None)
    return args


def _make_shell_args(**kwargs):
    """Create a fake args namespace with spec=[].

    Similar to _make_args but uses spec=[] to prevent
    attribute auto-creation on the mock.

    Args:
        **kwargs: Attribute key-value pairs to set.

    Returns:
        A MagicMock(spec=[]) with the given attributes
        and nowrap=False.
    """
    args = mock.MagicMock(spec=[])
    for key, val in kwargs.items():
        setattr(args, key, val)
    args.nowrap = False
    args.from_file = kwargs.get('from_file', None)
    args.from_json = kwargs.get('from_json', None)
    args.to_json = kwargs.get('to_json', False)
    args.to_file = kwargs.get('to_file', None)
    return args


PRINT_PATCHERS = [
    mock.patch(
        'cgtsclient.common.utils.print_list'
    ),
    mock.patch(
        'cgtsclient.common.utils.print_tuple_list'
    ),
    mock.patch(
        'cgtsclient.common.utils.print_dict'
    ),
    mock.patch(
        'cgtsclient.common.utils.print_dict_with_format'
    ),
]
"""List of mock patchers for print utility functions.

Apply via the _patch_print decorator to suppress
print output during shell command tests.
"""


def _patch_print(cls):
    """Decorate a test class to patch print utilities.

    Applies all PRINT_PATCHERS to the given test class
    so that shell commands do not produce output.

    Args:
        cls: The test class to decorate.

    Returns:
        The decorated test class with all print
        functions patched.
    """
    for patcher in PRINT_PATCHERS:
        cls = patcher(cls)
    return cls
