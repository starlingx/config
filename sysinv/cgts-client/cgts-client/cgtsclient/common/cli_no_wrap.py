#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
The sole purpose of this module is to manage access to the _no_wrap variable
used by the wrapping_formatters module
"""

_no_wrap = [False]


def is_nowrap_set(no_wrap=None):
    """
       returns True if no wrapping desired.
            determines this by either the no_wrap parameter
            or if the global no_wrap flag is set
    :param no_wrap:
    :return:
    """
    global _no_wrap
    if no_wrap is True:
        return True
    if no_wrap is False:
        return False
    no_wrap = _no_wrap[0]
    return no_wrap


def set_no_wrap(no_wrap):
    """
       Sets the global nowrap flag
       then returns result of call to is_nowrap_set(..)
    :param no_wrap:
    :return:
    """
    global _no_wrap
    if no_wrap is not None:
        _no_wrap[0] = no_wrap
    return is_nowrap_set(no_wrap)
