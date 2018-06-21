#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import abc
import six


@six.add_metaclass(abc.ABCMeta)
class BaseHelm(object):
    """Base class to encapsulate helm operations for chart overrides"""

    def __init__(self, operator):
        self._operator = operator

    @property
    def dbapi(self):
        return self._operator.dbapi

    @property
    def context(self):
        return self._operator.context
