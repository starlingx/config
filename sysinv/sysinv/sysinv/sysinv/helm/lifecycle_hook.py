#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

import six
from copy import copy
from copy import deepcopy

from sysinv.objects import base
from sysinv.objects import utils


class LifecycleHookInfo(base.SysinvObject):
    """Class containing information about a lifecycle hook.

    Make it serializable by inheriting SysinvObject.

    Attributes:
        mode (string): Manual or Auto
        lifecycle_type (string): Type of the hook (semantic check, operation
                                rbd, resource, manifest, armada-request).
        relative_timing (string): Relative timing to the operation (pre/post).
        operation (string): Operation being performed.
        extra (dict): Can populate data here and it is passed to the outside.
                      Should be used as a mechanism to share data between
                      hooks that form a chain, for example between the pre and
                      post hooks for a logical step.
    """
    VERSION = '1.0'

    fields = {
        'mode': utils.str_or_none,
        'lifecycle_type': utils.str_or_none,
        'relative_timing': utils.str_or_none,
        'operation': utils.str_or_none,
        'extra': utils.dict_or_none,
    }

    mode = None
    lifecycle_type = None
    relative_timing = None
    operation = None
    extra = None

    def __init__(self):
        super(LifecycleHookInfo, self).__init__()
        self.extra = dict()

    def init(self, mode, lifecycle_type, relative_timing, operation):
        self.mode = mode
        self.relative_timing = relative_timing
        self.lifecycle_type = lifecycle_type
        self.operation = operation
        self.extra = dict()

    def __getitem__(self, name):
        return getattr(self, name)

    # TODO(dvoicule): maybe allow just the object named 'extra' to be writable
    def __setitem__(self, name, value):
        setattr(self, name, value)

    def __str__(self):
        return format(
            {k: v for k, v in six.iteritems(self)
             if (k.startswith('_') and k[1:] in self.fields.keys())
                or k in self.fields.keys()})

    def __copy__(self):
        instance = type(self).__new__(self.__class__)
        instance.__dict__.update(self.__dict__)
        return instance

    def __deepcopy__(self, m):
        hook = copy(self)
        hook.extra = deepcopy(self.extra, m)
        return hook
