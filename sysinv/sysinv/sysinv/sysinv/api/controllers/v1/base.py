#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

import datetime

import wsme
from wsme import types as wtypes


class APIBase(wtypes.Base):

    created_at = datetime.datetime
    "The time in UTC at which the object is created"

    updated_at = datetime.datetime
    "The time in UTC at which the object is updated"

    def as_dict(self):
        """Render this object as a dict of its fields."""
        return dict((k, getattr(self, k))
                    for k in self.fields  # pylint: disable=no-member
                    if hasattr(self, k) and
                    getattr(self, k) != wsme.Unset)

    def unset_fields_except(self, except_list=None):
        """Unset fields so they don't appear in the message body.

        :param except_list: A list of fields that won't be touched.

        """
        if except_list is None:
            except_list = []

        for k in self.as_dict():
            if k not in except_list:
                setattr(self, k, wsme.Unset)

    @classmethod
    def from_rpc_object(cls, m, fields=None):
        """Convert a RPC object to an API object."""
        obj_dict = m.as_dict()
        # Unset non-required fields so they do not appear
        # in the message body
        obj_dict.update(dict((k, wsme.Unset)
                        for k in obj_dict.keys()
                        if fields and k not in fields))
        return cls(**obj_dict)
