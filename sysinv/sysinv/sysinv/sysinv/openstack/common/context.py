# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Simple class that stores security context information in the web request.

Projects should subclass this class if they wish to enhance the request
context or provide additional information in their specific WSGI pipeline.
"""

# TODO this file is only necessary for 22.12 -> 23.09 upgrades.

import itertools

from oslo_utils import uuidutils


def generate_request_id():
    return 'req-%s' % uuidutils.generate_uuid()


class RequestContext(object):

    """
    Stores information about the security context under which the user
    accesses the system, as well as additional request information.
    """

    def __init__(self, auth_token=None, user=None, tenant=None, is_admin=False,
                 read_only=False, show_deleted=False, request_id=None, **kwargs):
        self.auth_token = auth_token
        self.user = user
        self.tenant = tenant
        self.is_admin = is_admin
        self.read_only = read_only
        self.show_deleted = show_deleted
        if not request_id:
            request_id = generate_request_id()
        self.request_id = request_id

    def to_dict(self):
        return {'user': self.user,
                'tenant': self.tenant,
                'is_admin': self.is_admin,
                'read_only': self.read_only,
                'show_deleted': self.show_deleted,
                'auth_token': self.auth_token,
                'request_id': self.request_id}

    @classmethod
    def from_dict(cls, values):
        return cls(**values)


def get_admin_context(show_deleted=False):
    context = RequestContext(None,
                             tenant=None,
                             is_admin=True,
                             show_deleted=show_deleted)
    return context


def get_context_from_function_and_args(function, args, kwargs):
    """Find an arg of type RequestContext and return it.

       This is useful in a couple of decorators where we don't
       know much about the function we're wrapping.
    """

    for arg in itertools.chain(kwargs.values(), args):
        if isinstance(arg, RequestContext):
            return arg

    return None
