# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2013 Wind River, Inc.
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

from cgtsclient.common import utils
from cgtsclient import exc


def _print_iuser_show(iuser):
    fields = ['uuid', 'root_sig', 'passwd_expiry_days', 'passwd_hash',
              'isystem_uuid', 'created_at', 'updated_at']
    data = [(f, getattr(iuser, f, '')) for f in fields]
    utils.print_tuple_list(data)


def donot_user_show(cc, args):
    """Show USER (Domain Name Server) details."""

    iusers = cc.iuser.list()

    # iuser = cc.iuser.get(iusers[0])

    _print_iuser_show(iusers[0])


@utils.arg('attributes',
           metavar='<path=value>',
           nargs='+',
           action='append',
           default=[],
           help="USER attributes to modify ")
def donot_user_modify(cc, args):
    """Modify USER attributes."""

    iusers = cc.iuser.list()
    iuser = iusers[0]

    patch = utils.args_array_to_patch("replace", args.attributes[0])
    try:
        iuser = cc.iuser.update(iuser.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('USER not found: %s' % iuser.uuid)

    _print_iuser_show(iuser)
