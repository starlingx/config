# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014-2018 Wind River, Inc.
#
# Copyright 2013 UnitedStack Inc.
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

import jsonpatch
import pecan
import wsme
import wsmeext.pecan as wsme_pecan
from pecan import rest
from sysinv import objects
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _
from wsme import types as wtypes

LOG = log.getLogger(__name__)

IUSERS_ROOT_USERNAME = 'wrsroot'


class UserPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return ['/root_sig', '/passwd_expiry_days', '/passwd_hash']


class User(base.APIBase):
    """API representation of a user.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    an user.
    """

    uuid = types.uuid
    "Unique UUID for this user"

    root_sig = wtypes.text
    "Represent the root_sig of the iuser."

    # The passwd_hash is required for orchestration
    passwd_hash = wtypes.text
    "Represent the password hash of the iuser."

    passwd_expiry_days = int
    "Represent the password aging of the iuser."

    action = wtypes.text
    "Represent the action on the iuser."

    forisystemid = int
    "The isystemid that this iuser belongs to"

    isystem_uuid = types.uuid
    "The UUID of the system this user belongs to"

    links = [link.Link]
    "A list containing a self link and associated user links"

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    def __init__(self, **kwargs):
        self.fields = list(objects.user.fields.keys())
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        # 'action' is not part of objects.iuser.fields
        # (it's an API-only attribute)
        self.fields.append('action')
        setattr(self, 'action', kwargs.get('action', None))

    @classmethod
    def convert_with_links(cls, rpc_user, expand=True):
        # fields = ['uuid', 'address'] if not expand else None
        # user = iuser.from_rpc_object(rpc_user, fields)

        user = User(**rpc_user.as_dict())
        if not expand:
            user.unset_fields_except(['uuid',
                                      'root_sig',
                                      'passwd_hash',
                                      'passwd_expiry_days',
                                      'isystem_uuid',
                                      'created_at',
                                      'updated_at'])

        # never expose the isystem_id attribute
        user.isystem_id = wtypes.Unset

        # never expose the isystem_id attribute, allow exposure for now
        # user.forisystemid = wtypes.Unset

        user.links = [link.Link.make_link('self', pecan.request.host_url,
                                         'iusers', user.uuid),
                     link.Link.make_link('bookmark',
                                         pecan.request.host_url,
                                         'iusers', user.uuid,
                                         bookmark=True)
                      ]

        return user


class UserCollection(collection.Collection):
    """API representation of a collection of users."""

    iusers = [User]
    "A list containing user objects"

    def __init__(self, **kwargs):
        self._type = 'iusers'

    @classmethod
    def convert_with_links(cls, rpc_users, limit, url=None,
                           expand=False, **kwargs):
        collection = UserCollection()
        collection.iusers = [User.convert_with_links(p, expand)
                             for p in rpc_users]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


##############
# UTILS
##############
LOCK_NAME = 'UserController'


class UserController(rest.RestController):
    """REST controller for iusers."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_isystems=False):
        self._from_isystems = from_isystems

    def _get_users_collection(self, isystem_uuid, marker, limit, sort_key,
                             sort_dir, expand=False, resource_url=None):

        if self._from_isystems and not isystem_uuid:
            raise exception.InvalidParameterValue(_(
                  "System id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.user.get_by_uuid(pecan.request.context,
                                                  marker)

        if isystem_uuid:
            users = pecan.request.dbapi.iuser_get_by_isystem(
                                                    isystem_uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
        else:
            users = pecan.request.dbapi.iuser_get_list(limit, marker_obj,
                                                     sort_key=sort_key,
                                                     sort_dir=sort_dir)

        return UserCollection.convert_with_links(users, limit,
                                                 url=resource_url,
                                                 expand=expand,
                                                 sort_key=sort_key,
                                                 sort_dir=sort_dir)

    @wsme_pecan.wsexpose(UserCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, isystem_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of users. Only one per system"""

        return self._get_users_collection(isystem_uuid, marker, limit,
                                          sort_key, sort_dir)

    @wsme_pecan.wsexpose(UserCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, isystem_uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of users with detail."""
        # NOTE(lucasagomes): /detail should only work agaist collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "iusers":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['users', 'detail'])
        return self._get_users_collection(isystem_uuid,
                                          marker, limit,
                                          sort_key, sort_dir,
                                          expand, resource_url)

    @wsme_pecan.wsexpose(User, types.uuid)
    def get_one(self, user_uuid):
        """Retrieve information about the given user."""
        if self._from_isystems:
            raise exception.OperationNotPermitted

        rpc_user = objects.user.get_by_uuid(pecan.request.context, user_uuid)
        return User.convert_with_links(rpc_user)

    @wsme_pecan.wsexpose(User, body=User)
    def post(self, user):
        """Create a new user."""
        raise exception.OperationNotPermitted

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [UserPatchType])
    @wsme_pecan.wsexpose(User, types.uuid,
                         body=[UserPatchType])
    def patch(self, user_uuid, patch):
        """Update the current user configuration."""
        if self._from_isystems:
            raise exception.OperationNotPermitted

        rpc_user = objects.user.get_by_uuid(pecan.request.context, user_uuid)

        action = None
        for p in patch:
            if '/action' in p['path']:
                value = p['value']
                patch.remove(p)
                if value in (constants.APPLY_ACTION, constants.INSTALL_ACTION):
                    action = value
                break

        patch_obj = jsonpatch.JsonPatch(patch)

        state_rel_path = ['/uuid', '/id', '/forisystemid', '/isystem_uuid']
        if any(p['path'] in state_rel_path for p in patch_obj):
            raise wsme.exc.ClientSideError(_("The following fields can not be "
                                             "modified: %s" %
                                             state_rel_path))

        for p in patch_obj:
            if p['path'] == '/isystem_uuid':
                isystem = objects.system.get_by_uuid(pecan.request.context,
                                                     p['value'])
                p['path'] = '/forisystemid'
                p['value'] = isystem.id

        try:
            user = User(**jsonpatch.apply_patch(rpc_user.as_dict(),
                                                patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        user = user.as_dict()

        try:
            # Update only the fields that have changed
            for field in objects.user.fields:
                if rpc_user[field] != user[field]:
                    rpc_user[field] = user[field]

            # N.B: Additionally, we need to recompute
            # the password and age for this iuser and mark
            # those fields as changed. These fields will ALWAYS
            # come in via a SysInv Modify REST msg.
            #
            # This is needed so that the i_users table is updated
            # with the password and age. We use these during an
            # upgrade to configure the users on an upgraded controller.

            rpc_user.save()

            if action == constants.APPLY_ACTION:
                # perform rpc to conductor to perform config apply
                pecan.request.rpcapi.update_user_config(pecan.request.context)

            return User.convert_with_links(rpc_user)

        except exception.HTTPNotFound:
            msg = _("User wrsroot update failed: system %s user %s : patch %s"
                    % (isystem['systemname'], user, patch))
            raise wsme.exc.ClientSideError(msg)
        except exception.KeyError:
            msg = _("Cannot retrieve shadow entry for wrsroot: system %s : patch %s"
                    % (isystem['systemname'], patch))
            raise wsme.exc.ClientSideError(msg)

    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, user_uuid):
        """Delete a user."""
        raise exception.OperationNotPermitted
