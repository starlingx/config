#
# Copyright (c) 2015-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

import pecan
from pecan import rest
from pecan import expose
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.common import constants

LOG = log.getLogger(__name__)


class UpgradePatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return ['/state']


class Upgrade(base.APIBase):
    """API representation of a Software Upgrade instance.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of a upgrade
    """

    id = int
    "Unique ID for this entry"

    uuid = types.uuid
    "Unique UUID for this entry"

    state = wtypes.text
    "Software upgrade state."

    from_load = int
    "The load id that software upgrading from"

    to_load = int
    "The load id that software upgrading to"

    links = [link.Link]
    "A list containing a self link and associated upgrade links"

    from_release = wtypes.text
    "The load version that software upgrading from"

    to_release = wtypes.text
    "The load version that software upgrading to"

    def __init__(self, **kwargs):
        self.fields = list()
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    @classmethod
    def convert_with_links(cls, rpc_upgrade, expand=True):
        upgrade = Upgrade(**rpc_upgrade.as_dict())
        if not expand:
            upgrade.unset_fields_except(['uuid', 'state', 'from_release',
                                         'to_release'])

        upgrade.links = [link.Link.make_link('self', pecan.request.host_url,
                                             'upgrades', upgrade.uuid),
                         link.Link.make_link('bookmark',
                                             pecan.request.host_url,
                                             'upgrades', upgrade.uuid,
                                             bookmark=True)
                         ]
        return upgrade


class UpgradeCollection(collection.Collection):
    """API representation of a collection of software upgrades."""

    upgrades = [Upgrade]
    "A list containing Software Upgrade objects"

    def __init__(self, **kwargs):
        self._type = 'upgrades'

    @classmethod
    def convert_with_links(cls, rpc_upgrade, limit, url=None, expand=False,
                           **kwargs):
        collection = UpgradeCollection()
        collection.upgrades = [Upgrade.convert_with_links(p, expand)
                               for p in rpc_upgrade]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


ERROR_FILE = '/tmp/upgrade_fail_msg'
LOCK_NAME = 'UpgradeController'


class UpgradeController(rest.RestController):
    """REST controller for Software Upgrades."""

    _custom_actions = {
        'check_reinstall': ['GET'],
        'in_upgrade': ['GET'],
        'upgrade_in_progress': ['GET'],
        'get_upgrade_msg': ['GET'],
    }

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    @staticmethod
    def check_restore_in_progress():
        try:
            pecan.request.dbapi.restore_get_one(
                           filters={'state': constants.RESTORE_STATE_IN_PROGRESS})
        except exception.NotFound:
            return False
        else:
            return True

    def _get_updates(self, patch):
        """Retrieve the updated attributes from the patch request."""
        updates = {}
        for p in patch:
            attribute = p['path'] if p['path'][0] != '/' else p['path'][1:]
            updates[attribute] = p['value']
        return updates

    @expose('json')
    def check_reinstall(self):
        raise NotImplementedError("This API is deprecated.")

    @expose('json')
    def get_upgrade_msg(self):
        raise NotImplementedError("This API is deprecated.")

    @wsme_pecan.wsexpose(UpgradeCollection, types.uuid, int, wtypes.text,
                         wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of upgrades."""
        raise NotImplementedError("This API is deprecated.")

    @wsme_pecan.wsexpose(Upgrade, types.uuid)
    def get_one(self, uuid):
        """Retrieve information about the given upgrade."""
        raise NotImplementedError("This API is deprecated.")

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Upgrade, body=six.text_type)
    def post(self, body):
        """Create a new Software Upgrade instance and start upgrade."""

        raise NotImplementedError("This API is deprecated.")

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate([UpgradePatchType])
    @wsme_pecan.wsexpose(Upgrade, body=[UpgradePatchType])
    def patch(self, patch):
        """Updates attributes of Software Upgrade."""
        raise NotImplementedError("This API is deprecated.")

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Upgrade)
    def delete(self):
        """Complete upgrade and delete Software Upgrade instance."""

        raise NotImplementedError("This API is deprecated.")

    @wsme_pecan.wsexpose(wtypes.text, six.text_type)
    def in_upgrade(self, uuid):
        raise NotImplementedError("This API is deprecated.")

    @wsme_pecan.wsexpose(wtypes.text, six.text_type)
    def upgrade_in_progress(self, uuid):
        raise NotImplementedError("This API is deprecated.")
