#
# Copyright (c) 2015-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#
import pecan
from pecan import rest, expose
import os
import six
import socket
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.api.controllers.v1 import vim_api
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.common import constants
from sysinv import objects
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _

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
        self.fields = objects.software_upgrade.fields.keys()
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


LOCK_NAME = 'UpgradeController'


class UpgradeController(rest.RestController):
    """REST controller for Software Upgrades."""

    _custom_actions = {
        'check_reinstall': ['GET'],
        'in_upgrade': ['GET'],
    }

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    def _get_upgrade_collection(self, marker=None, limit=None,
                                sort_key=None, sort_dir=None,
                                expand=False, resource_url=None):
        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        marker_obj = None
        if marker:
            marker_obj = objects.software_upgrade.get_by_uuid(
                pecan.request.context, marker)

        upgrades = pecan.request.dbapi.software_upgrade_get_list(
                limit=limit, marker=marker_obj,
                sort_key=sort_key, sort_dir=sort_dir)

        return UpgradeCollection.convert_with_links(
            upgrades, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    def _get_updates(self, patch):
        """Retrieve the updated attributes from the patch request."""
        updates = {}
        for p in patch:
            attribute = p['path'] if p['path'][0] != '/' else p['path'][1:]
            updates[attribute] = p['value']
        return updates

    @expose('json')
    def check_reinstall(self):
        reinstall_necessary = False
        try:
            upgrade = pecan.request.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            pass
        else:
            controller_0 = pecan.request.dbapi.ihost_get_by_hostname(
                constants.CONTROLLER_0_HOSTNAME)
            host_upgrade = pecan.request.dbapi.host_upgrade_get_by_host(
                controller_0.id)

            if host_upgrade.target_load == upgrade.to_load or \
                    host_upgrade.software_load == upgrade.to_load:
                reinstall_necessary = True

        return {'reinstall_necessary': reinstall_necessary}

    @wsme_pecan.wsexpose(UpgradeCollection, types.uuid, int, wtypes.text,
                         wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of upgrades."""
        return self._get_upgrade_collection(marker, limit, sort_key, sort_dir)

    @wsme_pecan.wsexpose(Upgrade, types.uuid)
    def get_one(self, uuid):
        """Retrieve information about the given upgrade."""
        rpc_upgrade = objects.software_upgrade.get_by_uuid(
            pecan.request.context, uuid)
        return Upgrade.convert_with_links(rpc_upgrade)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Upgrade, body=six.text_type)
    def post(self, body):
        """Create a new Software Upgrade instance and start upgrade."""

        # Only start the upgrade from controller-0
        if socket.gethostname() != constants.CONTROLLER_0_HOSTNAME:
            raise wsme.exc.ClientSideError(_(
                "upgrade-start rejected: An upgrade can only be started "
                "when %s is active." % constants.CONTROLLER_0_HOSTNAME))

        # There must not already be an upgrade in progress
        try:
            pecan.request.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            pass
        else:
            raise wsme.exc.ClientSideError(_(
                "upgrade-start rejected: An upgrade is already in progress."))

        # Determine the from_load and to_load
        loads = pecan.request.dbapi.load_get_list()
        from_load = cutils.get_active_load(loads)
        from_version = from_load.software_version
        to_load = cutils.get_imported_load(loads)
        to_version = to_load.software_version

        controller_0 = pecan.request.dbapi.ihost_get_by_hostname(
            constants.CONTROLLER_0_HOSTNAME)

        force = body.get('force', False) is True

        try:
            # Set the upgrade flag in VIM
            # This prevents VM changes during the upgrade and health checks
            if utils.get_system_mode() != constants.SYSTEM_MODE_SIMPLEX:
                vim_api.set_vim_upgrade_state(controller_0, True)
        except Exception as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_(
                "upgrade-start rejected: Unable to set VIM upgrade state"))

        success, output = pecan.request.rpcapi.get_system_health(
                pecan.request.context, force=force, upgrade=True)

        if not success:
            LOG.info("Health audit failure during upgrade start. Health "
                     "query results: %s" % output)
            if os.path.exists(constants.SYSINV_RUNNING_IN_LAB) and force:
                LOG.info("Running in lab, ignoring health errors.")
            else:
                vim_api.set_vim_upgrade_state(controller_0, False)
                raise wsme.exc.ClientSideError(_(
                    "upgrade-start rejected: System is not in a valid state "
                    "for upgrades. Run system health-query-upgrade for more "
                    "details."))

        # Create upgrade record. Must do this before the prepare_upgrade so
        # the upgrade record exists when the database is dumped.
        create_values = {'from_load': from_load.id,
                         'to_load': to_load.id,
                         'state': constants.UPGRADE_STARTING}
        new_upgrade = None
        try:
            new_upgrade = pecan.request.dbapi.software_upgrade_create(
                create_values)
        except Exception as ex:
            vim_api.set_vim_upgrade_state(controller_0, False)
            LOG.exception(ex)
            raise

        # Prepare for upgrade
        LOG.info("Starting upgrade from release: %s to release: %s" %
                 (from_version, to_version))

        try:
            pecan.request.rpcapi.start_upgrade(pecan.request.context,
                                               new_upgrade)
        except Exception as ex:
            vim_api.set_vim_upgrade_state(controller_0, False)
            pecan.request.dbapi.software_upgrade_destroy(new_upgrade.uuid)
            LOG.exception(ex)
            raise

        return Upgrade.convert_with_links(new_upgrade)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate([UpgradePatchType])
    @wsme_pecan.wsexpose(Upgrade, body=[UpgradePatchType])
    def patch(self, patch):
        """Updates attributes of Software Upgrade."""
        updates = self._get_updates(patch)

        # Get the current upgrade
        try:
            upgrade = pecan.request.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            raise wsme.exc.ClientSideError(_(
                "operation rejected: An upgrade is not in progress."))

        to_load = pecan.request.dbapi.load_get(upgrade.to_load)
        to_version = to_load.software_version

        if updates['state'] == constants.UPGRADE_ABORTING:
            # Make sure upgrade wasn't already aborted
            if upgrade.state in [constants.UPGRADE_ABORTING,
                                 constants.UPGRADE_ABORTING_ROLLBACK]:
                raise wsme.exc.ClientSideError(_(
                    "upgrade-abort rejected: Upgrade already aborted "))

            # Abort the upgrade
            rpc_upgrade = pecan.request.rpcapi.abort_upgrade(
                pecan.request.context, upgrade)

            return Upgrade.convert_with_links(rpc_upgrade)

        # if an activation is requested, make sure we are not already in
        # activating state or have already activated
        elif updates['state'] == constants.UPGRADE_ACTIVATION_REQUESTED:

            if upgrade.state in [constants.UPGRADE_ACTIVATING,
                                 constants.UPGRADE_ACTIVATION_COMPLETE]:
                raise wsme.exc.ClientSideError(_(
                    "upgrade-activate rejected: "
                    "Upgrade already activating or activated."))

            hosts = pecan.request.dbapi.ihost_get_list()
            # All hosts must be unlocked and enabled, and running the new
            # release
            for host in hosts:
                if host['administrative'] != constants.ADMIN_UNLOCKED or \
                        host['operational'] != constants.OPERATIONAL_ENABLED:
                    raise wsme.exc.ClientSideError(_(
                        "upgrade-activate rejected: All hosts must be unlocked"
                        " and enabled before the upgrade can be activated."))
            for host in hosts:
                host_upgrade = objects.host_upgrade.get_by_host_id(
                    pecan.request.context, host.id)
                if (host_upgrade.target_load != to_load.id or
                        host_upgrade.software_load != to_load.id):
                    raise wsme.exc.ClientSideError(_(
                        "upgrade-activate rejected: All hosts must be "
                        "upgraded before the upgrade can be activated."))

            # we need to make sure the state is updated before calling the rpc
            rpc_upgrade = pecan.request.dbapi.software_upgrade_update(
                upgrade.uuid, updates)
            pecan.request.rpcapi.activate_upgrade(pecan.request.context,
                                                  upgrade)

            # make sure the to/from loads are in the correct state
            pecan.request.dbapi.set_upgrade_loads_state(
                upgrade,
                constants.ACTIVE_LOAD_STATE,
                constants.IMPORTED_LOAD_STATE)

            LOG.info("Setting SW_VERSION to release: %s" % to_version)
            system = pecan.request.dbapi.isystem_get_one()
            pecan.request.dbapi.isystem_update(
                system.uuid, {'software_version': to_version})

            return Upgrade.convert_with_links(rpc_upgrade)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Upgrade)
    def delete(self):
        """Complete upgrade and delete Software Upgrade instance."""

        # There must be an upgrade in progress
        try:
            upgrade = pecan.request.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            raise wsme.exc.ClientSideError(_(
                "upgrade-complete rejected: An upgrade is not in progress."))

        # Only complete the upgrade from controller-0. This is to ensure that
        # we can clean up all the upgrades related files, some of which are
        # local to controller-0.
        if socket.gethostname() != constants.CONTROLLER_0_HOSTNAME:
            raise wsme.exc.ClientSideError(_(
                "upgrade-complete rejected: An upgrade can only be completed "
                "when %s is active." % constants.CONTROLLER_0_HOSTNAME))

        from_load = pecan.request.dbapi.load_get(upgrade.from_load)

        if upgrade.state == constants.UPGRADE_ACTIVATION_COMPLETE:
            # Complete the upgrade
            current_abort_state = upgrade.state
            upgrade = pecan.request.dbapi.software_upgrade_update(
                upgrade.uuid, {'state': constants.UPGRADE_COMPLETING})
            try:
                pecan.request.rpcapi.complete_upgrade(
                    pecan.request.context, upgrade, current_abort_state)
            except Exception as ex:
                LOG.exception(ex)
                pecan.request.dbapi.software_upgrade_update(
                    upgrade.uuid,
                    {'state': constants.UPGRADE_ACTIVATION_COMPLETE})
                raise

        elif upgrade.state in [constants.UPGRADE_ABORTING,
                               constants.UPGRADE_ABORTING_ROLLBACK]:
            # All hosts must be running the old release
            hosts = pecan.request.dbapi.ihost_get_list()
            for host in hosts:
                host_upgrade = objects.host_upgrade.get_by_host_id(
                    pecan.request.context, host.id)
                if (host_upgrade.target_load != from_load.id or
                        host_upgrade.software_load != from_load.id):
                    raise wsme.exc.ClientSideError(_(
                        "upgrade-abort rejected: All hosts must be downgraded "
                        "before the upgrade can be aborted."))

            current_abort_state = upgrade.state

            upgrade = pecan.request.dbapi.software_upgrade_update(
                upgrade.uuid, {'state': constants.UPGRADE_ABORT_COMPLETING})

            try:
                pecan.request.rpcapi.complete_upgrade(
                    pecan.request.context, upgrade, current_abort_state)
            except Exception as ex:
                LOG.exception(ex)
                pecan.request.dbapi.software_upgrade_update(
                    upgrade.uuid, {'state': current_abort_state})
                raise

        else:
            raise wsme.exc.ClientSideError(_(
                "upgrade-complete rejected: An upgrade can only be completed "
                "when in the %s or %s state." %
                (constants.UPGRADE_ACTIVATION_COMPLETE,
                    constants.UPGRADE_ABORTING)))

        return Upgrade.convert_with_links(upgrade)

    @wsme_pecan.wsexpose(wtypes.text, six.text_type)
    def in_upgrade(self, uuid):
        # uuid is added here for potential future use
        try:
            upgrade = pecan.request.dbapi.software_upgrade_get_one()

            # We will wipe all the disks in the case of a host reinstall
            # during a downgrade.
            if upgrade.state in [constants.UPGRADE_ABORTING_ROLLBACK]:
                LOG.info("in_upgrade status. Aborting upgrade, host reinstall")
                return False

        except exception.NotFound:
            return False
        return True
