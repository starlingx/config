#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan
from pecan import rest
import os
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log

from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import patch_api
from sysinv.api.controllers.v1 import types
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class KubeUpgradePatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return ['/state']


class KubeUpgrade(base.APIBase):
    """API representation of a Kubernetes Upgrade."""

    id = int
    "Unique ID for this entry"

    uuid = types.uuid
    "Unique UUID for this entry"

    from_version = wtypes.text
    "The from version for the kubernetes upgrade"

    to_version = wtypes.text
    "The to version for the kubernetes upgrade"

    state = wtypes.text
    "Kubernetes upgrade state"

    links = [link.Link]
    "A list containing a self link and associated kubernetes upgrade links"

    def __init__(self, **kwargs):
        self.fields = objects.kube_upgrade.fields.keys()
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    @classmethod
    def convert_with_links(cls, rpc_kube_upgrade, expand=True):
        kube_upgrade = KubeUpgrade(**rpc_kube_upgrade.as_dict())
        if not expand:
            kube_upgrade.unset_fields_except(['uuid', 'from_version',
                                              'to_version', 'state'])

        kube_upgrade.links = [
            link.Link.make_link('self', pecan.request.host_url,
                                'kube_upgrade', kube_upgrade.uuid),
            link.Link.make_link('bookmark',
                                pecan.request.host_url,
                                'kube_upgrade', kube_upgrade.uuid,
                                bookmark=True)
                         ]
        return kube_upgrade


class KubeUpgradeCollection(collection.Collection):
    """API representation of a collection of kubernetes upgrades."""

    kube_upgrades = [KubeUpgrade]
    "A list containing kubernetes upgrade objects"

    def __init__(self, **kwargs):
        self._type = 'kube_upgrades'

    @classmethod
    def convert_with_links(cls, rpc_kube_upgrade, expand=True, **kwargs):
        collection = KubeUpgradeCollection()
        collection.kube_upgrades = [KubeUpgrade.convert_with_links(p, expand)
                                    for p in rpc_kube_upgrade]
        return collection


LOCK_NAME = 'KubeUpgradeController'


class KubeUpgradeController(rest.RestController):
    """REST controller for kubernetes upgrades."""

    def __init__(self):
        self._kube_operator = kubernetes.KubeOperator()

    def _get_updates(self, patch):
        """Retrieve the updated attributes from the patch request."""
        updates = {}
        for p in patch:
            attribute = p['path'] if p['path'][0] != '/' else p['path'][1:]
            updates[attribute] = p['value']
        return updates

    @wsme_pecan.wsexpose(KubeUpgradeCollection)
    def get_all(self):
        """Retrieve a list of kubernetes upgrades."""

        kube_upgrades = pecan.request.dbapi.kube_upgrade_get_list()
        return KubeUpgradeCollection.convert_with_links(kube_upgrades)

    @wsme_pecan.wsexpose(KubeUpgrade, types.uuid)
    def get_one(self, uuid):
        """Retrieve information about the given kubernetes upgrade."""

        rpc_kube_upgrade = objects.kube_upgrade.get_by_uuid(
            pecan.request.context, uuid)
        return KubeUpgrade.convert_with_links(rpc_kube_upgrade)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(KubeUpgrade, wtypes.text, body=six.text_type)
    def post(self, to_version, body):
        """Create a new Kubernetes Upgrade and start upgrade."""

        force = body.get('force', False) is True

        # There must not already be a kubernetes upgrade in progress
        try:
            pecan.request.dbapi.kube_upgrade_get_one()
        except exception.NotFound:
            pass
        else:
            raise wsme.exc.ClientSideError(_(
                "A kubernetes upgrade is already in progress"))

        # The target version must be available
        try:
            target_version_obj = objects.kube_version.get_by_version(
                to_version)
        except exception.KubeVersionNotFound:
            raise wsme.exc.ClientSideError(_(
                "Kubernetes version %s is not available" % to_version))

        # The upgrade path must be supported
        current_kube_version = \
            self._kube_operator.kube_get_kubernetes_version()
        if not target_version_obj.can_upgrade_from(current_kube_version):
            raise wsme.exc.ClientSideError(_(
                "The installed Kubernetes version %s cannot upgrade to "
                "version %s" % (current_kube_version,
                                 target_version_obj.version)))

        # The current kubernetes version must be active
        version_states = self._kube_operator.kube_get_version_states()
        if version_states.get(current_kube_version) != \
                kubernetes.KUBE_STATE_ACTIVE:
            raise wsme.exc.ClientSideError(_(
                "The installed Kubernetes version %s is not active on all "
                "hosts" % current_kube_version))

        # The necessary patches must be applied
        api_token = None
        system = pecan.request.dbapi.isystem_get_one()
        if target_version_obj.applied_patches:
            patches_applied = patch_api.patch_is_applied(
                token=api_token,
                timeout=constants.PATCH_DEFAULT_TIMEOUT_IN_SECS,
                region_name=system.region_name,
                patches=target_version_obj.applied_patches
            )
            if not patches_applied:
                raise wsme.exc.ClientSideError(_(
                    "The following patches must be applied before starting "
                    "the kubernetes upgrade: %s" %
                    target_version_obj.applied_patches))

        # The necessary patches must be available
        if target_version_obj.available_patches:
            patches_available = patch_api.patch_is_available(
                token=api_token,
                timeout=constants.PATCH_DEFAULT_TIMEOUT_IN_SECS,
                region_name=system.region_name,
                patches=target_version_obj.available_patches
            )
            if not patches_available:
                raise wsme.exc.ClientSideError(_(
                    "The following patches must be available before starting "
                    "the kubernetes upgrade: %s" %
                    target_version_obj.available_patches))

        # TODO: check that all installed applications support new k8s version
        # TODO: check that tiller/armada support new k8s version

        # The system must be healthy from the platform perspective
        success, output = pecan.request.rpcapi.get_system_health(
            pecan.request.context, force=force)
        if not success:
            LOG.info("Health query failure during kubernetes upgrade start: %s"
                     % output)
            if os.path.exists(constants.SYSINV_RUNNING_IN_LAB) and force:
                LOG.info("Running in lab, ignoring health errors.")
            else:
                raise wsme.exc.ClientSideError(_(
                    "System is not in a valid state for kubernetes upgrade. "
                    "Run system health-query-upgrade for more details."))

        # TODO: kubernetes related health checks...

        # Tell the conductor to download the images for the new version
        pecan.request.rpcapi.kube_download_images(
            pecan.request.context, to_version)

        # Create upgrade record.
        create_values = {'from_version': current_kube_version,
                         'to_version': to_version,
                         'state': kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES}
        new_upgrade = pecan.request.dbapi.kube_upgrade_create(create_values)

        # Set the target version for each host to the current version
        update_values = {'target_version': current_kube_version}
        kube_host_upgrades = pecan.request.dbapi.kube_host_upgrade_get_list()
        for kube_host_upgrade in kube_host_upgrades:
            pecan.request.dbapi.kube_host_upgrade_update(kube_host_upgrade.id,
                                                         update_values)

        LOG.info("Starting kubernetes upgrade from version: %s to version: %s"
                 % (current_kube_version, to_version))

        return KubeUpgrade.convert_with_links(new_upgrade)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate([KubeUpgradePatchType])
    @wsme_pecan.wsexpose(KubeUpgrade, body=[KubeUpgradePatchType])
    def patch(self, patch):
        """Updates attributes of a Kubernetes Upgrade."""

        updates = self._get_updates(patch)

        # Get the current upgrade
        try:
            kube_upgrade_obj = objects.kube_upgrade.get_one(
                pecan.request.context)
        except exception.NotFound:
            raise wsme.exc.ClientSideError(_(
                "A kubernetes upgrade is not in progress"))

        if updates['state'] == kubernetes.KUBE_UPGRADING_NETWORKING:
            # Make sure upgrade is in the correct state to upgrade networking
            if kube_upgrade_obj.state != \
                    kubernetes.KUBE_UPGRADED_FIRST_MASTER:
                raise wsme.exc.ClientSideError(_(
                    "Kubernetes upgrade must be in %s state to upgrade "
                    "networking" %
                    kubernetes.KUBE_UPGRADED_FIRST_MASTER))

            # Update the upgrade state
            kube_upgrade_obj.state = kubernetes.KUBE_UPGRADING_NETWORKING
            kube_upgrade_obj.save()

            # Tell the conductor to upgrade networking
            pecan.request.rpcapi.kube_upgrade_networking(
                pecan.request.context, kube_upgrade_obj.to_version)

            return KubeUpgrade.convert_with_links(kube_upgrade_obj)

        elif updates['state'] == kubernetes.KUBE_UPGRADE_COMPLETE:
            # Make sure upgrade is in the correct state to complete
            if kube_upgrade_obj.state != \
                    kubernetes.KUBE_UPGRADING_KUBELETS:
                raise wsme.exc.ClientSideError(_(
                    "Kubernetes upgrade must be in %s state to complete" %
                    kubernetes.KUBE_UPGRADING_KUBELETS))

            # Make sure the target version is active
            version_states = self._kube_operator.kube_get_version_states()
            if version_states.get(kube_upgrade_obj.to_version, None) != \
                    kubernetes.KUBE_STATE_ACTIVE:
                raise wsme.exc.ClientSideError(_(
                    "Kubernetes to_version must be active to complete"))

            # All is well, mark the upgrade as complete
            kube_upgrade_obj.state = kubernetes.KUBE_UPGRADE_COMPLETE
            kube_upgrade_obj.save()
            return KubeUpgrade.convert_with_links(kube_upgrade_obj)

        else:
            raise wsme.exc.ClientSideError(_(
                "Invalid state %s supplied" % updates['state']))

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(KubeUpgrade)
    def delete(self):
        """Delete Kubernetes Upgrade."""

        # An upgrade must be in progress
        try:
            kube_upgrade_obj = pecan.request.dbapi.kube_upgrade_get_one()
        except exception.NotFound:
            raise wsme.exc.ClientSideError(_(
                "A kubernetes upgrade is not in progress"))

        # The upgrade must be complete
        if kube_upgrade_obj.state != \
                kubernetes.KUBE_UPGRADE_COMPLETE:
            raise wsme.exc.ClientSideError(_(
                "Kubernetes upgrade must be in %s state to delete" %
                kubernetes.KUBE_UPGRADE_COMPLETE))

        # Delete the upgrade
        pecan.request.dbapi.kube_upgrade_destroy(kube_upgrade_obj.id)
