#
# Copyright (c) 2019-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from fm_api import constants as fm_constants
from fm_api import fm_api

from distutils.version import LooseVersion
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
from sysinv.api.controllers.v1 import types
from sysinv.common import constants
from sysinv.common import dc_api
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import usm_service as usm_service
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
        self.fields = list(objects.kube_upgrade.fields.keys())
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

    def _check_applied_apps_compatibility(self, from_version, to_version):
        """Ensure that applied applications are compatible with
           Kubernetes versions across the upgrade process

        :param from_version: Initial Kubernetes version
        :param to_version: Target Kubernetes version
        """

        system = pecan.request.dbapi.isystem_get_one()
        if system.system_mode == constants.SYSTEM_MODE_SIMPLEX:
            next_versions = self._kube_operator.kube_get_higher_patch_version(from_version,
                                                                              to_version)
        else:
            next_versions = [to_version]

        if not next_versions:
            raise wsme.exc.ClientSideError(_("Error while retrieving Kubernetes intermediate "
                                             "versions"))

        incompatible_apps = set()
        lower_k8s_version_from_incompatible_apps = None
        from_version = from_version.lstrip('v')
        to_version = to_version.lstrip('v')
        next_versions = [x.lstrip('v') for x in next_versions]
        apps = pecan.request.dbapi.kube_app_get_all()
        for app in apps:
            if app.status != constants.APP_APPLY_SUCCESS:
                continue

            # Applications with timing=pre need to be compatible with the current,
            # intermediate and target k8s versions:
            pre_update_compatible = pecan.request.dbapi.kube_app_bundle_is_k8s_compatible(
                name=app.name,
                k8s_timing=constants.APP_METADATA_TIMING_PRE,
                current_k8s_version=from_version,
                target_k8s_version=to_version)
            if not pre_update_compatible:
                LOG.debug("Unable to find a version of application {} to be pre updated."
                          .format(app.name))

            # Check if the target version is within the range of the applied app
            post_update_compatible = False
            applied_app_target_compatible = False
            applied_app_kube_min_version, applied_app_kube_max_version = \
                    cutils.get_app_supported_kube_version(app.name, app.app_version)
            if applied_app_kube_min_version is not None:
                applied_app_kube_min_version = str(applied_app_kube_min_version).lstrip('v')
            if applied_app_kube_max_version is not None:
                applied_app_kube_max_version = str(applied_app_kube_max_version).lstrip('v')
            if kubernetes.is_kube_version_supported(
                    to_version, applied_app_kube_min_version, applied_app_kube_max_version):
                applied_app_target_compatible = True

                # Applications with timing=post should be compatible with the target k8s version.
                # Compatibility with current or intermediate versions is not required:
                post_update_compatible = \
                    pecan.request.dbapi.kube_app_bundle_is_k8s_compatible(
                        name=app.name,
                        k8s_timing=constants.APP_METADATA_TIMING_POST,
                        target_k8s_version=to_version)

            if not post_update_compatible:
                LOG.debug("Unable to find a version of application {} to be post updated."
                          .format(app.name))

            if not pre_update_compatible and not post_update_compatible:
                # If the app cannot be pre or post updated, check if we can proceed with
                # the current applied version.
                if applied_app_target_compatible:
                    LOG.info("No updates found for application {} during Kubernetes upgrade "
                             "to {} but current applied version {} is supported.".format(
                                 app.name,
                                 to_version,
                                 app.app_version))
                    continue

                max_compatible_version = \
                    pecan.request.dbapi.kube_app_bundle_max_k8s_compatible_by_name(
                        name=app.name,
                        current_k8s_version=from_version,
                        target_k8s_version=to_version)
                if max_compatible_version is None:
                    max_compatible_version = from_version
                if (LooseVersion(applied_app_kube_max_version) >
                        LooseVersion(max_compatible_version)):
                    max_compatible_version = applied_app_kube_max_version

                incompatible_versions = [x for x in next_versions if LooseVersion(x) >
                                        LooseVersion(max_compatible_version)]
                LOG.error("Unable to find a suitable version of application {} "
                          "compatible with the following Kubernetes versions: {}."
                          .format(app.name, ', '.join(str(s) for s in incompatible_versions)))

                incompatible_apps.add(app.name)
                if (lower_k8s_version_from_incompatible_apps is None or
                        LooseVersion(max_compatible_version) <
                        LooseVersion(lower_k8s_version_from_incompatible_apps)):
                    lower_k8s_version_from_incompatible_apps = max_compatible_version

        # If the lowest compatible version found amongst all apps is out of the version range we
        # support then there is no upgrade path available.
        # If the lowest compatible version found amongst all apps is within the range we support
        # then inform the highest supported version.
        if (lower_k8s_version_from_incompatible_apps and
                LooseVersion(lower_k8s_version_from_incompatible_apps) <
                LooseVersion(next_versions[0])):
            raise wsme.exc.ClientSideError(_(
                "The following apps are incompatible with intermediate/target Kubernetes "
                "versions: {}. No upgrade path available to Kubernetes version {}."
                .format(', '.join(str(s) for s in incompatible_apps), to_version)))
        elif lower_k8s_version_from_incompatible_apps:
            highest_supported_version = next(
                x for x in list(reversed(next_versions))
                if (LooseVersion(x) <=
                LooseVersion(lower_k8s_version_from_incompatible_apps)))

            raise wsme.exc.ClientSideError(_(
                "The following apps are incompatible with intermediate/target Kubernetes "
                "versions: {}. The system can be upgraded up to Kubernetes {}."
                .format(', '.join(str(s) for s in incompatible_apps), highest_supported_version)))

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
        alarm_ignore_list = body.get('alarm_ignore_list')
        system = pecan.request.dbapi.isystem_get_one()

        # There must not be a platform upgrade in progress
        try:
            usm_service.get_platform_upgrade(pecan.request.dbapi)
        except exception.NotFound:
            pass
        else:
            raise wsme.exc.ClientSideError(_(
                "A kubernetes upgrade cannot be done while a platform upgrade "
                "is in progress"))

        # There must not already be a kubernetes upgrade in progress
        try:
            pecan.request.dbapi.kube_upgrade_get_one()
        except exception.NotFound:
            pass
        else:
            raise wsme.exc.ClientSideError(_(
                "A kubernetes upgrade is already in progress"))

        # Check whether target version is available or not
        try:
            to_version = to_version.lower()
            if not to_version.startswith('v'):
                to_version = "v{}".format(to_version)
            target_version_obj = objects.kube_version.get_by_version(
                to_version)
        except exception.KubeVersionNotFound:
            raise wsme.exc.ClientSideError(_(
                "Kubernetes version %s is not available" % to_version))

        # The upgrade path must be supported
        current_kube_version = self._kube_operator.kube_get_kubernetes_version()
        version_states = self._kube_operator.kube_get_version_states()

        # The target version must be available state
        if system.system_mode == constants.SYSTEM_MODE_SIMPLEX:
            if version_states.get(to_version) != kubernetes.KUBE_STATE_AVAILABLE:
                raise wsme.exc.ClientSideError(_(
                    "The target Kubernetes version %s is not in "
                    "available state" % (target_version_obj.version)))
        else:
            if not target_version_obj.can_upgrade_from(current_kube_version):
                raise wsme.exc.ClientSideError(_(
                    "The installed Kubernetes version %s cannot upgrade to "
                    "version %s" % (current_kube_version,
                                    target_version_obj.version)))

        # The current kubernetes version must be active
        if version_states.get(current_kube_version) != \
                kubernetes.KUBE_STATE_ACTIVE:
            raise wsme.exc.ClientSideError(_(
                "The installed Kubernetes version %s is not active on all "
                "hosts" % current_kube_version))

        # The system must be healthy
        success, output = pecan.request.rpcapi.get_system_health(
            pecan.request.context,
            force=force,
            kube_upgrade=True,
            alarm_ignore_list=alarm_ignore_list)
        if not success:
            LOG.info("Health query failure during kubernetes upgrade start: %s"
                     % output)
            if os.path.exists(constants.SYSINV_RUNNING_IN_LAB) and force:
                LOG.info("Running in lab, ignoring health errors.")
            else:
                raise wsme.exc.ClientSideError(_(
                    "System is not in a valid state for kubernetes upgrade. "
                    "Run system health-query-kube-upgrade for more details."))

        # Check app compatibility
        self._check_applied_apps_compatibility(current_kube_version, to_version)

        # Create upgrade record.
        create_values = {'from_version': current_kube_version,
                         'to_version': to_version,
                         'state': kubernetes.KUBE_UPGRADE_STARTED}
        new_upgrade = pecan.request.dbapi.kube_upgrade_create(create_values)

        # Set the target version for each host to the current version
        update_values = {'target_version': current_kube_version}
        kube_host_upgrades = pecan.request.dbapi.kube_host_upgrade_get_list()
        for kube_host_upgrade in kube_host_upgrades:
            pecan.request.dbapi.kube_host_upgrade_update(kube_host_upgrade.id,
                                                         update_values)
        # Raise alarm to show a kubernetes upgrade is in progress
        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                        constants.CONTROLLER_HOSTNAME)
        fault = fm_api.Fault(
            alarm_id=fm_constants.FM_ALARM_ID_KUBE_UPGRADE_IN_PROGRESS,
            alarm_state=fm_constants.FM_ALARM_STATE_SET,
            entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
            entity_instance_id=entity_instance_id,
            severity=fm_constants.FM_ALARM_SEVERITY_MINOR,
            reason_text="Kubernetes upgrade in progress.",
            # operational
            alarm_type=fm_constants.FM_ALARM_TYPE_7,
            # congestion
            probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_8,
            proposed_repair_action="No action required.",
            service_affecting=False)
        fm_api.FaultAPIs().set_fault(fault)

        # Set the new kubeadm version in the DB.
        # This will not actually change the executable version until we apply a
        # puppet manifest that makes use of it.
        kube_cmd_versions = objects.kube_cmd_version.get(
            pecan.request.context)
        kube_cmd_versions.kubeadm_version = to_version.lstrip('v')
        kube_cmd_versions.save()

        LOG.info("Started kubernetes upgrade from version: %s to version: %s"
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

        if updates['state'] and updates['state'].split('-')[-1] == 'failed':
            if kube_upgrade_obj.state in [
                    kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES,
                    kubernetes.KUBE_PRE_UPDATING_APPS,
                    kubernetes.KUBE_UPGRADING_FIRST_MASTER,
                    kubernetes.KUBE_UPGRADING_SECOND_MASTER,
                    kubernetes.KUBE_UPGRADING_STORAGE,
                    kubernetes.KUBE_UPGRADING_NETWORKING,
                    kubernetes.KUBE_POST_UPDATING_APPS]:
                kube_upgrade_obj.state = updates['state']
                kube_upgrade_obj.save()
                LOG.info("Kubernetes upgrade state is changed to %s" % updates['state'])
                return KubeUpgrade.convert_with_links(kube_upgrade_obj)
            else:
                raise wsme.exc.ClientSideError(_(
                    "A kubernetes upgrade is in %s state cannot be set to failed"
                    % kube_upgrade_obj.state))

        elif updates['state'] == kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES:
            # Make sure upgrade is in the correct state to download images
            if kube_upgrade_obj.state not in [
                    kubernetes.KUBE_UPGRADE_STARTED,
                    kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED]:
                raise wsme.exc.ClientSideError(_(
                    "Kubernetes upgrade must be in %s or %s state to download "
                    "images" %
                    (kubernetes.KUBE_UPGRADE_STARTED,
                     kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED)))

            # Update the upgrade state
            kube_upgrade_obj.state = kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES
            kube_upgrade_obj.save()

            # Tell the conductor to download the images for the new version
            pecan.request.rpcapi.kube_download_images(
                pecan.request.context, kube_upgrade_obj.to_version)

            LOG.info("Downloading kubernetes images for version: %s" %
                kube_upgrade_obj.to_version)
            return KubeUpgrade.convert_with_links(kube_upgrade_obj)

        elif updates['state'] == kubernetes.KUBE_PRE_UPDATING_APPS:
            # Make sure upgrade is in the correct state to update apps
            if kube_upgrade_obj.state not in [
                    kubernetes.KUBE_UPGRADE_DOWNLOADED_IMAGES,
                    kubernetes.KUBE_PRE_UPDATING_APPS_FAILED]:
                raise wsme.exc.ClientSideError(_(
                    "Kubernetes upgrade must be in %s or %s state to "
                    "update applications" %
                    (kubernetes.KUBE_UPGRADE_DOWNLOADED_IMAGES,
                     kubernetes.KUBE_PRE_UPDATING_APPS_FAILED)))

            # Update the upgrade state
            kube_upgrade_obj.state = kubernetes.KUBE_PRE_UPDATING_APPS
            kube_upgrade_obj.save()

            # Tell the conductor to update the required apps
            pecan.request.rpcapi.kube_pre_application_update(pecan.request.context,
                                                             kube_upgrade_obj.to_version)

            LOG.info("Updating applications to match target Kubernetes version %s" %
                     kube_upgrade_obj.to_version)
            return KubeUpgrade.convert_with_links(kube_upgrade_obj)

        elif updates['state'] == kubernetes.KUBE_UPGRADING_NETWORKING:
            # Make sure upgrade is in the correct state to upgrade networking
            if kube_upgrade_obj.state not in [
                    kubernetes.KUBE_PRE_UPDATED_APPS,
                    kubernetes.KUBE_UPGRADING_NETWORKING_FAILED]:
                raise wsme.exc.ClientSideError(_(
                    "Kubernetes upgrade must be in %s or %s state to "
                    "upgrade networking" %
                    (kubernetes.KUBE_PRE_UPDATED_APPS,
                     kubernetes.KUBE_UPGRADING_NETWORKING_FAILED)))

            # Update the upgrade state
            kube_upgrade_obj.state = kubernetes.KUBE_UPGRADING_NETWORKING
            kube_upgrade_obj.save()

            # Tell the conductor to upgrade networking
            pecan.request.rpcapi.kube_upgrade_networking(
                pecan.request.context, kube_upgrade_obj.to_version)

            LOG.info("Upgrading kubernetes networking to version: %s" %
                kube_upgrade_obj.to_version)
            return KubeUpgrade.convert_with_links(kube_upgrade_obj)

        elif updates['state'] == kubernetes.KUBE_UPGRADING_STORAGE:

            # Make sure upgrade is in the correct state to upgrade storage
            if kube_upgrade_obj.state not in [
                    kubernetes.KUBE_UPGRADED_NETWORKING,
                    kubernetes.KUBE_UPGRADING_STORAGE_FAILED]:
                raise wsme.exc.ClientSideError(_(
                    "Kubernetes upgrade must be in %s or %s state to "
                    "upgrade storage" %
                    (kubernetes.KUBE_UPGRADED_NETWORKING,
                     kubernetes.KUBE_UPGRADING_STORAGE_FAILED)))

            # Update the upgrade state
            kube_upgrade_obj.state = kubernetes.KUBE_UPGRADING_STORAGE
            kube_upgrade_obj.save()

            # Tell the conductor to upgrade storage
            pecan.request.rpcapi.kube_upgrade_storage(
                pecan.request.context, kube_upgrade_obj.to_version)

            LOG.info("Upgrading kubernetes storage to version: %s" %
                kube_upgrade_obj.to_version)
            return KubeUpgrade.convert_with_links(kube_upgrade_obj)

        elif updates['state'] == kubernetes.KUBE_UPGRADE_ABORTING:
            system = pecan.request.dbapi.isystem_get_one()
            if system.system_mode != constants.SYSTEM_MODE_SIMPLEX:
                raise wsme.exc.ClientSideError(_(
                    "The 'system kube-upgrade-abort' is not supported "
                    "in %s" % system.system_mode))
            if kube_upgrade_obj.state in [kubernetes.KUBE_UPGRADE_ABORTING,
                                          kubernetes.KUBE_UPGRADE_ABORTED,
                                          kubernetes.KUBE_UPGRADE_COMPLETE,
                                          kubernetes.KUBE_POST_UPDATING_APPS,
                                          kubernetes.KUBE_POST_UPDATING_APPS_FAILED,
                                          kubernetes.KUBE_POST_UPDATED_APPS
                                          ]:
                raise wsme.exc.ClientSideError(_(
                    "Cannot abort the kubernetes upgrade it is in %s state" %
                    (kube_upgrade_obj.state)))

            # Assign the original state of the k8s upgrade before the abort.
            kube_state = kube_upgrade_obj.state
            # Restore the kube upgrade target version for each host to the from_version
            # and set the status as aborting.
            update_values = {'target_version': kube_upgrade_obj.from_version,
                             'status': kubernetes.KUBE_UPGRADE_ABORTING}
            kube_host_upgrades = pecan.request.dbapi.kube_host_upgrade_get_list()
            for kube_host_upgrade in kube_host_upgrades:
                pecan.request.dbapi.kube_host_upgrade_update(kube_host_upgrade.id,
                                                            update_values)
            # Restore the kubeadm_version and kubelet_version to the from_version
            kube_cmd_versions = objects.kube_cmd_version.get(pecan.request.context)
            kube_cmd_versions.kubeadm_version = kube_upgrade_obj.from_version.lstrip('v')
            kube_cmd_versions.kubelet_version = kube_upgrade_obj.from_version.lstrip('v')
            kube_cmd_versions.save()

            # Update the state as aborted for these states since no actual k8s changes done
            # so we don't need to do anything more to complete the abort.
            if kube_upgrade_obj.state in [kubernetes.KUBE_UPGRADE_STARTED,
                                          kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES,
                                          kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED,
                                          kubernetes.KUBE_UPGRADE_DOWNLOADED_IMAGES,
                                          kubernetes.KUBE_PRE_UPDATING_APPS,
                                          kubernetes.KUBE_PRE_UPDATING_APPS_FAILED,
                                          kubernetes.KUBE_PRE_UPDATED_APPS]:
                kube_upgrade_obj.state = kubernetes.KUBE_UPGRADE_ABORTED
                kube_upgrade_obj.save()
            else:
                kube_upgrade_obj.state = kubernetes.KUBE_UPGRADE_ABORTING
                kube_upgrade_obj.save()

                # Tell the conductor to abort k8s upgrade
                pecan.request.rpcapi.kube_upgrade_abort(
                    pecan.request.context, kube_state)

            LOG.info("Aborting kubernetes upgrade version: %s" %
                kube_upgrade_obj.to_version)
            return KubeUpgrade.convert_with_links(kube_upgrade_obj)

        elif updates['state'] == kubernetes.KUBE_UPGRADE_CORDON:
            system = pecan.request.dbapi.isystem_get_one()
            if system.system_mode != constants.SYSTEM_MODE_SIMPLEX:
                raise wsme.exc.ClientSideError(_(
                    "The 'system kube-host-cordon' is not supported "
                    "in %s" % system.system_mode))
            # Make sure upgrade is in the correct state to cordon
            if kube_upgrade_obj.state not in [
                    kubernetes.KUBE_UPGRADED_NETWORKING,
                    kubernetes.KUBE_UPGRADED_STORAGE,
                    kubernetes.KUBE_UPGRADE_CORDON_FAILED]:
                raise wsme.exc.ClientSideError(_(
                    "Kubernetes upgrade must be in %s, %s or %s state "
                    "to cordon" %
                    (kubernetes.KUBE_UPGRADED_NETWORKING,
                     kubernetes.KUBE_UPGRADED_STORAGE,
                     kubernetes.KUBE_UPGRADE_CORDON_FAILED)))

            # Update the upgrade state
            kube_upgrade_obj.state = kubernetes.KUBE_UPGRADE_CORDON
            kube_upgrade_obj.save()

            # Tell the conductor to cordon the pods to evict from the host
            pecan.request.rpcapi.kube_host_cordon(
                pecan.request.context, updates['hostname'])

            return KubeUpgrade.convert_with_links(kube_upgrade_obj)

        elif updates['state'] == kubernetes.KUBE_UPGRADE_UNCORDON:
            system = pecan.request.dbapi.isystem_get_one()
            if system.system_mode != constants.SYSTEM_MODE_SIMPLEX:
                raise wsme.exc.ClientSideError(_(
                    "The system kube-host-uncordon is not supported "
                    "in %s" % system.system_mode))
            # Make sure upgrade is in the correct state to uncordon
            if kube_upgrade_obj.state not in [
                    kubernetes.KUBE_UPGRADING_KUBELETS,
                    kubernetes.KUBE_UPGRADE_UNCORDON_FAILED]:
                raise wsme.exc.ClientSideError(_(
                    "Kubernetes upgrade must be in %s or %s state to "
                    "uncordon" %
                    (kubernetes.KUBE_UPGRADING_KUBELETS,
                     kubernetes.KUBE_UPGRADE_UNCORDON_FAILED)))

            # Make sure no hosts are in a transitory or failed state
            kube_host_upgrades = \
                pecan.request.dbapi.kube_host_upgrade_get_list()
            for kube_host_upgrade in kube_host_upgrades:
                if kube_host_upgrade.status != \
                        kubernetes.KUBE_HOST_UPGRADED_KUBELET:
                    raise wsme.exc.ClientSideError(_(
                        "At least one host has not completed the kubelet "
                        "upgrade"))

            # Update the upgrade state
            kube_upgrade_obj.state = kubernetes.KUBE_UPGRADE_UNCORDON
            kube_upgrade_obj.save()

            # Tell the conductor to allow the evicted pods on the host again
            pecan.request.rpcapi.kube_host_uncordon(
                pecan.request.context, updates['hostname'])

            return KubeUpgrade.convert_with_links(kube_upgrade_obj)

        elif updates['state'] == kubernetes.KUBE_UPGRADE_COMPLETE:
            # Make sure upgrade is in the correct state to complete
            system = pecan.request.dbapi.isystem_get_one()

            if system.system_mode == constants.SYSTEM_MODE_SIMPLEX:
                # If the node is unschedulable=True then the cordon command
                # executed already and some of the pods are in pending status.
                # The uncordon command needs to be triggered.
                # If the node is unschedulable=None then the pods are in the
                # running status.
                unschedulable = None
                node_status = self._kube_operator.kube_get_node_status(constants.CONTROLLER_0_HOSTNAME)
                LOG.debug("Node status: %s" % node_status)
                if node_status:
                    unschedulable = node_status.spec.unschedulable

                if unschedulable:
                    if kube_upgrade_obj.state not in [
                            kubernetes.KUBE_UPGRADE_UNCORDON_COMPLETE]:
                        raise wsme.exc.ClientSideError(_(
                            "Kubernetes upgrade must be in %s state to complete" %
                            kubernetes.KUBE_UPGRADE_UNCORDON_COMPLETE))
                else:
                    if kube_upgrade_obj.state not in [
                            kubernetes.KUBE_UPGRADING_KUBELETS,
                            kubernetes.KUBE_UPGRADE_UNCORDON_COMPLETE]:
                        raise wsme.exc.ClientSideError(_(
                            "Kubernetes upgrade must be in %s or %s state to complete" %
                            (kubernetes.KUBE_UPGRADING_KUBELETS,
                            kubernetes.KUBE_UPGRADE_UNCORDON_COMPLETE)))
            else:
                if kube_upgrade_obj.state not in [
                        kubernetes.KUBE_UPGRADING_KUBELETS]:
                    raise wsme.exc.ClientSideError(_(
                        "Kubernetes upgrade must be in %s state to complete" %
                        kubernetes.KUBE_UPGRADING_KUBELETS))

            # Make sure no hosts are in a transitory or failed state
            kube_host_upgrades = \
                pecan.request.dbapi.kube_host_upgrade_get_list()
            for kube_host_upgrade in kube_host_upgrades:
                if kube_host_upgrade.status != \
                        kubernetes.KUBE_HOST_UPGRADED_KUBELET:
                    raise wsme.exc.ClientSideError(_(
                        "At least one host has not completed the kubernetes "
                        "upgrade"))

            # Make sure the target version is active
            version_states = self._kube_operator.kube_get_version_states()
            if version_states.get(kube_upgrade_obj.to_version, None) != \
                    kubernetes.KUBE_STATE_ACTIVE:
                raise wsme.exc.ClientSideError(_(
                    "Kubernetes to_version must be active to complete"))

            # Set the new kubelet version in the DB.
            kube_cmd_versions = objects.kube_cmd_version.get(
                pecan.request.context)
            kube_cmd_versions.kubelet_version = kube_upgrade_obj.to_version.lstrip('v')
            kube_cmd_versions.save()

            # The global kubelet version is set, clear the per-host status.
            for kube_host_upgrade in kube_host_upgrades:
                pecan.request.dbapi.kube_host_upgrade_update(
                    kube_host_upgrade.id, {'status': None})

            # All is well, mark the upgrade as complete
            kube_upgrade_obj.state = kubernetes.KUBE_UPGRADE_COMPLETE
            kube_upgrade_obj.save()

            role = system.get('distributed_cloud_role')
            # Clean up container images for the system other than systemcontroller
            if role != constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
                pecan.request.rpcapi.kube_delete_container_images(
                    pecan.request.context, kube_upgrade_obj.to_version)

            LOG.info("Completed kubernetes upgrade to version: %s" %
                kube_upgrade_obj.to_version)

            # If applicable, notify dcmanager upgrade is complete
            if role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
                dc_api.notify_dcmanager_kubernetes_upgrade_completed()

            return KubeUpgrade.convert_with_links(kube_upgrade_obj)

        elif updates['state'] == kubernetes.KUBE_POST_UPDATING_APPS:
            # Make sure upgrade is in the correct state to update apps
            if kube_upgrade_obj.state not in [
                    kubernetes.KUBE_UPGRADE_COMPLETE,
                    kubernetes.KUBE_POST_UPDATING_APPS_FAILED]:
                raise wsme.exc.ClientSideError(_(
                    "Kubernetes upgrade must be in %s or %s state to update applications" %
                    (kubernetes.KUBE_UPGRADE_COMPLETE,
                     kubernetes.KUBE_POST_UPDATING_APPS_FAILED)))

            # Update the upgrade state
            kube_upgrade_obj.state = kubernetes.KUBE_POST_UPDATING_APPS
            kube_upgrade_obj.save()

            # Update apps that contain 'k8s_upgrade.timing = post' metadata
            pecan.request.rpcapi.kube_post_application_update(pecan.request.context,
                                                              kube_upgrade_obj.to_version)

            LOG.info("Updating applications to match current Kubernetes version %s" %
                     kube_upgrade_obj.to_version)
            return KubeUpgrade.convert_with_links(kube_upgrade_obj)
        else:
            raise wsme.exc.ClientSideError(_(
                "Invalid state %s supplied" % updates['state']))

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None)
    def delete(self):
        """Delete Kubernetes Upgrade."""

        # An upgrade must be in progress
        try:
            kube_upgrade_obj = pecan.request.dbapi.kube_upgrade_get_one()
        except exception.NotFound:
            raise wsme.exc.ClientSideError(_(
                "A kubernetes upgrade is not in progress"))
        if kube_upgrade_obj.state not in [kubernetes.KUBE_UPGRADE_COMPLETE,
                                          kubernetes.KUBE_POST_UPDATING_APPS_FAILED,
                                          kubernetes.KUBE_POST_UPDATED_APPS,
                                          kubernetes.KUBE_UPGRADE_ABORTED]:
            # The upgrade must be in complete or abort state to delete
            raise wsme.exc.ClientSideError(_(
                "Kubernetes upgrade must be in %s, %s, %s or %s state to delete" %
                (kubernetes.KUBE_UPGRADE_COMPLETE,
                 kubernetes.KUBE_POST_UPDATING_APPS_FAILED,
                 kubernetes.KUBE_POST_UPDATED_APPS,
                 kubernetes.KUBE_UPGRADE_ABORTED)))

        # Clean up k8s control-plane backup
        pecan.request.rpcapi.remove_kube_control_plane_backup(
            pecan.request.context)

        # Delete the upgrade
        pecan.request.dbapi.kube_upgrade_destroy(kube_upgrade_obj.id)

        # Clear the kubernetes upgrade alarm
        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                        constants.CONTROLLER_HOSTNAME)
        fm_api.FaultAPIs().clear_fault(
            fm_constants.FM_ALARM_ID_KUBE_UPGRADE_IN_PROGRESS,
            entity_instance_id)

        # Check if apps need to be reapplied
        pecan.request.rpcapi.evaluate_apps_reapply(
            pecan.request.context,
            trigger={'type': constants.APP_EVALUATE_REAPPLY_TYPE_KUBE_UPGRADE_COMPLETE})
