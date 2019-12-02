#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan
from pecan import rest
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import kubernetes
from sysinv import objects


class KubeHostUpgrade(base.APIBase):
    """API representation of a Kubernetes Host Upgrade."""

    id = int
    "Unique ID for this entry"

    uuid = types.uuid
    "Unique UUID for this entry"

    target_version = wtypes.text
    "The target version for this host"

    status = wtypes.text
    "The status of the kubernetes upgrade for this host"

    control_plane_version = wtypes.text
    "The control plane version for this host"

    kubelet_version = wtypes.text
    "The kubelet version for this host"

    host_id = int
    "The host this belongs to"

    links = [link.Link]
    "A list containing a self link and associated kubernetes host upgrade links"

    def __init__(self, **kwargs):
        self.fields = list(objects.kube_host_upgrade.fields.keys())
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, kube_host_upgrade_obj, expand=True):
        kube_host_upgrade = KubeHostUpgrade(**kube_host_upgrade_obj.as_dict())
        if not expand:
            kube_host_upgrade.unset_fields_except([
                'id', 'uuid', 'target_version', 'status',
                'control_plane_version', 'kubelet_version', 'host_id'])

        kube_host_upgrade.links = [
            link.Link.make_link('self', pecan.request.host_url,
                                'kube_host_upgrade', kube_host_upgrade.uuid),
            link.Link.make_link('bookmark', pecan.request.host_url,
                                'kube_host_upgrade', kube_host_upgrade.uuid,
                                bookmark=True)]
        return kube_host_upgrade


class KubeHostUpgradeCollection(collection.Collection):
    """API representation of a collection of kubernetes host upgrades."""

    kube_host_upgrades = [KubeHostUpgrade]
    "A list containing kubernetes host upgrade objects"

    def __init__(self):
        self._type = 'kube_host_upgrades'

    @classmethod
    def convert_with_links(cls, kube_host_upgrade_objs, limit, url=None,
                           expand=False, **kwargs):
        upgrade_collection = KubeHostUpgradeCollection()
        upgrade_collection.kube_host_upgrades = [
            KubeHostUpgrade.convert_with_links(p, expand)
            for p in kube_host_upgrade_objs]
        upgrade_collection.next = upgrade_collection.get_next(
            limit, url=url, **kwargs)
        return upgrade_collection


class KubeHostUpgradeController(rest.RestController):
    """REST controller for kubernetes host upgrades."""

    def __init__(self):
        self._kube_operator = kubernetes.KubeOperator()

    @staticmethod
    def _get_host_details():
        # Retrieve the list of hosts from the database
        host_objs = pecan.request.dbapi.ihost_get_list()

        # Map the host_id to required fields
        host_details = dict()
        for host_obj in host_objs:
            host_details[host_obj.id] = {
                'hostname': host_obj.hostname,
                'personality': host_obj.personality,
            }

        return host_details

    @staticmethod
    def _set_dynamic_versions(upgrade_obj, host_details, cp_versions,
                              kubelet_versions):
        # Not all hosts support kubernetes
        if host_details[upgrade_obj.host_id]['personality'] == \
                constants.CONTROLLER:
            upgrade_obj.control_plane_version = \
                cp_versions.get(
                    host_details[upgrade_obj.host_id]['hostname'],
                    'unknown')
        else:
            upgrade_obj.control_plane_version = 'N/A'

        if host_details[upgrade_obj.host_id]['personality'] in \
                [constants.CONTROLLER, constants.WORKER]:
            upgrade_obj.kubelet_version = \
                kubelet_versions.get(
                    host_details[upgrade_obj.host_id]['hostname'],
                    'unknown')
        else:
            upgrade_obj.kubelet_version = 'N/A'

    @wsme_pecan.wsexpose(KubeHostUpgradeCollection, wtypes.text, int,
                         wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of kubernetes host upgrades."""

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.kube_host_upgrade.get_by_uuid(
                pecan.request.context,
                marker)

        # Retrieve the host upgrades from the database
        kube_host_upgrades = pecan.request.dbapi.kube_host_upgrade_get_list(
            limit, marker_obj, sort_key=sort_key, sort_dir=sort_dir)

        # Get some details about the hosts
        host_details = self._get_host_details()

        # Get the dynamic version information
        cp_versions = self._kube_operator.kube_get_control_plane_versions()
        kubelet_versions = self._kube_operator.kube_get_kubelet_versions()

        for upgrade_obj in kube_host_upgrades:
            self._set_dynamic_versions(upgrade_obj, host_details, cp_versions,
                                       kubelet_versions)

        return KubeHostUpgradeCollection.convert_with_links(
            kube_host_upgrades, limit, sort_key=sort_key, sort_dir=sort_dir)

    @wsme_pecan.wsexpose(KubeHostUpgrade, wtypes.text)
    def get_one(self, kube_host_upgrade_uuid):
        """Retrieve information about the given kube host upgrade."""

        # Retrieve the host upgrade from the database
        kube_host_upgrade_obj = objects.kube_host_upgrade.get_by_uuid(
            pecan.request.context, kube_host_upgrade_uuid)

        # Get some details about the hosts
        host_details = self._get_host_details()

        # Get the dynamic version information
        cp_versions = self._kube_operator.kube_get_control_plane_versions()
        kubelet_versions = self._kube_operator.kube_get_kubelet_versions()

        self._set_dynamic_versions(kube_host_upgrade_obj, host_details,
                                   cp_versions, kubelet_versions)

        return KubeHostUpgrade.convert_with_links(kube_host_upgrade_obj)
