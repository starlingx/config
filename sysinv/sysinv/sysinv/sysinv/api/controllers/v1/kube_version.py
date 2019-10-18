#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from pecan import rest
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.common import kubernetes
from sysinv import objects


class KubeVersion(base.APIBase):
    """API representation of a k8s version."""

    version = wtypes.text
    "Unique version for this entry"

    upgrade_from = [wtypes.text]
    "List of versions that can upgrade to this version"

    downgrade_to = [wtypes.text]
    "List of versions that this version can downgrade to"

    applied_patches = [wtypes.text]
    "List of patches that must be applied before upgrading to this version"

    available_patches = [wtypes.text]
    "List of patches that must be available before upgrading to this version"

    target = bool
    "Denotes whether this is the target version"

    state = wtypes.text
    "State of this version"

    def __init__(self, **kwargs):
        self.fields = objects.kube_version.fields.keys()
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    @classmethod
    def convert_with_links(cls, rpc_kube_version, expand=True):
        kube_version = KubeVersion(**rpc_kube_version.as_dict())
        if not expand:
            kube_version.unset_fields_except(['version', 'target', 'state'])

        # The version is not a database object so does not have timestamps.
        kube_version.created_at = wtypes.Unset
        kube_version.updated_at = wtypes.Unset
        return kube_version


class KubeVersionCollection(collection.Collection):
    """API representation of a collection of k8s versions."""

    kube_versions = [KubeVersion]
    "A list containing kubernetes version objects"

    def __init__(self, **kwargs):
        self._type = 'kube_versions'

    @classmethod
    def convert_with_links(cls, rpc_kube_version, expand=False):
        collection = KubeVersionCollection()
        collection.kube_versions = [KubeVersion.convert_with_links(p, expand)
                                    for p in rpc_kube_version]
        return collection


class KubeVersionController(rest.RestController):
    """REST controller for Kubernetes Versions."""

    def __init__(self, parent=None, **kwargs):
        self._parent = parent
        self._kube_operator = kubernetes.KubeOperator()

    @wsme_pecan.wsexpose(KubeVersionCollection)
    def get_all(self):
        """Retrieve a list of kubernetes versions."""

        # Get the dynamic version information
        version_states = self._kube_operator.kube_get_version_states()

        rpc_kube_versions = []
        for version in kubernetes.get_kube_versions():
            version_obj = KubeVersion()
            version_obj.version = version['version']
            version_obj.upgrade_from = version['upgrade_from']
            version_obj.downgrade_to = version['downgrade_to']
            version_obj.applied_patches = version['applied_patches']
            version_obj.available_patches = version['available_patches']
            version_obj.state = version_states[version['version']]
            # For now, the active version will be marked as the target. When
            # upgrades are supported, we will also have to consider whether
            # an upgrade is in progress to determine the target.
            if version_obj.state == kubernetes.KUBE_STATE_ACTIVE:
                version_obj.target = True
            else:
                version_obj.target = False
            rpc_kube_versions.append(version_obj)

        return KubeVersionCollection.convert_with_links(rpc_kube_versions)

    @wsme_pecan.wsexpose(KubeVersion, wtypes.text)
    def get_one(self, version):
        """Retrieve information about the given kubernetes version."""

        # Get the static version information
        rpc_kube_version = objects.kube_version.get_by_version(version)

        # Get the dynamic version information
        version_states = self._kube_operator.kube_get_version_states()
        rpc_kube_version.state = version_states[version]
        # For now, the active version will be marked as the target. When
        # upgrades are supported, we will also have to consider whether
        # an upgrade is in progress to determine the target.
        if rpc_kube_version.state == kubernetes.KUBE_STATE_ACTIVE:
            rpc_kube_version.target = True
        else:
            rpc_kube_version.target = False
        return KubeVersion.convert_with_links(rpc_kube_version)
