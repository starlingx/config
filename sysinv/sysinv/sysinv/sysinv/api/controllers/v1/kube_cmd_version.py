#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import jsonpatch
import pecan
from pecan import rest
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)
LOCK_NAME = 'KubeCmdVersionController'


class KubeCmdVersionPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return ['/kubeadm_version', '/kubelet_version']


class KubeCmdVersion(base.APIBase):
    """API representation of a k8s cmd version."""

    kubeadm_version = wtypes.text
    "Kubeadm version for this entry"

    kubelet_version = wtypes.text
    "Kubelet version for this entry"

    def __init__(self, **kwargs):
        self.fields = objects.kube_cmd_version.fields
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    @classmethod
    def convert_with_links(cls, rpc_kube_cmd_version):
        kube_version = KubeCmdVersion(**rpc_kube_cmd_version.as_dict())
        return kube_version


class KubeCmdVersionController(rest.RestController):
    """REST controller for Kubernetes Cmd Versions."""

    @wsme_pecan.wsexpose(KubeCmdVersion)
    def get(self):
        """Get the kube cmd version object"""
        kube_cmd_version = objects.kube_cmd_version.get(pecan.request.context)
        return KubeCmdVersion.convert_with_links(kube_cmd_version)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(KubeCmdVersion, body=[KubeCmdVersionPatchType])
    def patch(self, patch):
        """Modify the kube cmd version object"""
        try:
            utils.validate_patch(patch)
            patch_obj = jsonpatch.JsonPatch(patch)
            kube_cmd_version = objects.kube_cmd_version.get(pecan.request.context)
            kube_cmd_version_patched = KubeCmdVersion(**jsonpatch.apply_patch(
                                                      kube_cmd_version.as_dict(),
                                                      patch_obj))
            # Update only the fields that have changed
            for field in objects.kube_cmd_version.fields:
                if kube_cmd_version[field] != getattr(kube_cmd_version_patched, field):
                    kube_cmd_version[field] = getattr(kube_cmd_version_patched, field)
            kube_cmd_version.save()

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)
        except Exception as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_(
                "Unable modify the KubeCmdVersion object."))
        return KubeCmdVersion.convert_with_links(kube_cmd_version)
