# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2023 Wind River Systems, Inc.
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
from sysinv.api.controllers.v1 import link
from sysinv.common import utils as cutils
from sysinv import objects

from sysinv.common import constants

from typing import Set

LOCK_NAME = 'KernelController'

LOG = log.getLogger(__name__)


class KernelPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return ['ihost_uuid',
                'hostname',
                'kernel_provisioned',
                'kernel_running']


class Kernel(base.APIBase):
    """
    API representation of the kernel configuration of a ihost.
    """
    ihost_uuid = types.uuid
    "The UUID of the host of this kernel"

    hostname = wtypes.text
    "The name of the host of this kernel"

    kernel_provisioned = wtypes.text
    "The provisined kernel of the ihost"

    kernel_running = wtypes.text
    "The running kernel of the ihost"

    links = [link.Link]
    "A list containing a self link and associated kernel links"

    def __init__(self, **kwargs):
        self.fields = ['ihost_uuid',
                       'hostname',
                       'kernel_provisioned',
                       'kernel_running',
                       'links']
        self.hostname = kwargs.get('hostname')
        self.ihost_uuid = kwargs.get('uuid')
        self.kernel_provisioned = kwargs.get('kernel_provisioned')
        self.kernel_running = kwargs.get('kernel_running')

        # if 'kernel_provisioned' key is missing use 'subfunctions' key instead
        if self.kernel_provisioned is None:
            if constants.LOWLATENCY in kwargs.get(constants.SUBFUNCTIONS):
                self.kernel_provisioned = constants.KERNEL_LOWLATENCY
            else:
                self.kernel_provisioned = constants.KERNEL_STANDARD

    @staticmethod
    def _create_subfunctions_str(subfunctions_set: Set):
        """Generate the subfunctions string using the set
           Preserves expected order

        Args:
            subfunctions_set (Set): _description_
        """
        expected_order = [constants.CONTROLLER,
                          constants.WORKER,
                          constants.STORAGE,
                          constants.LOWLATENCY]
        subfunctions_list = []
        for i in expected_order:
            if i in subfunctions_set:
                subfunctions_list.append(i)
                subfunctions_set.discard(i)

        for i in subfunctions_set:
            subfunctions_list.append(i)

        return ','.join(subfunctions_list)

    def _update_kernel(self, ihost, kernel: str):
        """ Update the kernel value

        Args:
            ihost: rpc ihost object
            kernel (str): kernel value
        """
        LOG.info(
            f"Updating kernel {self.hostname} "
            f"[running={self.kernel_running} "
            f"provisioned={self.kernel_provisioned}] "
            f"to {kernel}]"
        )

        if self.kernel_provisioned == kernel and self.kernel_running == kernel:
            return None

        if kernel == constants.KERNEL_LOWLATENCY:
            lowlatency = True
        else:
            lowlatency = False

        subfunctions = ihost.get(constants.SUBFUNCTIONS) or ""
        subfunctions_set = set(subfunctions.split(','))

        if lowlatency is True:
            subfunctions_set.add(constants.LOWLATENCY)
        else:
            subfunctions_set.discard(constants.LOWLATENCY)

        updated_subfunctions = Kernel._create_subfunctions_str(subfunctions_set)
        updates = \
            {
                constants.SUBFUNCTIONS: updated_subfunctions
            }

        ihost.save_changes(pecan.request.context, updates)
        pecan.request.rpcapi.kernel_runtime_manifests(pecan.request.context,
                                                      self.ihost_uuid)
        self.kernel_provisioned = kernel

    @classmethod
    def convert_with_links(cls, ihost):
        ihost_dict = ihost.as_dict()
        kernel = Kernel(**ihost_dict)
        url_arg = f"{ihost.uuid}/kernel"
        kernel.links = [link.Link.make_link('self',
                                            pecan.request.host_url,
                                            'ihosts', url_arg),
                        link.Link.make_link('bookmark',
                                            pecan.request.host_url,
                                            'ihosts', url_arg,
                                            bookmark=True)
                        ]
        return kernel


class KernelController(rest.RestController):

    @staticmethod
    def _check_host(ihost):
        if ihost.administrative != constants.ADMIN_LOCKED:
            raise wsme.exc.ClientSideError(_('Host must be locked.'))

        if constants.WORKER not in ihost.subfunctions:
            raise wsme.exc.ClientSideError(_('Can only modify worker nodes.'))

    @staticmethod
    def _check_patch(patch):
        KERNEL_PATH = '/kernel_provisioned'

        if not isinstance(patch, list):
            patch = [patch]

        utils.validate_patch(patch)

        supported_ops = ['replace']
        supported_paths = [KERNEL_PATH]
        supported_kernels = constants.SUPPORTED_KERNELS
        for p in patch:
            path = p["path"]
            op = p["op"]
            value = p["value"]

            if path not in supported_paths:
                error_msg = f"Path in not supported: {path}"
                raise wsme.exc.ClientSideError(_(error_msg))

            if op not in supported_ops:
                error_msg = f"Operation in not supported: {op}"
                raise wsme.exc.ClientSideError(_(error_msg))

            if path == KERNEL_PATH and value not in supported_kernels:
                error_msg = f"Supported kernels: {supported_kernels}"
                raise wsme.exc.ClientSideError(_(error_msg))

    # GET ihosts/<uuid>/kernel
    @wsme_pecan.wsexpose(Kernel, types.uuid)
    def get(self, ihost_uuid):
        """Query information of a specific host kernel

        Args:
            ihost_uuid (uuid): UUID of the host

        Returns:
            Kernel: Kernel API object
        """
        ihost = objects.host.get_by_uuid(pecan.request.context, ihost_uuid)
        kernel = Kernel.convert_with_links(ihost)
        return kernel

    # PATCH ihosts/<uuid>/kernel
    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [KernelPatchType])
    @wsme_pecan.wsexpose(Kernel, types.uuid,
                         body=[KernelPatchType])
    def patch(self, ihost_uuid, patch):
        """Modify a host kernel's configuration.

        Example:
        /v1/ihost/<uuid>/kernel
        patch
        [
            {
                "op" : "replace",
                "path" : "/kernel",
                "value" : "lowlatency"
            }
        ]

        Args:
            ihost_uuid (uuid): UUID of the host
            patch (json): kernel patch
        """
        ihost = objects.host.get_by_uuid(pecan.request.context, ihost_uuid)

        KernelController._check_host(ihost)
        KernelController._check_patch(patch)

        patch_obj = jsonpatch.JsonPatch(patch)
        kernel_obj = Kernel.convert_with_links(ihost)
        kernel_dict = kernel_obj.as_dict()

        try:
            patched_kernel_dict = jsonpatch.apply_patch(kernel_dict, patch_obj)
        except jsonpatch.JsonPatchException as inst:
            LOG.exception(inst)
            error_msg = f"Update Kernel Error: {inst}"
            raise wsme.exc.ClientSideError(_(error_msg))

        kernel_value = patched_kernel_dict.get('kernel_provisioned')
        kernel_obj._update_kernel(ihost, kernel_value)
        return kernel_obj
