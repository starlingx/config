########################################################################
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

import pecan
from pecan import expose
from pecan import rest

from sysinv.common import utils as cutils
from sysinv.openstack.common.rpc.common import RemoteError

LOCK_NAME = 'KubeConfigKubeletController'


class KubeConfigKubeletController(rest.RestController):
    """REST controller for kube_config_kubelet."""

    _custom_actions = {
        'apply': ['POST'],
    }

    @expose('json')
    @cutils.synchronized(LOCK_NAME)
    def apply(self):
        try:
            pecan.request.rpcapi.kube_config_kubelet(pecan.request.context)
        except RemoteError as e:
            return dict(success="", error=e.value)
        except Exception as ex:
            return dict(success="", error=str(ex))

        return dict(success="kube-config-kubelet applied.", error="")
