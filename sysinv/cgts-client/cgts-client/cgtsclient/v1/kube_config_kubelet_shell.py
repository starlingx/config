#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient import exc


def do_kube_config_kubelet(cc, args):
    """Apply the kubelet config."""

    try:
        response = cc.kube_config_kubelet.apply()
    except exc.HTTPNotFound:
        raise exc.CommandError('Failed to apply kubelet config. No response.')
    except Exception as e:
        raise exc.CommandError('Failed to apply kubelet config: %s' % (e))
    else:
        success = response.get('success')
        error = response.get('error')
        if success:
            print("Success: " + success)
        if error:
            print("Error: " + error)
