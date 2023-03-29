#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# All Rights Reserved.
#

""" System Inventory Etcd Utilities and helper functions."""

import os
import ruamel.yaml as yaml
import subprocess

from oslo_log import log
from ruamel.yaml.compat import StringIO

from sysinv.common import exception
from sysinv.common import kubernetes

LOG = log.getLogger(__name__)

ETCD_API_ENV_VAR = {"ETCDCTL_API": "3"}
ETCD_SNAPSHOT_FILE_NAME = "stx_etcd.snap"


def get_cluster_information():
    """Retrieve configured cluster endpoints and certs information
    from the kubeadm-configmap

    :returns: etcd_config: OrderedDict containing cluster information
    """
    try:
        newyaml = yaml.YAML()
        kube_operator = kubernetes.KubeOperator()
        configmap_data = kube_operator.kube_read_config_map(
            'kubeadm-config', kubernetes.NAMESPACE_KUBE_SYSTEM)
        stream = StringIO(configmap_data.data['ClusterConfiguration'])
        config = newyaml.load(stream)
        etcd_config = config['etcd']['external']
    except Exception as e:
        LOG.error('Error retrieving etcd cluster details: %s' % e)
        raise
    return etcd_config


def snapshot_etcd(snapshot_file):
    """"Snapshot etcd to a file

    :param snapshot_file: Full path of the snapshot file
    """
    try:
        etcd_config = get_cluster_information()

        ca_cert = etcd_config['caFile']
        cert_file = etcd_config['certFile']
        key_file = etcd_config['keyFile']
        endpoints = ",".join(etcd_config['endpoints'])

        snapshot_path = os.path.dirname(snapshot_file)
        if not os.path.exists(snapshot_path):
            os.makedirs(snapshot_path)

        command = ["etcdctl", "--cert", cert_file, "--key", key_file,
        "--cacert", ca_cert, "--endpoints", endpoints, "snapshot", "save",
        snapshot_file]
        proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=ETCD_API_ENV_VAR)
        try:
            stdout, stderr = proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            LOG.error("Command %s: timed out." % command)
            raise
    except Exception as e:
        LOG.error("Failed to snapshot etcd: %s" % e)
        raise
    if 'Snapshot saved at' in str(stdout):
        LOG.info("Etcd backup successful at %s" % snapshot_file)
    else:
        LOG.error("Failed to save etcd backup with error %s" % stderr)
        raise exception.EtcdOperationFailure(operation=command, error=str(stderr))
