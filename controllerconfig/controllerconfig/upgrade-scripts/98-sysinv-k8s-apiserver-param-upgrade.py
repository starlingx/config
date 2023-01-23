#!/usr/bin/env python
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will upgrade kubernetes service parameters
# from release 22.06 and 21.12 to 22.12
#
# Note: this can be removed in the release after STX8.0

import datetime
import json
import sys
import ruamel.yaml as yaml

from oslo_utils import uuidutils
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.extras import DictCursor

from controllerconfig.common import log

LOG = log.get_logger(__name__)

K8S_SERVICE = 'kubernetes'

K8S_BOOTSTRAP_PARAMETERS =\
    "/opt/platform/config/22.12/last_kube_extra_config_bootstrap.yaml"

SYSINV_K8S_SECTIONS = {
    'apiserver_extra_args': 'kube_apiserver',
    'controllermanager_extra_args': 'kube_controller_manager',
    'scheduler_extra_args': 'kube_scheduler',
    'apiserver_extra_volumes': 'kube_apiserver_volumes',
    'controllermanager_extra_volumes': 'kube_controller_manager_volumes',
    'scheduler_extra_volumes': 'kube_scheduler_volumes',
    'kubelet_configurations': 'kubelet'}

default_extra_volumes = {
    "encryption-config": {
        'name': "encryption-config",
        'hostPath': "/etc/kubernetes/encryption-provider.yaml",
        'mountPath': "/etc/kubernetes/encryption-provider.yaml",
        'readOnly': True,
        'pathType': 'File'},

    "default-audit-policy-file": {
        'name': "default-audit-policy-file",
        'hostPath': "/etc/kubernetes/default-audit-policy.yaml",
        'mountPath': "/etc/kubernetes/default-audit-policy.yaml",
        'readOnly': True,
        'pathType': 'File'},
    "audit-log-dir": {
        'name': "audit-log-dir",
        'hostPath': "/var/log/kubernetes/audit/",
        'mountPath': "/var/log/kubernetes/audit/",
        'readOnly': False,
        'pathType': 'DirectoryOrCreate'}
}


def get_service_parameters(db_conn, K8S_SERVICE, K8S_SECTION):
    with db_conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("select name, uuid, value, personality, resource from "
                    "service_parameter where service='{}' and "
                    "section='{}'".format(K8S_SERVICE, K8S_SECTION))
        return cur.fetchall()


def add_service_parameter(db_conn, name, value, service, section,
                          personality=None, resource=None):
    with db_conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute(
            "INSERT INTO service_parameter "
            "(created_at, uuid, name, value, service, "
            "section, personality, resource) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s);",
            (datetime.datetime.now(), uuidutils.generate_uuid(),
             name, value, service, section, personality, resource))
        LOG.info("Adding %s=%s to db [%s]." % (name, value, section))


def main():
    action = None
    from_release = None
    to_release = None
    arg = 1

    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        else:
            LOG.error("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()

    LOG.info("%s invoked with from_release = %s to_release = %s action = %s"
             % (sys.argv[0], from_release, to_release, action))
    if action == "migrate" and from_release in ['22.06', '21.12']:
        try:
            db_conn = psycopg2.connect("dbname=sysinv user=postgres")
            with db_conn:
                migrate_k8s_control_plane_and_kubelet_parameters(db_conn)
                return 0
        except Exception as ex:
            LOG.exception(ex)
            return 1


def migrate_k8s_control_plane_and_kubelet_parameters(db_conn):
    """This method will take each k8s cluster config and kubelet parameter
    stored in backup data and will restore it into sysinv database
    """
    try:
        with open(K8S_BOOTSTRAP_PARAMETERS, 'r') as file:
            cluster_cfg = yaml.load(file, Loader=yaml.RoundTripLoader)
    except FileNotFoundError as e:
        msg = str('Loading k8s bootstrap parameters from file. {}'.format(e))
        LOG.error(msg)
        return 1

    # -------------------------------------------------------------------------
    # Restoring params into sysinv db
    # -------------------------------------------------------------------------
    for kubeadm_section in [
            'apiserver_extra_args', 'controllermanager_extra_args',
            'scheduler_extra_args', 'apiserver_extra_volumes',
            'controllermanager_extra_volumes', 'scheduler_extra_volumes',
            'kubelet_configurations']:

        # current parameters stored into sysinv db
        sysinv_section = SYSINV_K8S_SECTIONS.get(kubeadm_section)
        sysinv_section_params = get_service_parameters(
            db_conn, K8S_SERVICE, sysinv_section)
        sysinv_section_params_names =\
            [param.get('name') for param in sysinv_section_params]

        # cases: apiserver, controller-manager and scheduler extra-args
        # params loaded during latest bootstrap take precedence over 22.06
        if isinstance(cluster_cfg[kubeadm_section], (
                dict, yaml.comments.CommentedMap)):
            for param_name, param_value in cluster_cfg[
                    kubeadm_section].items():
                if param_name not in sysinv_section_params_names:
                    try:
                        if isinstance(param_value, (
                                dict, yaml.comments.CommentedMap)):
                            param_value = str(dict(param_value))

                        # add new parameter to sysinv
                        add_service_parameter(
                            db_conn, param_name, param_value,
                            K8S_SERVICE, sysinv_section)

                    except Exception as e:
                        LOG.error("[%s] Adding %s=%s to db [Detail: %s]." % (
                            sysinv_section, param_name, param_value, e))
                else:
                    LOG.info("Skipping %s pre existent param." % (param_name))

        # cases: apiserver, controller-manager and scheduler extra-volumes
        elif isinstance(cluster_cfg[kubeadm_section], (
                list, yaml.comments.CommentedSeq)):
            for parameter in cluster_cfg[kubeadm_section]:
                if not isinstance(parameter, yaml.comments.CommentedMap):
                    continue
                # each parameter is a dictionary containing the fields needed
                # to create an extra-volume service-parameter entry and the
                # associated k8s configmap.
                param_dict = dict(parameter)
                param_name = param_dict['name']
                if 'content' in param_dict:
                    param_dict.pop('content')
                param_value = json.dumps(param_dict)

                if param_name not in sysinv_section_params_names:
                    try:
                        # add new extra-volume parameter to sysinv
                        add_service_parameter(
                            db_conn, param_name, param_value,
                            K8S_SERVICE, sysinv_section)
                    except Exception as e:
                        LOG.error("[%s] Adding %s=%s to db [Detail: %s]." % (
                            sysinv_section, param_name, param_value, e))
                        continue
                else:
                    LOG.info("Skipping %s pre existent param." % (param_name))

    # -------------------------------------------------------------------------
    # Restoring params into sysinv db
    # -------------------------------------------------------------------------
    # The default extra_volumes in 22.06 or earlier versions are hardcoded
    # in the kubeadmin configuration file. This function adds the corresponding
    # service parameter entries in the sysinv database
    # (service: kubernetes, section: kube_apiserver_volumes).

    # current parameters stored into sysinv db
    sysinv_section = 'kube_apiserver_volumes'
    sysinv_section_params = get_service_parameters(
        db_conn, K8S_SERVICE, sysinv_section)
    sysinv_section_params_names =\
        [param.get('name') for param in sysinv_section_params]

    for param_name, volume_dict in default_extra_volumes.items():
        if param_name not in sysinv_section_params_names:
            param_value = json.dumps(volume_dict)
            try:
                add_service_parameter(
                    db_conn, param_name, param_value,
                    K8S_SERVICE, sysinv_section)
            except Exception as e:
                LOG.error("[%s] Adding %s=%s to db [Detail: %s]." % (
                    sysinv_section, param_name, param_value, e))
                raise

    LOG.info("k8s service-parameters upgrade completed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
