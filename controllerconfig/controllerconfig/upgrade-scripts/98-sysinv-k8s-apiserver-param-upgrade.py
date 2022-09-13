#!/usr/bin/env python
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will upgrade kubernetes service parameters
# from release 22.06 to 22.12
#
# Note: this can be removed in the release after STX8.0

import datetime
import sys
import ruamel.yaml as yaml

from oslo_utils import uuidutils
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.extras import DictCursor

from controllerconfig.common import log


LOG = log.get_logger(__name__)

K8S_SERVICE = 'kubernetes'
K8S_APISERVER_SECTION = 'kube_apiserver'
K8S_CONTROLLER_MANAGER_SECTION = 'kube_controller_manager'
K8S_SCHEDULER_SECTION = 'kube_scheduler'
K8S_KUBELET_SECTION = 'kubelet'

SYSINV_K8S_SECTIONS = {
    'apiserver': K8S_APISERVER_SECTION,
    'controllermanager': K8S_CONTROLLER_MANAGER_SECTION,
    'scheduler': K8S_SCHEDULER_SECTION,
    'kubelet': K8S_KUBELET_SECTION}


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
    if action == "migrate" and from_release == '22.06':
        try:
            db_conn = psycopg2.connect("dbname=sysinv user=postgres")
            with db_conn:
                upgrade_k8s_apiserver_parameters(db_conn)
                return 0
        except Exception as ex:
            LOG.exception(ex)
            return 1


def upgrade_k8s_apiserver_parameters(db_conn):
    """This method will take each parameter from dict params and update its
    name. key is the current value for instance, oidc_issuer_url.
    And, its value is the new name for instance, oidc-issuer-url.
    """
    k8s_bootstrap_parameters =\
        "/opt/platform/config/22.12/last_kube_extra_config_bootstrap.yaml"

    try:
        with open(k8s_bootstrap_parameters, 'r') as file:
            cluster_cfg = yaml.load(file, Loader=yaml.RoundTripLoader)
    except FileNotFoundError as e:
        msg = str('Loading k8s bootstrap parameters from file. {}'.format(e))
        LOG.error(msg)
        return 1

    # -------------------------------------------------------------------------
    # Save new params into sysinv
    # -------------------------------------------------------------------------
    for kubeadm_section in [
            'apiserver_extra_args', 'controllermanager_extra_args',
            'scheduler_extra_args', 'kubelet_configurations']:

        # current parameters stored in sysinv db
        sysinv_section = SYSINV_K8S_SECTIONS.get(kubeadm_section.split('_')[0])
        sysinv_params = get_service_parameters(
            db_conn, K8S_SERVICE, sysinv_section)
        sysinv_params_names = [param.get('name') for param in sysinv_params]

        # new parameters to store into sysinv db (loaded from 22.06)
        for param_name, param_value in cluster_cfg[kubeadm_section].items():
            if param_name not in sysinv_params_names:
                try:
                    # add new parameter to sysinv
                    add_service_parameter(
                        db_conn, param_name, param_value,
                        K8S_SERVICE, sysinv_section)
                except Exception as e:
                    LOG.error("[%s] Adding %s=%s to db [Detail: %s]." % (
                        sysinv_section, param_name, param_value, e))
            else:
                LOG.info("Skipping %s pre existent param." % (param_name))

    LOG.info("k8s service-parameters upgrade completed")


if __name__ == "__main__":
    sys.exit(main())
