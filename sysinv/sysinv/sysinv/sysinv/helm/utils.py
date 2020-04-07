# sim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

"""Helm utilities and helper functions."""

import os
from eventlet.green import subprocess
import ruamel.yaml as yaml
from oslo_log import log as logging
from sysinv.agent import rpcapi as agent_rpcapi
from sysinv.common import kubernetes
from sysinv.common import exception
from sysinv.openstack.common import context
import threading

LOG = logging.getLogger(__name__)


def refresh_helm_repo_information():
    """Refresh the helm chart repository information.

    Ensure that the local repository information maintained in key user home
    directories are updated. Run this after application uploads.

    This handles scenarios where an upload occurs on the active controller
    followed by a swact. The newly actvated controller needs to make sure that
    the local repository cache reflect any changes.
    """
    LOG.debug("refresh_helm_repo_information: sending command to agent(s)")
    rpcapi = agent_rpcapi.AgentAPI()
    rpcapi.refresh_helm_repo_information(context.get_admin_context())


def retrieve_helm_releases():
    """Retrieve the deployed helm releases from tiller

    Get the name, namespace and version for the deployed releases
    by querying helm tiller
    :return: a dict of deployed helm releases
    """
    deployed_releases = {}

    # Helm v3 releases
    helm_list = subprocess.Popen(
        ['helm', '--kubeconfig', kubernetes.KUBERNETES_ADMIN_CONF,
         'list', '--all-namespaces', '--output', 'yaml'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timer = threading.Timer(20, helm_list.kill)

    try:
        releases = {}

        timer.start()
        out, err = helm_list.communicate()
        if out and not err:
            releases = yaml.safe_load(out)
        elif err and not out:
            raise exception.HelmTillerFailure(
                reason="Failed to retrieve releases: %s" % err)
        elif not err and not out:
            err_msg = "Failed to retrieve releases. " \
                      "Helm tiller response timeout."
            raise exception.HelmTillerFailure(reason=err_msg)

        for r in releases:
            r_name = r.get('name')
            r_version = r.get('revision')
            r_namespace = r.get('namespace')

            deployed_releases.setdefault(r_name, {}).update(
                {r_namespace: r_version})
    except Exception as e:
        raise exception.HelmTillerFailure(
            reason="Failed to retrieve releases: %s" % e)
    finally:
        timer.cancel()

    # Helm v2 releases
    env = os.environ.copy()
    env['PATH'] = '/usr/local/sbin:' + env['PATH']
    env['KUBECONFIG'] = kubernetes.KUBERNETES_ADMIN_CONF
    helm_list = subprocess.Popen(
        ['helmv2-cli', '--',
         'helm',
         'list', '--output', 'yaml'],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timer = threading.Timer(20, helm_list.kill)

    try:
        releases = {}

        timer.start()
        out, err = helm_list.communicate()
        if out and not err:
            output = yaml.safe_load(out)
            releases = output.get('Releases', None)
        elif err and not out:
            raise exception.HelmTillerFailure(
                reason="Failed to retrieve releases: %s" % err)
        elif not err and not out:
            err_msg = "Failed to retrieve releases. " \
                      "Helm tiller response timeout."
            raise exception.HelmTillerFailure(reason=err_msg)

        for r in releases:
            r_name = r.get('Name')
            r_version = r.get('Revision')
            r_namespace = r.get('Namespace')

            deployed_releases.setdefault(r_name, {}).update(
                {r_namespace: r_version})
    except Exception as e:
        raise exception.HelmTillerFailure(
            reason="Failed to retrieve releases: %s" % e)
    finally:
        timer.cancel()

    return deployed_releases


def delete_helm_release(release):
    """Delete helm release

    This method deletes a helm release without --purge which removes
    all associated resources from kubernetes but not from the store(ETCD)

    In the scenario of updating application, the method is needed to clean
    up the releases if there were deployed releases in the old application
    but not in the new application

    :param release: the name of the helm release
    """
    # NOTE: This mechanism deletes armada/tiller managed releases.
    # This could be adapted to also delete helm v3 releases using
    # 'helm uninstall'.
    env = os.environ.copy()
    env['PATH'] = '/usr/local/sbin:' + env['PATH']
    env['KUBECONFIG'] = kubernetes.KUBERNETES_ADMIN_CONF
    helm_cmd = subprocess.Popen(
        ['helmv2-cli', '--',
         'helm', 'delete', release],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timer = threading.Timer(20, helm_cmd.kill)

    try:
        timer.start()
        out, err = helm_cmd.communicate()
        if err and not out:
            if ("deletion completed" or "not found" or "is already deleted") in err:
                LOG.debug("Release %s not found or deleted already" % release)
                return True
            raise exception.HelmTillerFailure(
                reason="Failed to delete release: %s" % err)
        elif not err and not out:
            err_msg = "Failed to delete release. " \
                      "Helm tiller response timeout."
            raise exception.HelmTillerFailure(reason=err_msg)
        return True
    except Exception as e:
        LOG.error("Failed to delete release: %s" % e)
        raise exception.HelmTillerFailure(
            reason="Failed to delete release: %s" % e)
    finally:
        timer.cancel()


def get_openstack_pending_install_charts():
    env = os.environ.copy()
    env['PATH'] = '/usr/local/sbin:' + env['PATH']
    env['KUBECONFIG'] = kubernetes.KUBERNETES_ADMIN_CONF
    try:
        return subprocess.check_output(
            ['helmv2-cli', '--',
             'helm', 'list', '--namespace', 'openstack', '--pending'],
            env=env)
    except Exception as e:
        raise exception.HelmTillerFailure(
            reason="Failed to obtain pending charts list: %s" % e)
