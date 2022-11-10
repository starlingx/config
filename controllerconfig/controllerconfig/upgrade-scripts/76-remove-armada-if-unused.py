#!/usr/bin/env python
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# The purpose of this script is to check for armada apps uploaded/applied,
# and, if none are found, remove armada, including:
# - armada helm v3 release
# - armada kubernetes namespace
# - armada docker image

import os
import psutil
import ruamel.yaml as yaml
import sys
import threading
from eventlet.green import subprocess
from time import sleep

from controllerconfig.common import log
from sysinv.common import exception
from sysinv.common import utils as common_utils
from sysinv.helm import utils as helm_utils

from sysinv.common.kubernetes import KUBERNETES_ADMIN_CONF
from tsconfig.tsconfig import PLATFORM_PATH


LOG = log.get_logger(__name__)
log.configure()

# This script should only execute in the following upgrade conditions:
ACCEPTED_FROM = ['21.12', '22.06']
ACCEPTED_TO = ['22.12']
ACCEPTED_ACTIONS = ['activate']

ARMADA_MANIFEST_DIRECTORY = os.path.join(PLATFORM_PATH, 'armada')
ARMADA_NS = 'armada'
ARMADA_RELEASE_NAME = 'armada'

TIMEOUT = 180  # timeout in seconds for armada pods to terminate
TIME_STEP = 15  # wait X seconds between checks


def run_cmd(cmd, interrupt_on_error=False, env=None):
    "A wrapper for common_utils.trycmd()"

    out, err = common_utils.trycmd(*cmd.split(), env=env)

    if err:
        if env:
            err += "\nEnv: {}".format(env)

        if interrupt_on_error:
            raise Exception(err)
        else:
            LOG.debug(err)

    return out, err


def wait_cmd_output(cmd, expected_output, timeout=TIMEOUT, step=TIME_STEP,
                    interrupt_on_error=True):
    "Executes cmd until output matches 'expected_output' or a timeout."

    LOG.debug('Wait for output of "%s" to match "%s"' % (cmd, expected_output))

    time_elapsed = 0
    while time_elapsed < timeout:
        output, _ = run_cmd(cmd, interrupt_on_error=interrupt_on_error)
        if output == expected_output:
            return time_elapsed
        sleep(step)
        time_elapsed += step

    msg = 'Timeout waiting for output of cmd "%s" to match "%s"' \
          % (cmd, expected_output)
    raise Exception(msg)


def kill_process_and_descendants(proc):
    # function to kill a process and its children processes
    for child in psutil.Process(proc.pid).children(recursive=True):
        child.kill()
    proc.kill()


def retrieve_helm_v2_releases():
    env = os.environ.copy()
    env['PATH'] = '/usr/local/sbin:' + env['PATH']
    env['KUBECONFIG'] = KUBERNETES_ADMIN_CONF
    helm_list = subprocess.Popen(
        ['helmv2-cli', '--',
         'helm',
         'list', '--output', 'yaml', '--tiller-connection-timeout', '5'],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True)
    timer = threading.Timer(20, kill_process_and_descendants, [helm_list])

    try:
        timer.start()
        out, err = helm_list.communicate()
        if helm_list.returncode != 0:
            if err:
                raise exception.HelmTillerFailure(reason=err)

            # killing the subprocesses with +kill() when timer expires
            # returns EBADF because the pipe is closed, but no error
            # string on stderr.
            if helm_list.returncode == -9:
                raise exception.HelmTillerFailure(
                    reason="helmv2-cli -- helm list operation timed out after "
                           "20 seconds. Terminated by threading timer.")
            raise exception.HelmTillerFailure(
                reason="helmv2-cli -- helm list operation failed without "
                       "error message, errno=%s" % helm_list.returncode)

        deployed_releases = {}
        if out:
            output = yaml.safe_load(out)
            releases = output.get('Releases', {})
            for r in releases:
                r_name = r.get('Name')
                r_version = r.get('Revision')
                r_namespace = r.get('Namespace')

                deployed_releases.setdefault(r_name, {}).update(
                    {r_namespace: r_version})

        return deployed_releases
    except Exception as e:
        raise exception.HelmTillerFailure(
            reason="Failed to retrieve helmv2 releases: %s" % e)
    finally:
        timer.cancel()


def is_armada_required():
    """
    Check for armada manifests or helm v2 releases.
    Return True if any are found,
    False otherwise (including if helm v2 was already removed).
    """

    # Check if there armada apps uploaded/applied, exit if there are any
    if os.path.exists(ARMADA_MANIFEST_DIRECTORY):
        for sw_version in os.listdir(ARMADA_MANIFEST_DIRECTORY):
            directory = os.path.join(ARMADA_MANIFEST_DIRECTORY, sw_version)
            if os.listdir(directory):
                LOG.debug("Armada apps found: " + str(os.listdir(directory)))
                return True

    # Check for releases in helm v2, exit if there are any
    try:
        helm_v2_releases = retrieve_helm_v2_releases()
        if helm_v2_releases:
            LOG.debug("helm v2 releases found: %s" % (list(helm_v2_releases)))
            return True
    except Exception as e:
        # Don't touch armada if helm v2 query fails for unknown reason.
        # If armada was already removed, exception message will be:
        # "helm list operation failed without error message"
        # and it's okay to continue.
        if 'operation failed' not in str(e):
            raise Exception("Error listing helm v2 releases: %s" % e)

    return False


def remove_armada_resources():
    """
    Remove Armada helm release and namespace.
    Note: removing the HR terminates pods and secrets.
    """

    # Remove armada helm v3 release
    try:
        if ARMADA_RELEASE_NAME in helm_utils.retrieve_helm_v3_releases():
            helm_utils.delete_helm_v3_release(
                ARMADA_RELEASE_NAME, namespace=ARMADA_NS)
        else:
            LOG.warning("Helm v3 release %s not found." % ARMADA_RELEASE_NAME)
    except Exception as e:
        # Couldn't remove HR, so don't touch anything else.
        raise Exception("Could not remove Armada helm release: %s" % e)

    # Wait for kubernetes armada namespace to have no resources,
    # fail after a timeout
    LOG.debug("Waiting for resources to terminate...")
    cmd = "kubectl get all -n %s -o name --kubeconfig %s" \
          % (ARMADA_NS, KUBERNETES_ADMIN_CONF)
    time_elapsed = wait_cmd_output(cmd=cmd, expected_output="")
    LOG.debug("Took about {} seconds".format(time_elapsed))

    # Remove armada namespace
    cmd = "kubectl delete namespace %s --kubeconfig %s --ignore-not-found" \
          % (ARMADA_NS, KUBERNETES_ADMIN_CONF)
    run_cmd(cmd)

    return True


def remove_armada_manifest_directory():

    cmd = "sudo rm -rf %s" % (ARMADA_MANIFEST_DIRECTORY)
    _, stderr = run_cmd(cmd)
    if stderr:
        LOG.warning("Could not remove %s" % (ARMADA_MANIFEST_DIRECTORY))
        return False

    return True


def remove_armada_docker_image():
    """
    Loads the keystone admin environment variables and uses 'system' commands
    to remove the armada docker image in the local registry.

    Return True if successful, False otherwise.
    """

    # Get env
    keystone_env = common_utils.get_keystone_admin_env()
    if not keystone_env:
        LOG.warning("While trying to remove armada image from docker registry,"
                    " could not get keystone admin env to run system commands")
        return False

    # Get image name
    cmd = "system registry-image-list"
    output, _ = run_cmd(cmd, env=keystone_env)
    if not output:
        LOG.warning("Failed to remove armada docker image. "
                    "'%s' did not return an output" % cmd)
        return False
    output = output.replace('|', '').replace('+', '').split()
    for line in output:
        if 'armada' in line:
            image_name = line
            break
    else:
        LOG.debug("Could not find armada image in docker registry.")
        return True

    # Get image tag
    cmd = "system registry-image-tags %s" % image_name
    output, _ = run_cmd(cmd, env=keystone_env)
    if not output.strip():
        LOG.warning("Armada image already deleted, but still appears on "
                    "'system registry-image-list'")
        return True
    image_tag = output.replace('|', '').replace('+', '').split()[-2]

    cmd = "system registry-image-delete %s:%s" % (image_name, image_tag)
    run_cmd(cmd, env=keystone_env)

    cmd = "system registry-garbage-collect"
    run_cmd(cmd, env=keystone_env)

    return True


def main():
    if len(sys.argv) != 4:
        error_msg = "Invalid arguments: %s" % (sys.argv)
        print(error_msg)
        LOG.error(error_msg)
        return 1

    script_name, from_release, to_release, action = sys.argv

    LOG.info("%s invoked with from_release = %s to_release = %s action = %s"
             % (script_name, from_release, to_release, action))

    if from_release in ACCEPTED_FROM and to_release in ACCEPTED_TO \
            and action in ACCEPTED_ACTIONS:

        try:
            if is_armada_required():
                LOG.info("Armada is in use. It will not be removed.")
                return 0

            LOG.info("Armada is not in use. It will be removed.")

            remove_armada_resources()
            remove_armada_manifest_directory()
            remove_armada_docker_image()

            LOG.info("Armada removed.")

        except Exception as e:
            print(e)
            LOG.error("An error occured while trying to remove armada:")
            LOG.exception(e)

        return 0


if __name__ == "__main__":
    sys.exit(main())
