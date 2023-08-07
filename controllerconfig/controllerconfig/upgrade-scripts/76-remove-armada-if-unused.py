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
from cgtsclient import client as cgts_client
from cgtsclient import exc as client_exception
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

ARMADA_MANIFEST_DIRECTORY = os.path.join(PLATFORM_PATH, 'armada')
ARMADA_NS = 'armada'
ARMADA_RELEASE_NAME = 'armada'
HELMV2_PATH = '/usr/local/sbin/helmv2-cli'
ERROR_CODE_TIMEOUT_HELMV2_CLI = -9
TIMEOUT = 180  # timeout in seconds for armada pods to terminate
TIME_STEP = 15  # wait X seconds between checks


class CgtsClient(object):
    SYSINV_API_VERSION = 1

    def __init__(self):
        self.conf = {}
        self._sysinv_client = None
        source_command = "source /etc/platform/openrc && env"
        with open(os.devnull, "w") as fnull:
            proc = subprocess.Popen(
                ["bash", "-c", source_command],
                stdout=subprocess.PIPE,
                stderr=fnull,
                universal_newlines=True,
            )
        for line in proc.stdout:
            key, _, value = line.partition("=")
            if key == "OS_USERNAME":
                self.conf["admin_user"] = value.strip()
            elif key == "OS_PASSWORD":
                self.conf["admin_pwd"] = value.strip()
            elif key == "OS_PROJECT_NAME":
                self.conf["admin_tenant"] = value.strip()
            elif key == "OS_AUTH_URL":
                self.conf["auth_url"] = value.strip()
            elif key == "OS_REGION_NAME":
                self.conf["region_name"] = value.strip()
            elif key == "OS_USER_DOMAIN_NAME":
                self.conf["user_domain"] = value.strip()
            elif key == "OS_PROJECT_DOMAIN_NAME":
                self.conf["project_domain"] = value.strip()
        proc.communicate()

    @property
    def sysinv(self):
        if not self._sysinv_client:
            self._sysinv_client = cgts_client.get_client(
                self.SYSINV_API_VERSION,
                os_username=self.conf["admin_user"],
                os_password=self.conf["admin_pwd"],
                os_auth_url=self.conf["auth_url"],
                os_project_name=self.conf["admin_tenant"],
                os_project_domain_name=self.conf["project_domain"],
                os_user_domain_name=self.conf["user_domain"],
                os_region_name=self.conf["region_name"],
                os_service_type="platform",
                os_endpoint_type="admin",
            )
        return self._sysinv_client


def run_cmd(cmd, interrupt_on_error=False):
    """A wrapper for common_utils.trycmd()"""
    out, err = common_utils.trycmd(*cmd.split())
    if err:
        if interrupt_on_error:
            raise Exception(err)
        else:
            LOG.debug(err)
    return out, err


def wait_cmd_output(cmd, expected_output, timeout=TIMEOUT, step=TIME_STEP,
                    interrupt_on_error=True):
    """Executes cmd until output matches 'expected_output' or a timeout."""
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
    """function to kill a process and its children processes"""
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
                raise exception.HelmFailure(reason=err)
            # killing the subprocesses with +kill() when timer expires
            # returns EBADF because the pipe is closed, but no error
            # string on stderr.
            if helm_list.returncode == ERROR_CODE_TIMEOUT_HELMV2_CLI:
                raise exception.HelmFailure(
                    reason="helmv2-cli -- helm list operation timed out after "
                           "20 seconds. Terminated by threading timer.")
            raise exception.HelmFailure(
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
        raise exception.HelmFailure(
            reason="Failed to retrieve helmv2 releases: %s" % e)
    finally:
        timer.cancel()


def has_helmv2_cli():
    if os.path.isfile(HELMV2_PATH):
        return True
    return False


def has_armada_pod():
    """
    Determine running armada pods, including list of status conditions
    This jsonpath gives the following output format per pod:
    armada-api-bc77f956d-jwl4n::Initialized=True:
    Ready=True:ContainersReady=True:PodScheduled=True
    """
    JSONPATH = '{range .items[*]}{"\n"}{@.metadata.name}:'\
        '{@.metadata.deletionTimestamp}{range @.status.conditions[*]}'\
        '{":"}{@.type}={@.status}{end}{end}'

    cmd = 'kubectl get pods -n armada --selector=application=armada,'\
        'component=api --field-selector status.phase=Running '\
        '--output=jsonpath="{}"'.format(JSONPATH)

    output, _ = run_cmd(cmd)

    if output:
        return True
    return False


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
    if has_helmv2_cli() and has_armada_pod():
        try:
            helm_v2_releases = retrieve_helm_v2_releases()
            if helm_v2_releases:
                LOG.debug("helm v2 releases found: %s" %
                          (list(helm_v2_releases)))
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
        if ARMADA_RELEASE_NAME in helm_utils.retrieve_helm_releases():
            helm_utils.delete_helm_release(
                ARMADA_RELEASE_NAME, namespace=ARMADA_NS)
        else:
            LOG.warning("Helm v3 release %s not found." % ARMADA_RELEASE_NAME)
    except Exception as e:
        # Couldn't remove HR, so don't touch anything else.
        LOG.error("Could not remove Armada helm release: %s. Try running "
                  "'helm uninstall -n armada armada' manually." % e)
        return False

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


def remove_docker_images():
    """
    Loads the keystone admin environment variables and uses 'system' commands
    to remove the armada docker image in the local registry.
    Return True if successful, False otherwise.
    """

    def delete_images(image_name):
        if image_name:
            image_tags = client.sysinv.registry_image.tags(image_name)
            if not image_tags:
                LOG.warning("Image %s already deleted, but still appears on "
                            "registry image list" % (image_name))
                return True

            # Delete all armada related tags
            for image_tag in image_tags:
                image_name_and_tag = "%s:%s" % (image_name, image_tag.tag)
                try:
                    client.sysinv.registry_image.delete(image_name_and_tag)
                except client_exception.HTTPNotFound:
                    LOG.error("Image not found: %s" % image_name_and_tag)
                    return False
                except Exception as e:
                    LOG.exception("Error while removing image: %s: %s"
                                  % (image_name_and_tag, e))
                    return False

            return True
        else:
            LOG.debug("Could not find image %s in docker registry."
                      % (image_name))
            return False

    client = CgtsClient()
    armada_image = None
    tiller_image = None

    # Get image names
    image_list = client.sysinv.registry_image.list()
    if not image_list:
        LOG.warning("Failed to remove armada docker image.")
        return False
    for image in image_list:
        if "airshipit/armada" in image.name:
            armada_image = image.name
        elif "helm/tiller" in image.name:
            tiller_image = image.name

    if not armada_image and not tiller_image:
        LOG.debug("Could not find armada and tiller images in "
                  "docker registry.")
        return True

    # Delete images
    if delete_images(armada_image) and delete_images(tiller_image):
        client.sysinv.registry_image.garbage_collect()
    else:
        return False

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

    if action == 'activate' and from_release >= '22.12':
        try:
            if is_armada_required():
                LOG.info("Armada is in use. Migrate existing Armada "
                         "applications to FluxCD and run the activation "
                         "step again.")
                return 1

            LOG.info("Armada is not in use. It will be removed.")

            if not remove_armada_resources():
                return 1

            if not remove_armada_manifest_directory():
                return 1

            if not remove_docker_images():
                return 1

            LOG.info("Armada removed.")
        except Exception as e:
            print(e)
            LOG.error("An error occured while trying to remove armada:")
            LOG.exception(e)
            return 1

        return 0


if __name__ == "__main__":
    sys.exit(main())
