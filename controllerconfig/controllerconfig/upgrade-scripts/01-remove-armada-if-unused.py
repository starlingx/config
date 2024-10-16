#!/usr/bin/env python
#
# Copyright (c) 2022-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# The purpose of this script is to check for armada apps uploaded/applied,
# and, if none are found, remove armada, including:
# - armada helm v3 release
# - armada kubernetes namespace
# - armada docker image

import logging as LOG
import os
import psutil
import ruamel.yaml as yaml
import sys
import threading
from cgtsclient import client as cgts_client
from cgtsclient import exc as client_exception
from eventlet.green import subprocess
from time import sleep
from sysinv.common import exception
from sysinv.common import utils as common_utils
from sysinv.helm import utils as helm_utils
from sysinv.common.kubernetes import KUBERNETES_ADMIN_CONF
from sysinv.common.kubernetes import test_k8s_health
from tsconfig.tsconfig import PLATFORM_PATH

log_format = ('%(asctime)s: ' + '[%(process)s]: '
              '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
LOG.basicConfig(filename="/var/log/software.log",
                format=log_format, level=LOG.INFO, datefmt="%FT%T")

ARMADA_MANIFEST_DIRECTORY = os.path.join(PLATFORM_PATH, 'armada')
ARMADA_NS = 'armada'
ARMADA_RELEASE_NAME = 'armada'
HELMV2_PATH = '/usr/local/sbin/helmv2-cli'
ERROR_CODE_TIMEOUT_HELMV2_CLI = -9
TIMEOUT = 180  # timeout in seconds for armada pods to terminate
TIME_STEP = 15  # wait X seconds between checks
ATTEMPTS_TO_DELETE_ARMADA_POD = 3
TIMEOUT_KUBECTL = "2m"


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


@test_k8s_health
def wait_cmd_output(cmd, expected_output, timeout=TIMEOUT, step=TIME_STEP,
                    interrupt_on_error=True):
    """Executes cmd until output matches 'expected_output' or a timeout."""
    LOG.debug('Wait for output of "%s" to match "%s"' % (cmd, expected_output))
    time_elapsed = 0
    while time_elapsed < timeout:
        output, _ = run_cmd(cmd, interrupt_on_error=interrupt_on_error)
        if output == expected_output:
            return True
        sleep(step)
        time_elapsed += step
    LOG.warning('Timeout waiting for output of cmd "%s" to match "%s"'
                % (cmd, expected_output))

    return False


def kill_process_and_descendants(proc):
    """function to kill a process and its children processes"""
    for child in psutil.Process(proc.pid).children(recursive=True):
        child.kill()
    proc.kill()


@test_k8s_health
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


@test_k8s_health
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
    Check for Armada pods with application=armada label in namespace
    armada.

    Check for helm v2 releases as an additional check.

    Return True if both are found, False otherwise.
    """

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


@test_k8s_health
def delete_armada_pods():
    """
    Best effort approach to delete lingering Armada pods

    This function is only used if deleting helmrelease is not enough
    to delete the armada pods.
    """

    get_pods_cmd = "kubectl get po -n %s -o name --kubeconfig %s" \
        % (ARMADA_NS, KUBERNETES_ADMIN_CONF)

    result = False

    try:
        # Capture the output of the kubectl command
        output, _ = run_cmd(get_pods_cmd)
        # Extract pod names from the result
        pods = output.splitlines()  # Get each line as a pod name
        if not pods:
            LOG.info("No pods found in the namespace %s." % ARMADA_NS)
            result = True
            return result

        # Delete each pod
        for pod in pods:
            pod_name = pod.split('/')[1]  # Extract the pod name
            delete_pod_cmd = "kubectl delete pod %s \
                --now --request-timeout=%s -n %s --kubeconfig %s" \
                % (pod_name,
                   TIMEOUT_KUBECTL,
                   ARMADA_NS,
                   KUBERNETES_ADMIN_CONF)

            LOG.info("Deleting pod: %s" % pod_name)

            # Retry logic for deleting the pod
            retries = ATTEMPTS_TO_DELETE_ARMADA_POD
            for attempt in range(1, retries + 1):
                try:
                    run_cmd(delete_pod_cmd, interrupt_on_error=True)
                    LOG.info("Pod %s deleted successfully." % pod_name)
                    result = True
                    break
                except Exception as e:
                    LOG.warning("Attempt %d to delete pod %s failed: %s"
                                % (attempt, pod_name, e))
                    if attempt == retries:
                        LOG.error("Failed to delete pod %s after %d attempts."
                                  % (pod_name, retries))
                        result = False
                    else:
                        LOG.info("Retrying...")

    except Exception as e:
        LOG.error("An error occurred: %s" % e)

    return result


@test_k8s_health
def has_armada_deployment():
    """
    Check if there is an active deployment in the armada namespace
    """

    cmd = "kubectl get deployment -n %s --kubeconfig %s" \
        % (ARMADA_NS, KUBERNETES_ADMIN_CONF)
    try:
        output, _ = run_cmd(cmd)
        if output:
            return True
        else:
            return False
    except Exception as e:
        LOG.error("An error occurred: %s" % e)


@test_k8s_health
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
    success = wait_cmd_output(cmd=cmd, expected_output="")

    if not success:
        # In some cases, when deleting the armada helmrelease, the pod
        # continues to run. For this cases, a targeted deletion of the
        # pods is performed.
        if not delete_armada_pods():
            LOG.error("Deletion of Armada pods failed")
            return False

        # Check if there is an active deployment in the armada namespace
        if has_armada_deployment():
            LOG.error("Deletion of Armada deployment failed")
            return False

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
    armada_images = []

    # Get image names
    filter_out_untagged = False
    image_list = client.sysinv.registry_image.list(int(filter_out_untagged))
    if not image_list:
        LOG.warning("No images were returned from the image registry."
                    "Aborting image cleanup")
        return False

    for image in image_list:
        if any(x in image.name for x in (
            'airshipit/armada',
            'starlingx/armada-image',
            'helm/tiller')
        ):
            armada_images.append(image.name)

    if armada_images:
        deletion_success = True
        for image in armada_images:
            LOG.info("Deleting image: %s" % image)

            if not delete_images(image):
                LOG.error("Could not delete image: %s. Continuing..." % image)
                deletion_success = False

        LOG.info("Running image garbage collect.")
        client.sysinv.registry_image.garbage_collect()
        return deletion_success
    else:
        LOG.info("No armada/tiller images are present in the registry.")
        return True


def drop_helm_v2_database():
    """
    Drop Helm v2 PostgreSQL database since it is not needed
    after Armada removal.
    """

    env = os.environ.copy()
    drop_database = subprocess.Popen(
        ['sudo', '-u', 'postgres',
         'psql', '-c',
         'DROP DATABASE IF EXISTS helmv2'],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True)
    timer = threading.Timer(20, kill_process_and_descendants, [drop_database])

    try:
        timer.start()
        _, err = drop_database.communicate()
        if drop_database.returncode != 0 and err:
            LOG.exception(err)
            return False
        elif drop_database.returncode != 0:
            LOG.error("Unknown error while dropping helmv2 database")
            return False
    except Exception as e:
        LOG.exception("Failed to drop helmv2 database: %s" % e)
        return False
    finally:
        timer.cancel()

    return True


def main():

    if len(sys.argv) not in [4, 5]:
        error_msg = "Invalid arguments: %s" % (sys.argv)
        print(error_msg)
        LOG.error(error_msg)
        return 1

    script_name, from_release, to_release, action = sys.argv[0:4]
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

            if not drop_helm_v2_database():
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
