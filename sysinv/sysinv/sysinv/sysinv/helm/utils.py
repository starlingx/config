# sim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

"""Helm utilities and helper functions."""

import base64
import json
import os
import time
import psutil
import ruamel.yaml as yaml
import io
import tempfile
import random
import string
import threading
import zlib

from eventlet.green import subprocess
from oslo_context import context
from oslo_log import log as logging
from sysinv.agent import rpcapiproxy as agent_rpcapi
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common.retrying import retry
from sysinv.helm import common


LOG = logging.getLogger(__name__)


# TODO(agrosu):
# There is a lot of duplicate code just to execute a helm command
# in a subshel.
# We should either move to a Helm API or, at least, move all this
# suprocess calling and error handling into a common function/object.
# python3 supports a 'timeout' parameter for +communicate() which
# will raise a subprocess.TimeoutExpired.
# When python3 migration is finished, the explicit timer should
# be removed.

# TODO(lfagunde):
# Some of the logic in here is outdated and assumes the default helm used is v2,
# such as the delete_helm_release() function.
# Also, this module would benefit from refatoring to add more
# functionality and make the current functions more flexible.
# Could create a generic "execute_helm_cmd" style function and derive the
# specific ones (list, delete, etc) from there. If that's done, remember
# to update function calls done to this module from elsewhere in the code.

def kill_process_and_descendants(proc):
    # function to kill a process and its children processes
    for child in psutil.Process(proc.pid).children(recursive=True):
        child.kill()
    proc.kill()


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


def _retry_on_HelmFailure(ex):
    LOG.info('Caught exception retrieving helm releases. Retrying... Exception: {}'.format(ex))
    return isinstance(ex, exception.HelmFailure)


@retry(stop_max_attempt_number=6, wait_fixed=20 * 1000,
       retry_on_exception=_retry_on_HelmFailure)
def retrieve_helm_releases():
    helm_list = subprocess.Popen(
        ['helm', '--kubeconfig', kubernetes.KUBERNETES_ADMIN_CONF,
         'list', '--all-namespaces', '--output', 'yaml'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True)
    timer = threading.Timer(20, kill_process_and_descendants, [helm_list])

    try:
        timer.start()
        out, err = helm_list.communicate()
        if helm_list.returncode != 0:
            if err:
                raise exception.HelmFailure(reason=err)

            # killing the subprocesses with +kill() when timer expires returns EBADF
            # because the pipe is closed, but no error string on stderr.
            if helm_list.returncode == -9:
                raise exception.HelmFailure(
                    reason="helm list operation timed out after "
                           "20 seconds. Terminated by threading timer.")
            raise exception.HelmFailure(
                reason="helm list operation failed without error "
                       "message, errno=%s" % helm_list.returncode)

        deployed_releases = {}
        if out:
            releases = yaml.safe_load(out)
            for r in releases:
                r_name = r.get('name')
                r_version = r.get('revision')
                r_namespace = r.get('namespace')

                deployed_releases.setdefault(r_name, {}).update(
                    {r_namespace: r_version})

        return deployed_releases
    except Exception as e:
        raise exception.HelmFailure(
            reason="Failed to retrieve helm releases: %s" % e)
    finally:
        timer.cancel()


def delete_helm_release(release, namespace="default", flags=None):
    """Delete helm release via callout to helm command

    :param release: Helm release name
    :param namespace: Helm release namespace
    :param flags: List with any other flags required to add to the command
    """

    env = os.environ.copy()
    env['PATH'] = '/usr/local/sbin:' + env['PATH']
    env['KUBECONFIG'] = kubernetes.KUBERNETES_ADMIN_CONF

    helm_cmd = ['helm', 'uninstall', '-n', namespace, release]
    if flags:
        helm_cmd += flags

    process = subprocess.Popen(
        helm_cmd,
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True)
    timer = threading.Timer(20, kill_process_and_descendants, [process])

    try:
        timer.start()
        out, err = process.communicate()

        if process.returncode == 0 and err:
            LOG.warning("Command: %s; %s" % (' '.join(helm_cmd), err))
        elif err:
            if "not found" in err:
                LOG.error("Release %s/%s not found or deleted already" % (namespace, release))
                return out, err
            raise exception.HelmFailure(
                reason="Failed to delete release: %s" % err)
        elif not out:
            err_msg = "Failed to execute helm command. " \
                      "Helm response timeout."
            raise exception.HelmFailure(reason=err_msg)

        return out, err
    except Exception as e:
        LOG.error("Failed to execute helm command: %s" % e)
        raise exception.HelmFailure(
            reason="Failed to execute helm command: %s" % e)
    finally:
        timer.cancel()


def create_tmp_chart_dir():
    """ Create a helm-compatible temporary chart directory

    Chart directory names must have only lower cases letters and
    numbers in order to be accepted as valid by Helm.

    :returns: full path of the temporary directory created
    """

    dir_name = ''.join(random.choices(
                    string.ascii_lowercase + string.digits, k=32))
    dir_path = os.path.join(tempfile.gettempdir(), dir_name)
    os.mkdir(dir_path)

    return dir_path


def install_helm_chart_with_dry_run(args=None):
    """Simulate a chart install

    This method calls helm install with --dry-run option to simulate
    a chart install to generate the rendered templates. It's being
    used to merge the application's system overrides and user overrides
    by passing helm chart overrides to the helm command.

    :param args: additional arguments to helm command
    """
    env = os.environ.copy()
    env['KUBECONFIG'] = kubernetes.KUBERNETES_ADMIN_CONF
    cmd = ['helm', 'install', '--dry-run', '--debug', '--generate-name']
    if args:
        cmd.extend(args)

    timer = None
    try:
        # Make a temporary directory with a fake chart in it
        tmpdir = create_tmp_chart_dir()
        chartfile = tmpdir + '/Chart.yaml'
        with open(chartfile, 'w') as tmpchart:
            tmpchart.write('name: mychart\napiVersion: v1\n'
                           'version: 0.1.0\n')
        cmd.append(tmpdir)

        helm_install = subprocess.Popen(
            cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True)
        timer = threading.Timer(10, kill_process_and_descendants, [helm_install])

        timer.start()
        out, err = helm_install.communicate()
        if helm_install.returncode == 0:
            return out
        elif err:
            raise exception.HelmFailure(reason=err)
        else:
            err_msg = "Helm install --dry-run operation timeout."
            raise exception.HelmFailure(reason=err_msg)
    except Exception as e:
        raise exception.HelmFailure(
            reason="Failed to render helm chart: %s" % e)
    finally:
        if timer:
            timer.cancel()
        os.remove(chartfile)
        os.rmdir(tmpdir)


def decompress_helm_release_data(release_data):
    """ Convert release data to format for applying transformations

    :param release_data: Helm release secret data
                         Format is gzip double base64 encoded
    :return: string
    """
    release_data = base64.b64decode(release_data)
    release_data = base64.b64decode(release_data)
    # wbits value needs to specify 16 for gzip header/trailer plus window size.
    # Window size needs to be at least the one used for compression
    # this set the largest
    release_data = zlib.decompress(release_data, wbits=16 + zlib.MAX_WBITS).decode('utf-8')

    return str(release_data)


def compress_helm_release_data(release_data):
    """ Convert release data to format for storing in cluster

    :param release_data: Helm release secret data
    :return: string
             Format is gzip double base64 encoded
    """
    # wbits value of 25 specifies the minimum window size
    # and gzip header/trailer.
    compressed_object = zlib.compressobj(wbits=25)

    release_data = compressed_object.compress(release_data.encode('utf-8'))
    release_data += compressed_object.flush()
    release_data = base64.b64encode(release_data)
    release_data = base64.b64encode(release_data)

    release_data = release_data.decode('utf-8')

    return release_data


def build_overrides_filename(chart_name, namespace=None):
    """ Build a standardized overrides filename

    :param chart_name: Name of the Helm chart
    :param namespace: Chart base namespace
    :return: string
             Standardized overrides filename
    """
    filename = chart_name + ".yaml"
    if namespace:
        filename = namespace + "-" + filename

    return filename


def get_chart_tarball_path(repo_path, chart_name, chart_version):
    """ Get the path of a chart tarball available in a Helm repository.

    :param repo_path: Filesystem path to the Helm repository
    :param chart_name: Name of the Helm chart
    :param chart_version: Version of the Helm chart
    :return: String with full path of the chart tarball in the repository if a
             matching chart/version is found. Otherwise returns None.
    """

    repo_index_file = os.path.join(repo_path, "index.yaml")
    with io.open(repo_index_file, "r", encoding="utf-8") as f:
        root_index_yaml = next(yaml.safe_load_all(f))
        if chart_name in root_index_yaml["entries"]:
            chart_versions = root_index_yaml["entries"][chart_name]

            for chart in chart_versions:
                if chart["version"] == chart_version and len(chart["urls"]) > 0:
                    return os.path.join(repo_path, chart["urls"][0])
        else:
            LOG.warning("Chart {} not found in {}."
                        .format(chart_name, repo_index_file))
            return None


def index_repo(repo_path):
    """ Index a given Helm repository.

    :param repo_path: Filesystem path to the Helm repository
    """

    helm_cmd = ['helm', 'repo', 'index', repo_path]
    env = os.environ.copy()
    env['KUBECONFIG'] = kubernetes.KUBERNETES_ADMIN_CONF

    process = subprocess.Popen(
        helm_cmd,
        env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True)
    timer = threading.Timer(20, kill_process_and_descendants, [process])

    try:
        timer.start()
        _, err = process.communicate()

        if process.returncode is None or (process.returncode < 0 and not err):
            err_msg = "Timeout while indexing repository {}".format(repo_path)
            raise exception.HelmFailure(reason=err_msg)
        elif process.returncode == 0 and err:
            LOG.warning("Command: %s; %s" % (' '.join(helm_cmd), err))
        elif err:
            LOG.error("Failed to index repository {}".format(repo_path))
            raise exception.HelmFailure(reason=err)
    except Exception as e:
        err_msg = "Failed to execute Helm command: {}".format(e)
        LOG.error(err_msg)
        raise exception.HelmFailure(reason=err_msg)
    finally:
        timer.cancel()


def extract_repository_info(helmrepo_path):
    """ Extract the Helm repository name, url and local path from
    a HelmRepository file.

    :param helmrepo_path: The path to file that contains the HelmRepository definition.
    :return: A dictionary containing the HelmRepository name, url and local path.
    """

    with io.open(helmrepo_path, 'r', encoding='utf-8') as f:
        helm_repo_yaml = next(yaml.safe_load_all(f))

    helm_repo_url = helm_repo_yaml["spec"]["url"]
    helm_repo_name = helm_repo_yaml["metadata"]["name"]
    target_folder = helm_repo_url.rsplit('/', 1)[-1]

    # Check if repository is supported
    if target_folder in common.HELM_SUPPORTED_REPOS:
        helm_repo_local_path = os.path.join(common.HELM_REPO_BASE_PATH, target_folder)
    else:
        raise exception.SysinvException(f"Repository {helm_repo_url} from {helmrepo_path} "
                                        "is not supported")

    repository_dict = {"name": helm_repo_name,
                       "url": helm_repo_url,
                       "path": helm_repo_local_path
                       }

    return repository_dict


@retry(retry_on_exception=lambda x: isinstance(x, exception.SysinvException),
       stop_max_attempt_number=3)
def call_fluxcd_reconciliation(helmrelease, namespace):
    """ Force fluxcd reconciliation

    The purpose of this function is to force a fluxcd reconciliation to be
    called. Changing any value in the helmrelease spec is capable of triggering
    reconciliation. Updating spec.value.reconcile_trigger has no side effects.

    Param: helmrelease (string): helmrelease name
    param: namespace (string): namespace where the target helmrelease is installed
    """

    timestamp = int(time.time())

    # Create the patch data as a dictionary
    patch_data = {
        "spec": {
            "values": {
                "reconcile_trigger": timestamp
            }
        }
    }
    patch_json = json.dumps(patch_data)

    # TODO (dbarbosa):
    # When the fluxcd CLI is available, the "kubectl patch" command used here to
    # force helm-controler reconciliation should be replaced with "flux reconcile".
    cmd = [
        "kubectl", "patch", "helmrelease", helmrelease, "-n", namespace,
        "--type=merge", "-p", patch_json, "--request-timeout=5s"
    ]

    env = os.environ.copy()
    env['KUBECONFIG'] = kubernetes.KUBERNETES_ADMIN_CONF

    try:
        process = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, universal_newlines=True)
        _, stderr = process.communicate()

        if process.returncode != 0:
            raise exception.SysinvException(f"Error executing kubectl patch: {stderr}")

    except Exception as e:
        raise exception.SysinvException(f"Error trying to force reconciliation via \
                                        {cmd}, reason: {e}")


@retry(retry_on_exception=lambda x: isinstance(x, exception.SysinvException),
       stop_max_attempt_number=3)
def call_fluxcd_repository_reconciliation(helm_repos):
    """ Force Flux's repository reconciliation

    The purpose of this function is to force a reconciliation of FluxCD's internal
    repositories. The HelmRepository object is annotated to trigger the reconciliation
    outside the specified interval window.

    param: helm_repos: list of yaml formatted HelmRepository objects
    """

    timestamp = int(time.time())
    env = os.environ.copy()
    env['KUBECONFIG'] = kubernetes.KUBERNETES_ADMIN_CONF

    for helmrepo in helm_repos:
        name = helmrepo['metadata']['name']
        try:
            namespace = helmrepo['metadata']['namespace']
        except KeyError:
            namespace = "default"

        cmd = [
            "kubectl",
            "annotate",
            "--field-manager=flux-client-side-apply",
            "-n", f"{namespace}",
            "--overwrite",
            f"helmrepository/{name}",
            f"reconcile.fluxcd.io/requestedAt=\"{timestamp}\"",
            "--request-timeout=5s"
        ]

        LOG.info(f"Requesting reconciliation for {namespace}/{name} repository")
        try:
            process = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, universal_newlines=True)
            _, stderr = process.communicate()

            if process.returncode != 0:
                raise exception.SysinvException(f"Error executing kubectl annotate: {stderr}")

        except Exception as e:
            raise exception.SysinvException(f"Error trying to force repository reconciliation \
                                            via {cmd}, reason: {e}")
