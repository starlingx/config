#!/usr/bin/python
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will perform helm v2 to helm v3 resource migration. This includes
# using the helm 2to3 plugin along with labeling and annotating cluster
# resources associated with the helm release so that it is managable by helm v3
#

import keyring
import psycopg2
import subprocess
import sys
import os

from controllerconfig.common import log
from psycopg2.extras import RealDictCursor
LOG = log.get_logger(__name__)


def main():
    if len(sys.argv) != 2:
        raise Exception("Release name should be specified")

    log.configure()

    release = sys.argv[1]
    LOG.info("Starting to migrate release {}".format(release))
    conn = init_connection()
    migrate_release(conn, release)


def init_connection():
    helmv2_db_pw = keyring.get_password("helmv2", "database")
    if not helmv2_db_pw:
        raise Exception("Unable to get password to access helmv2 database.")

    return psycopg2.connect(user="admin-helmv2",
                            password=helmv2_db_pw,
                            host="localhost",
                            database="helmv2")


def migrate_release(conn, release):
    release_info = get_release_info(conn, release)
    release_name = release_info["name"]
    create_configmap(release_info)
    helm2to3_migrate(release_name)
    update_release_resources(release_name)
    cleanup_release(conn, release_name)


def get_release_info(conn, release):
    release_info = None
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("select * from releases where name = %s", (release,))
            release_info = cur.fetchone()
            if not release_info:
                raise Exception("Release name is not present in the DB")
    return release_info


def create_configmap(release_info):
    configmap_label_name = release_info["name"]
    configmap = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: {key}
  namespace: kube-system
  labels:
    NAME: {name}
    STATUS: {status}
    OWNER: {owner}
    VERSION: "{version}"
data:
  release: {release}
""".format(key=release_info["key"],
           name=configmap_label_name,
           status=release_info["status"],
           owner=release_info["owner"],
           version=release_info["version"],
           release=release_info["body"])

    configmap_path = os.path.join("/tmp", configmap_label_name + ".yaml")
    with open(configmap_path, "w") as f:
        f.write(configmap)

    cmd = "kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f {}" \
        .format(configmap_path)
    execute_command(cmd)
    LOG.info("Configmap {} created".format(configmap_label_name))
    os.remove(configmap_path)


def helm2to3_migrate(release_name):
    cmd = ("helm 2to3 convert --kubeconfig=/etc/kubernetes/admin.conf "
           "--tiller-out-cluster -s configmaps {}".format(release_name))
    execute_command(cmd)
    LOG.info("Migrated {} helm2 release to helm3".format(release_name))


def get_api_resources(namespaced=True):
    if namespaced:
        namespace_arg = ' --namespaced=true'
    else:
        namespace_arg = ' --namespaced=false'

    # Get all API resources
    try:
        api_resources = []
        api_resources_query = subprocess.check_output(
            ("kubectl --kubeconfig=/etc/kubernetes/admin.conf api-resources "
             " --verbs=list {} -o name".format(namespace_arg)),
            shell=True, stderr=subprocess.STDOUT).decode('utf-8')
        if api_resources_query:
            api_resources = [a for a in api_resources_query.split("\n") if a]
    except Exception as e:
        LOG.info("Exception {} occured when trying to get kubernetes API "
                 "resources".format(e))
        raise
    return api_resources


def update_release_resources(release_name):
    """ Properly label resources to support Helm v3

    Per https://github.com/helm/helm-2to3/issues/147, existing cluster
    resources deployed by helm v2 are not labeled properly for helm v3.
    Search for deployed resources based on release name and adjust the
    labeling.
    """

    LOG.info("Gathering namespaced kubernetes API resources...")
    namespaced_api_resources = get_api_resources(namespaced=True)

    LOG.info("Gathering non-namespaced kubernetes API resources...")
    nonamespaced_api_resources = get_api_resources(namespaced=False)

    # Get all helm release resources
    release_resources = []
    for r in namespaced_api_resources + nonamespaced_api_resources:
        if r in nonamespaced_api_resources:
            awk_print = '{print $1}'
        else:
            awk_print = '{print "-n "$1" "$2}'

        LOG.info("Searching for {} resource related to {}...".format(
            r, release_name))
        try:
            cmd = ("kubectl --kubeconfig=/etc/kubernetes/admin.conf get -A "
                   "-l app.kubernetes.io/instance={} --show-kind "
                   "--ignore-not-found --no-headers {}".format(
                       release_name, r))
            release_query = subprocess.Popen(cmd, shell=True,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE)

            output_filter = subprocess.Popen(['awk', awk_print],
                                             stdin=release_query.stdout,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE,
                                             universal_newlines=True)
            release_query.stdout.close()
            resource_list, err = output_filter.communicate()
            if output_filter.returncode != 0:
                LOG.info("Command failed:\n {}\n{}\n{}".format(
                    cmd, resource_list, err))
                raise Exception("Failed to execute command: %s" % cmd)

            if resource_list:
                resources = [r for r in resource_list.split("\n") if r]
                release_resources += resources

        except Exception as e:
            LOG.info("Exception {} occured when trying to check for {} use of "
                     "API resource {}".format(e, release_name, r))
            continue

    # Dump the resources need to be labeled/annotated
    for r in release_resources:
        LOG.info("Found {} resource: {}".format(release_name, r))

    # Label the resources appropriately to support the release upgrade
    for tiller_managed_resource in release_resources:
        try:
            labeling_out = subprocess.check_output(
                ('kubectl --kubeconfig=/etc/kubernetes/admin.conf label '
                 '--overwrite {} '
                 '"app.kubernetes.io/managed-by=Helm"'.format(
                     tiller_managed_resource)),
                shell=True, stderr=subprocess.STDOUT).decode('utf-8')
            LOG.info(labeling_out)
        except Exception as e:
            LOG.info("Exception {} occured when trying to label '{}'".format(
                e, tiller_managed_resource))
            continue

        if "-n " in tiller_managed_resource:
            # Extract and annotate the namespaced resource
            #    Ex: '-n metrics-server deployment.apps/ms-metrics-server'
            components = [c for c in tiller_managed_resource.split(" ") if c]
            namespace = components[1]

            try:
                annotate_out = subprocess.check_output(
                    ('kubectl --kubeconfig=/etc/kubernetes/admin.conf annotate'
                     ' --overwrite {} "meta.helm.sh/release-name={}" '
                     '"meta.helm.sh/release-namespace={}"'.format(
                         tiller_managed_resource, release_name, namespace)),
                    shell=True, stderr=subprocess.STDOUT).decode('utf-8')
                LOG.info(annotate_out)
            except Exception as e:
                LOG.info("Exception {} occured when trying to annotate "
                         "'{}'".format(e, tiller_managed_resource))
                continue


def cleanup_release(conn, release_name):
    cmd = ("helm 2to3 cleanup --kubeconfig=/etc/kubernetes/admin.conf "
           "--release-cleanup --tiller-out-cluster -s configmaps "
           "--skip-confirmation --name {}".format(release_name))
    execute_command(cmd)
    with conn:
        with conn.cursor() as cur:
            cur.execute("delete from releases where name = %s",
                        (release_name,))

    LOG.info("Cleaned up helm2 data for {}".format(release_name))


def execute_command(cmd):
    sub = subprocess.Popen(cmd, shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout, stderr = sub.communicate()
    if sub.returncode != 0:
        LOG.info("Command failed:\n %s\n%s\n%s" % (cmd, stdout, stderr))
        raise Exception("Failed to execute command: %s" % cmd)
    return stdout


if __name__ == "__main__":
    main()
