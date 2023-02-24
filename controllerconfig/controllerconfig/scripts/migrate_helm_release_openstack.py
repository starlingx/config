#!/usr/bin/python
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will perform the helm v2 to helm v3
# resource migration for Openstack's helm releases.
#
# It is based on migrate_helm_release.py and basically performs the same steps
# as the script in question. The biggest difference resides in the execution
# of the helm resources labeling and annotation step.
#
# Since the Openstack related resources aren't commonly labeled with the
# "app.kubernetes.io/instance" label, which is used by the original script,
# we need to take a different approach to ensure that all Openstack related
# resources are considered, labeled and annotated correctly.
#
# The labeling and annotation process consists of two steps:
#
# 1) Labeling and annotating all resources that match the label selector
#    "release_group=<release-name>". This should match Pods, Jobs,
#    DaemonSets, ReplicaSets, etc.;
#
# 2) Labeling and annotating all resources that weren't previously considered
#    in the previous step - because they lacked the label "release_group" -
#    but that are still related to Openstack and present in the app's
#    namespace. This step uses the helm release's manifest to match
#    ConfigMaps, Secrets, Ingresses, etc.

import keyring
import os
import psycopg2
import subprocess
import sys
import yaml

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
    cleanup_jobs(release_name)


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
    try:
        execute_command(cmd)
    except Exception:
        LOG.info(
            "Configmap creation failed. "
            "Retrying with --force-conflicts=true --server-side"
        )
        cmd = "kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f {}" \
            " --force-conflicts=true --server-side" \
            .format(configmap_path)
        execute_command(cmd)
    LOG.info("Configmap {} created".format(configmap_label_name))
    os.remove(configmap_path)


def helm2to3_migrate(release_name):
    cmd = ("helm 2to3 convert --kubeconfig=/etc/kubernetes/admin.conf "
           "--tiller-out-cluster -s configmaps {}".format(release_name))
    execute_command(cmd)
    LOG.info("Migrated {} helm2 release to helm3".format(release_name))


def get_labeled_resources(release_name):
    """Get labeled resources related to an Openstack helm release."""

    labeled_resources = []

    try:
        cmd = ("kubectl --kubeconfig=/etc/kubernetes/admin.conf get "
               "-n openstack -l release_group={} --show-kind "
               "--ignore-not-found --no-headers all".format(release_name))

        resource_query = subprocess.Popen(cmd, shell=True,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE)

        output_filter = subprocess.Popen(["awk", '{print "-n openstack "$1}'],
                                         stdin=resource_query.stdout,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE,
                                         universal_newlines=True)

        resource_query.stdout.close()
        resource_list, err = output_filter.communicate()
        if output_filter.returncode != 0:
            LOG.info("Command failed:\n {}\n{}\n{}".format(
                cmd, resource_list, err))
            raise Exception("Failed to execute command: {}".format(cmd))

        if resource_list:
            labeled_resources = [lr for lr in resource_list.split("\n") if lr]
    except Exception as e:
        LOG.info("Exception {} occurred when trying to get labeled "
                 "resources".format(e))
        raise

    return labeled_resources


def get_unlabeled_resources(release_name, ignore_types=[]):
    """Get unlabeled resources related to an Openstack helm release."""

    unlabeled_resources = []

    try:
        cmd = ("helm get manifest {} -n openstack".format(release_name))

        manifest_output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT).decode('utf-8')
    except Exception as e:
        LOG.info("Exception {} occurred when trying to get helm "
                 "manifest".format(e))
        raise

    for manifest in yaml.load_all(manifest_output):
        if manifest is None:
            continue

        if manifest.get("kind") and manifest.get("metadata", {}).get("name"):
            kind = manifest["kind"].lower()
            name = manifest["metadata"]["name"].lower()

            if kind in ignore_types:
                continue

            unlabeled_resources.append("-n openstack {}/{}".format(
                kind, name))

    return unlabeled_resources


def get_unique_resource_types(resources):
    """Get unique resource types from a list of resources."""

    unique_resource_types = set()
    for resource in resources:
        # Assuming that the resources follow the format:
        # -n openstack pod/...
        # -n openstack job.batch/...
        # -n openstack daemonset.apps/...
        # -n openstack deployment.apps/...
        # Add to the set only the resource type part.
        resource_type = resource.split()[-1].split("/")[0].split(".")[0]
        unique_resource_types.add(resource_type)

    return list(unique_resource_types)


def update_release_resources(release_name):
    """ Properly label resources to support Helm v3

    Per https://github.com/helm/helm-2to3/issues/147, existing cluster
    resources deployed by helm v2 are not labeled properly for helm v3.
    Search for deployed resources based on release name and adjust the
    labeling.
    """

    LOG.info("Gathering labeled resources in Openstack's namespace...")
    labeled_resources = get_labeled_resources(release_name)
    labeled_resources_types = get_unique_resource_types(labeled_resources)

    LOG.info("Gathering unlabeled resources in Openstack's namespace...")
    unlabeled_resources = get_unlabeled_resources(
        release_name, labeled_resources_types)

    release_resources = labeled_resources + unlabeled_resources

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


def cleanup_jobs(release_name):
    """Clean up jobs

    When going from Armada to FluxCD, it has been noted that several Jobs
    can't be updated due to changes that were made in immutable fields.

    Attempting to update them results in:
    https://github.com/kubernetes/kubernetes/issues/89657

    Therefore, to avoid conflicts, all successfully completed Jobs are
    deleted beforehand.
    """

    cmd = ("kubectl -n openstack delete jobs -l release_group={} "
           "--field-selector status.successful=1".format(release_name))
    execute_command(cmd)

    # Some bootstrap jobs do not contain the `release_group` label.
    # For these, the `application` label is used.
    bootstrap_job = (
        release_name.replace("osh-openstack-", "") + "-bootstrap"
    )
    cmd = ("kubectl -n openstack delete jobs -l application={} "
           "--field-selector status.successful=1".format(bootstrap_job))
    execute_command(cmd)

    LOG.info("Cleaned up jobs for {}".format(release_name))


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
