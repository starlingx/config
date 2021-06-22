#!/usr/bin/python
#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This migration script is used for migrating all helm releases
# from configmaps to postgresql during the activate stage of
# a platform upgrade.
#
# This script can be removed in the release that follows stx5.0
#

import collections
from datetime import datetime
import psycopg2
import subprocess
import sys
import json
import keyring

from controllerconfig.common import log

LOG = log.get_logger(__name__)

Release = collections.namedtuple(
    'release', 'key body name version status owner created_at modified_at')


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
            print ("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()

    if from_release == '20.06' and action == 'activate':
        LOG.info("%s invoked with from_release = %s to_release = %s "
                 "action = %s"
                 % (sys.argv[0], from_release, to_release, action))
        migrate_helm_releases()
        LOG.info("Complete helm releases migration for release %s "
                 "to %s with action %s."
                 % (from_release, to_release, action))


def execute_command(cmd):
    sub = subprocess.Popen(cmd, shell=True,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           universal_newlines=True)

    stdout, stderr = sub.communicate()
    if sub.returncode != 0:
        LOG.error("Command failed:\n %s\n%s\n%s" % (cmd, stdout, stderr))
        raise Exception("Failed to execute command: %s" % cmd)
    return stdout


def get_helm_releases():
    # Get all configmaps that store helm releases
    cmd = "kubectl --kubeconfig=/etc/kubernetes/admin.conf get configmaps " \
          "-n kube-system -l OWNER=TILLER --sort-by '{.metadata.name}' " \
          "--template '{{range .items}}{{.metadata.name}}{{\"\\n\"}}{{end}}'"

    releases = execute_command(cmd)
    releases_list = [r for r in releases.split('\n') if r]
    return releases_list


def delete_helm_releases():
    # Delete all configmaps that store helm releases
    cmd = "kubectl --kubeconfig=/etc/kubernetes/admin.conf delete configmaps " \
          "-n kube-system -l OWNER=TILLER"
    execute_command(cmd)


def get_helm_release_from_configmap(release_name):
    # Get the content of a specific helm release from configmap
    cmd = "kubectl --kubeconfig=/etc/kubernetes/admin.conf get configmaps " \
          "-n kube-system {} -o json".format(release_name)
    release_data = execute_command(cmd)

    return json.loads(release_data)


def map_helm_release(release):
    # Map the format of a helm release from configmap to postgresql
    try:
        key = str(release['metadata']['name'])
        body = str(release['data']['release'])
        name = str(release['metadata']['labels']['NAME'])
        version = int(release['metadata']['labels']['VERSION'])
        status = str(release['metadata']['labels']['STATUS'])
        owner = str(release['metadata']['labels']['OWNER'])
        created_at = int(datetime.strftime(datetime.strptime(
            release['metadata']['creationTimestamp'],
            "%Y-%m-%dT%H:%M:%SZ"), "%s"))
        modified_at = int(release['metadata']['labels']['MODIFIED_AT'])

        mapped_release = Release(
            key=key, body=body, name=name, version=version, status=status,
            owner=owner, created_at=created_at, modified_at=modified_at)
    except Exception as e:
        LOG.exception("Failed to convert helm release: %s" % e)
        raise

    return mapped_release


def create_helm_release_in_db(conn, release):
    with conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    "insert into releases(key, body, name, version,"
                    "status, owner, created_at, modified_at) "
                    "values(%s, %s, %s, %s, %s, %s, %s, %s)",
                    release)
            except psycopg2.IntegrityError:
                # release already exists
                pass
            except Exception as e:
                LOG.exception("Failed to create release in db:\n%s" % e)
                raise


def migrate_helm_releases():
    releases = get_helm_releases()

    if not releases:
        LOG.info("No helm releases need to be migrated.")
        return

    LOG.info("Start migrating helm releases:\n%s" % releases)

    helmv2_db_pw = keyring.get_password("helmv2", "database")
    if not helmv2_db_pw:
        raise Exception("Unable to get password to access helmv2 database.")

    try:
        conn = psycopg2.connect(user="admin-helmv2",
                                password=helmv2_db_pw,
                                host="localhost",
                                database="helmv2")
    except Exception as e:
        LOG.exception("Failed to connect helmv2 database: %s" % e)
        raise

    for release in releases:
        release_data = get_helm_release_from_configmap(release)
        mapped_release = map_helm_release(release_data)
        create_helm_release_in_db(conn, mapped_release)
        LOG.info("Migrated release: %s" % release)

    delete_helm_releases()


if __name__ == "__main__":
    sys.exit(main())
