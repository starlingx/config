#!/usr/bin/env python


import keyring
import psycopg2
import subprocess
import sys
import os

from psycopg2.extras import RealDictCursor


def main():
    if len(sys.argv) != 2:
        raise Exception("Release name should be specified")
    release = sys.argv[1]
    print("Starting to migrate release {}".format(release))
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
    print("Configmap {} created".format(configmap_label_name))
    os.remove(configmap_path)


def helm2to3_migrate(release_name):
    cmd = "helm 2to3 convert --kubeconfig=/etc/kubernetes/admin.conf \
          --tiller-out-cluster -s configmaps {}" \
        .format(release_name)
    execute_command(cmd)
    print("Migrated {} to helm3".format(release_name))


def cleanup_release(conn, release_name):
    cmd = "helm 2to3 cleanup --kubeconfig=/etc/kubernetes/admin.conf --release-cleanup \
          --tiller-out-cluster -s configmaps --skip-confirmation --name {}" \
        .format(release_name)
    execute_command(cmd)
    with conn:
        with conn.cursor() as cur:
            cur.execute("delete from releases where name = %s",
                        (release_name,))

    print("Cleaned up helm2 data for {}".format(release_name))


def execute_command(cmd):
    sub = subprocess.Popen(cmd, shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout, stderr = sub.communicate()
    if sub.returncode != 0:
        print("Command failed:\n %s\n%s\n%s" % (cmd, stdout, stderr))
        raise Exception("Failed to execute command: %s" % cmd)
    return stdout


if __name__ == "__main__":
    main()
