"""

Copyright (c) 2015-2018 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import numpy as np
import os
import subprocess
import sys
import textwrap
import time

from keystoneclient.auth.identity import v3
from keystoneauth1 import session as ksc_session
from cinderclient.v3 import client as cinder_client_v3
from glanceclient import Client

from cinderclient import utils as c_utils
from controllerconfig.common import log
from controllerconfig.common.rest_api_utils import get_token
from controllerconfig.common.exceptions import TidyStorageFail

LOG = log.get_logger(__name__)

KEYSTONE_AUTH_SERVER_RETRY_CNT = 60
KEYSTONE_AUTH_SERVER_WAIT = 1  # 1sec wait per retry

search_opts = {'all_tenants': 1}


class OpenStack(object):

    def __init__(self):
        self.admin_token = None
        self.conf = {}
        self.cinder_client = None
        self.glance_client_v1 = None
        self.glance_client_v2 = None

        try:
            self.conf['admin_user'] = os.environ['OS_USERNAME']
            self.conf['admin_pwd'] = os.environ['OS_PASSWORD']
            self.conf['admin_tenant'] = os.environ['OS_PROJECT_NAME']
            self.conf['auth_url'] = os.environ['OS_AUTH_URL']
            self.conf['region_name'] = os.environ['OS_REGION_NAME']
            self.conf['user_domain'] = os.environ['OS_USER_DOMAIN_NAME']
            self.conf['project_domain'] = os.environ['OS_PROJECT_DOMAIN_NAME']
        except KeyError:
            LOG.error("Please source openstack service credentials file.")
            raise TidyStorageFail("Please source openstack credentials file.")

    def __enter__(self):
        if not self._connect():
            raise Exception('Failed to connect')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._disconnect()

    def __del__(self):
        self._disconnect()

    def _connect(self):
        """ Connect to an OpenStack instance """

        if self.admin_token is not None:
            self._disconnect()

        # Try to obtain an admin token from keystone
        for _ in range(KEYSTONE_AUTH_SERVER_RETRY_CNT):
            self.admin_token = get_token(self.conf['auth_url'],
                                         self.conf['admin_tenant'],
                                         self.conf['admin_user'],
                                         self.conf['admin_pwd'],
                                         self.conf['user_domain'],
                                         self.conf['project_domain'])
            if self.admin_token:
                break
            time.sleep(KEYSTONE_AUTH_SERVER_WAIT)

        return self.admin_token is not None

    def _disconnect(self):
        """ Disconnect from an OpenStack instance """
        self.admin_token = None

    @property
    def get_cinder_client(self):
        if not self.cinder_client:
            auth = v3.Password(auth_url=self.conf['auth_url'],
                               username=self.conf['admin_user'],
                               password=self.conf['admin_pwd'],
                               user_domain_name=self.conf['user_domain'],
                               project_name=self.conf['admin_tenant'],
                               project_domain_name=self.conf['project_domain'])

            self.cinder_client = cinder_client_v3.Client(
                session=ksc_session.Session(auth=auth),
                auth_url=self.conf['auth_url'],
                endpoint_type='internalURL',
                region_name="RegionOne")

        return self.cinder_client

    @property
    def get_glance_client(self):
        if not self.glance_client_v1 or not self.glance_client_v2:
            auth = v3.Password(auth_url=self.conf['auth_url'],
                               username=self.conf['admin_user'],
                               password=self.conf['admin_pwd'],
                               user_domain_name=self.conf['user_domain'],
                               project_name=self.conf['admin_tenant'],
                               project_domain_name=self.conf['project_domain'])

            self.glance_client_v1 = Client(
                '1', session=ksc_session.Session(auth=auth))
            self.glance_client_v2 = Client(
                '2', session=ksc_session.Session(auth=auth))

        return self.glance_client_v1, self.glance_client_v2


def show_help():
    print("Usage: %s  <user_action_log_file>" % sys.argv[0])
    print(textwrap.fill(
        "Tidy storage post system restore. Check user actions "
        "in the generated user_action_log_file.", 80))


def tidy_storage(result_file):
    """
    Search Glance images DB and rbd images pool for any discrepancy
    between the two.
      - If an image is in Glance images DB but not in rbd images pool,
        list the image and suggested actions to take in a log file.
      - If an image is in rbd images pool but not in Glance images DB,
        create a Glance image in Glance images DB to associate with the
        backend data. List the image and suggested actions to take in a log
        file.

    Search Cinder volumes DB and rbd cinder-volumes pool for any discrepancy
    between the two.
       - If a volume is in Cinder volumes DB but not in rbd cinder-volumes
         pool, set the volume state to "error". List the volume and suggested
         actions to take in a log file.
       - If a volume is in rbd cinder-volumes pool but not in Cinder volumes
         DB, remove any snapshot(s) assoicated with this volume in rbd pool and
         create a volume in Cinder volumes DB to associate with the backend
         data. List the volume and suggested actions to take in a log file.
       - If a volume is in both Cinder volumes DB and rbd cinder-volumes pool
         and it has snapshot(s) in the rbd pool, re-create the snapshot in
         Cinder if it doesn't exist.

    Clean up Cinder snapshots DB if the snapshot doesn't have backend data.

    """
    with OpenStack() as client:
        # Check Glance images
        print("Scanning Glance images in DB and rbd images pool...\n")
        try:
            g_client_v1, g_client_v2 = client.get_glance_client
            image_l = g_client_v2.images.list()
            image_id_l = [image['id'].encode('utf-8') for image in image_l]

            output = subprocess.check_output(
                ["rbd",
                 "ls",
                 "--pool",
                 "images"],
                stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            LOG.error("Failed to access rbd images pool")
            raise TidyStorageFail("Failed to access rbd images pool")
        except Exception as e:
            LOG.exception(e)
            raise TidyStorageFail("Failed to list Glance images")

        rbd_image_l = [i for i in output.split('\n') if i != ""]

        print("Images in Glance images DB: %s \n" % image_id_l)
        print("Images in rbd images pool:  %s \n" % rbd_image_l)

        in_glance_only = np.setdiff1d(image_id_l, rbd_image_l)
        in_rbd_image_only = np.setdiff1d(rbd_image_l, image_id_l)

        print("Images in Glance images DB only: %s \n" % in_glance_only)
        print("Images in rbd images pool only:  %s \n" % in_rbd_image_only)

        if in_rbd_image_only.size != 0:
            output = subprocess.check_output(
                ["grep",
                 "fsid",
                 "/etc/ceph/ceph.conf"],
                stderr=subprocess.STDOUT)

            ceph_cluster = [i.strip() for i in output.split('=')
                            if i.find('fsid') == -1]

        fields = dict()
        for image in in_rbd_image_only:
            try:
                img_file = 'rbd:images/{}'.format(image)
                output = subprocess.check_output(
                    ["qemu-img", "info", img_file], stderr=subprocess.STDOUT)

                fields['disk_format'] = 'qcow2'
                for line in output.split('\n'):
                    if 'file format:' in line:
                        fields['disk_format'] = line.split(':')[1].strip()
                        break

                fields['name'] = 'found-image-%s' % image
                fields['id'] = image
                fields['container_format'] = 'bare'
                fields['location'] = \
                    'rbd://{}/images/{}/snap'.format(ceph_cluster[0],
                                                     image)

                print("Creating a Glance image %s ...\n " % fields['name'])
                g_client_v1.images.create(**fields)
            except subprocess.CalledProcessError:
                LOG.error("Failed to access rbd image %s" % image)
                raise TidyStorageFail("Failed to access rbd image")
            except Exception as e:
                LOG.exception(e)
                raise TidyStorageFail("Failed to create glance image")

        # Check cinder volume snapshots. Do it before "cinder manage"
        # operation as "cinder manage" does not support keeping the same
        # volume id.
        print("Scanning Cinder snapshots in DB and rbd cinder-volumes "
              "pool...\n")
        try:
            c_client = client.get_cinder_client
            snap_l = c_client.volume_snapshots.list(search_opts=search_opts)
        except Exception as e:
            LOG.exception(e)
            raise TidyStorageFail("Failed to get Cinder snapshots")

        snaps_no_backend_vol = []
        for snap in snap_l:
            print("Check if volume snapshot %s has backend " % snap.name)
            try:
                output = subprocess.check_output(
                    ["rbd", "ls", "--pool", "cinder-volumes"],
                    stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError:
                LOG.error("Failed to access rbd cinder-volumes pool")
                raise TidyStorageFail(
                    "Failed to access rbd cinder-volumes pool")

            found_vol = False
            for line in output.split('\n'):
                if snap.volume_id in line:
                    found_vol = True
                    break

            if found_vol:
                volume = 'cinder-volumes/volume-{}'.format(snap.volume_id)
                try:
                    output = subprocess.check_output(
                        ["rbd", "snap", "list", volume],
                        stderr=subprocess.STDOUT)

                    keep_snap = False
                    for line in output.split('\n'):
                        if snap.id in line:
                            keep_snap = True
                            break
                except subprocess.CalledProcessError:
                    LOG.info("Failed to list snapshots for volume %s in "
                             "rbd cinder-volumes pool"
                             % snap.volume_id)
                    raise TidyStorageFail("Failed to list snapshots in rbd.")

                if not keep_snap:
                    try:
                        print("Volume snapshot %s has no backend data. "
                              "Deleting it from Cinder...\n" % snap.name)

                        c_client.volume_snapshots.delete(c_utils.find_resource(
                            c_client.volume_snapshots, snap.id), force=True)

                    except Exception as e:
                        LOG.exception(e)
                        raise TidyStorageFail(
                            "Failed to delete volume snapshot")

            else:
                # Volume snapshot that doesn't have backend volume cannot
                # be deleted. If the backend volume is restored later, then
                # the snapshot can be deleted. So for now we will add these
                # snapshots in the user action log.
                snaps_no_backend_vol.append(snap)

        # Check Cinder volumes
        print("Scanning Cinder volumes in DB and rbd cinder-volumes pool...\n")
        try:
            volume_l = c_client.volumes.list(search_opts=search_opts)
            v_t_d = c_client.volume_types.default()
            avail_zones = c_client.availability_zones.list()
            pools = c_client.pools.list()
        except Exception as e:
            LOG.exception(e)
            raise TidyStorageFail("Failed to get Cinder volume info")

        if pools:
            host = pools[0].name

        if v_t_d is None:
            v_t_d = 'ceph'
        else:
            v_t_d = v_t_d.name

        cinder_volume_l = [i.id.encode('utf-8') for i in volume_l]

        if avail_zones:
            avail_z = avail_zones[0].zoneName

        try:
            output = subprocess.check_output(
                ["rbd", "ls", "--pool", "cinder-volumes"],
                stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            LOG.error("Failed to access rbd cinder-volumes pool")
            raise TidyStorageFail("Failed to access rbd cinder-volumes pool")

        rbd_volume_l = [i[7:] for i in output.split('\n') if i != ""]

        print("Volumes in Cinder volumes DB: %s \n" % cinder_volume_l)
        print("Volumes in rbd pool: %s \n" % rbd_volume_l)

        in_cinder_only = np.setdiff1d(cinder_volume_l, rbd_volume_l)
        in_rbd_volume_only = np.setdiff1d(rbd_volume_l, cinder_volume_l)
        in_cinder_and_rbd = np.intersect1d(cinder_volume_l, rbd_volume_l)

        print("Volumes in Cinder volumes DB only: %s \n" % in_cinder_only)
        print("Volumes in rbd pool only: %s \n" % in_rbd_volume_only)
        print("Volumes in Cinder volumes DB and rbd pool: %s \n"
              % in_cinder_and_rbd)

        for vol_id in in_rbd_volume_only:
            volume = 'cinder-volumes/volume-{}'.format(vol_id)
            try:
                # Find out if the volume is a bootable one
                output = subprocess.check_output(
                    ["rbd", "info", volume],
                    stderr=subprocess.STDOUT)

                bootable = False
                for line in output.split('\n'):
                    if 'parent: images/' in line:
                        bootable = True
                        break

                # Find out if the volume has any snapshots.
                print("Checking if volume %s has snapshots...\n" % vol_id)
                output = subprocess.check_output(
                    ["rbd", "snap", "list", volume], stderr=subprocess.STDOUT)

                snap_l = [item.strip() for item in output.split(' ')
                          if item.find('snapshot-') != -1]

                # Returned volume id (vol.id) will be different from vol_id
                try:
                    vol = c_client.volumes.manage(
                        host=host,
                        ref={'source-name': 'volume-%s' % vol_id},
                        name='found-volume-%s' % vol_id,
                        description='manage a volume',
                        volume_type=v_t_d,
                        availability_zone=avail_z,
                        bootable=bootable)

                    print("Creating volume found-volume-%s in Cinder...\n"
                          % vol_id)
                except Exception as e:
                    LOG.exception(e)
                    raise TidyStorageFail("Failed to manage volume")

                try:
                    for snap in snap_l:
                        # Manage a snapshot for a managed volume is not
                        # supported in rbd. So we just remove the snapshot.

                        # Remove the snapshot
                        print(textwrap.fill(
                              "Removing snapshot %s from volume %s "
                              "in rbd...\n" % (snap, vol_id), 76))
                        del_snap = '{}@{}'.format(volume, snap)
                        output = subprocess.check_output(
                            ["rbd", "snap", "unprotect", del_snap],
                            stderr=subprocess.STDOUT)

                        output = subprocess.check_output(
                            ["rbd", "snap", "rm", del_snap],
                            stderr=subprocess.STDOUT)

                except Exception as e:
                    LOG.exception(e)
                    raise TidyStorageFail("Failed to manage volume snapshot")
            except subprocess.CalledProcessError:
                LOG.error("Failed to access volume %s in cinder-volumes pool"
                          % vol_id)
                raise TidyStorageFail("Failed to access rbd image")

        for vol in in_cinder_only:
            try:
                c_client.volumes.reset_state(
                    c_utils.find_volume(c_client, vol), state='error')
                print("Setting state to error for volume %s \n" % vol)
            except Exception as e:
                LOG.error("Failed to update volume to error state for %s"
                          % vol)
                raise TidyStorageFail("Failed to update volume to error state")

        # For volumes that are in Cinder volumes DB and rbd cinder-volumes
        # pool, we check if any volume snapshot needs to be re-created
        try:
            c_s_l = c_client.volume_snapshots.list(search_opts=search_opts)
            cinder_snap_l = ['snapshot-{}'.format(snap.id) for snap in c_s_l]
        except Exception as e:
            LOG.exception(e)
            raise TidyStorageFail("Failed to get Cinder snapshots")

        for vol_id in in_cinder_and_rbd:
            volume = 'cinder-volumes/volume-{}'.format(vol_id)
            try:
                # Find out if the volume has any snapshots.
                print("Checking if volume %s has snapshots...\n" % vol_id)
                output = subprocess.check_output(
                    ["rbd", "snap", "list", volume],
                    stderr=subprocess.STDOUT)

                snap_l = [item.strip() for item in output.split(' ')
                          if item.find('snapshot-') != -1]

                for snap in snap_l:
                    if snap not in cinder_snap_l:
                        print("Creating volume snapshot found-%s "
                              "in Cinder...\n" % snap)

                        c_client.volume_snapshots.manage(
                            volume_id=vol_id,
                            ref={'source-name': snap},
                            name='found-%s' % snap,
                            description='manage a snapshot')
            except subprocess.CalledProcessError:
                LOG.error("Failed to access snapshot for volume %s"
                          % vol_id)
                raise TidyStorageFail("Failed to access volume snapshot")
            except Exception as e:
                LOG.exception(e)
                raise TidyStorageFail("Failed to manage Cinder snapshot")

        try:
            with open(result_file, 'w') as f:
                f.write('\n%s\n' % ('-' * 80))
                f.write(textwrap.fill(
                    "Following images are found in Ceph images pool but "
                    "not in Glance. These images were created after the "
                    "system backup was done. If you do not want to keep "
                    "them, you can delete them by "
                    "\"glance image-delete <id>\" command.", 80))
                f.write("\n\n")
                f.write('{0[0]:<40}{0[1]:<50}\n'.format(['ID', 'NAME']))
                image_l = g_client_v2.images.list()
                for image in image_l:
                    if image['name'].find("found-image") != -1:
                        f.write('{0[0]:<40}{0[1]:<50}\n'.format(
                            [image['id'].encode('utf-8'), image['name']]))

                f.write("\n")
                f.write('\n%s\n' % ('-' * 80))
                f.write(textwrap.fill(
                    "Following images are found in Glance without backend "
                    "data associated with. These images were deleted after "
                    "the system backup was done. You can delete them by "
                    "\"glance image-delete <id>\" command or follow the B&R "
                    "document to restore the image.", 80))
                f.write("\n\n")
                f.write('{0[0]:<40}{0[1]:<50}\n'.format(['ID', 'NAME']))
                image_l = g_client_v2.images.list()
                for image in image_l:
                    if (in_glance_only.size != 0 and
                            image['id'].encode('utf-8') in in_glance_only):
                        f.write('{0[0]:<40}{0[1]:<50}\n'.format(
                            [image['id'].encode('utf-8'), image['name']]))

                f.write("\n")
                f.write('\n%s\n' % ('-' * 80))
                f.write(textwrap.fill(
                    "Following volumes are found in Ceph cinder-volumes "
                    "pool but not in Cinder. These volumes were created "
                    "after the system backup was done. If you do not want "
                    "to keep them you can delete them by "
                    "\"cinder delete <id>\" command.", 80))
                f.write("\n\n")
                f.write('{0[0]:<40}{0[1]:<50}\n'.format(['ID', 'NAME']))
                volume_l = c_client.volumes.list(search_opts=search_opts)
                for volume in volume_l:
                    if volume.name.find("found-") != -1:
                        f.write('{0[0]:<40}{0[1]:<50}\n'.format(
                            [volume.id.encode('utf-8'), volume.name]))

                f.write("\n")
                f.write('\n%s\n' % ('-' * 80))
                f.write(textwrap.fill(
                    "Following volumes are found in Cinder without backend "
                    "data associated with. These volumes were deleted "
                    "after the system backup was done. You can delete them "
                    "by \"cinder delete <id>\" command or follow the B&R "
                    "document to restore the cinder volume.", 80))
                f.write("\n\n")
                f.write('{0[0]:<40}{0[1]:<50}\n'.format(['ID', 'NAME']))
                volume_l = c_client.volumes.list(search_opts=search_opts)
                for volume in volume_l:
                    if (in_cinder_only.size != 0 and
                            volume.id in in_cinder_only):
                        f.write('{0[0]:<40}{0[1]:<50}\n'.format(
                            [volume.id.encode('utf-8'), volume.name]))

                f.write("\n")
                f.write('\n%s\n' % ('-' * 80))
                f.write(textwrap.fill(
                    "Following volume snapshots are found in Ceph but not in "
                    "Cinder. These volume snapshots were created after the "
                    "system backup was done. If you do not want to keep them "
                    "you can delete them by \"cinder snapshot-delete <id>\" "
                    "command.", 80))
                f.write("\n\n")
                f.write('{0[0]:<40}{0[1]:<50}\n'.format(['ID', 'NAME']))
                snap_l = c_client.volume_snapshots.list(
                    search_opts=search_opts)
                for snap in snap_l:
                    if snap.name.find("found-") != -1:
                        f.write('{0[0]:<40}{0[1]:<50}\n'.format(
                            [snap.id.encode('utf-8'), snap.name]))

                f.write("\n")
                f.write('\n%s\n' % ('-' * 80))
                f.write(textwrap.fill(
                    "Following volume snapshots are found in Cinder without "
                    "backend volumes. If you want to delete them, you can do "
                    "so by \"cinder snapshot-delete <id>\" after backend "
                    "volumes are restored.", 80))
                f.write("\n\n")
                f.write('{0[0]:<40}{0[1]:<50}\n'.format(['ID', 'NAME']))
                for snap in snaps_no_backend_vol:
                        f.write('{0[0]:<40}{0[1]:<50}\n'.format(
                            [snap.id.encode('utf-8'), snap.name]))

                f.write("\n\n")

        except IOError:
            raise TidyStorageFail("Failed to open file: %s" % result_file)


def main():
    if (len(sys.argv) < 2 or
            sys.argv[1] in ['--help', '-h', '-?']):
        show_help()
        exit(1)

    log.configure()

    result_file = sys.argv[1]

    try:
        open(result_file, 'w')
    except IOError:
        raise TidyStorageFail("Failed to open file: %s" % result_file)
        exit(1)

    tidy_storage(result_file)
