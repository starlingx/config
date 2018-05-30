#!/usr/bin/env python
# Copyright (c) 2017-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will update the storage backends for controller-1.

import psycopg2
import sys
import json

from sysinv.openstack.common import uuidutils
from sysinv.common import constants
from psycopg2.extras import RealDictCursor
from controllerconfig.common import log
from controllerconfig.upgrades import utils

LOG = log.get_logger(__name__)

CINDER_BACKEND = None
CONFIG_CINDER_LVM_TYPE = "CONFIG_CINDER_LVM_TYPE"


def main():
    action = None
    from_release = None
    to_release = None  # noqa
    arg = 1

    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]  # noqa
        elif arg == 3:
            action = sys.argv[arg]
        else:
            print ("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()

    if from_release == "17.06" and action == "migrate":
        try:
            set_backends(from_release)
        except Exception as ex:
            LOG.exception(ex)
            return 1


def update_capabilities(cur):
    # Update i_idisk capabilities.
    cur.execute("select i_idisk.forihostid, i_idisk.uuid, "
                "i_idisk.device_node, i_idisk.device_path, "
                "i_idisk.id, i_idisk.capabilities from i_idisk")

    disks = cur.fetchall()
    for d in disks:
        d_json_dict = json.loads(d['capabilities'])
        if constants.IDISK_DEV_FUNCTION in d_json_dict:
            del d_json_dict[constants.IDISK_DEV_FUNCTION]
            d_new_capab = json.dumps(d_json_dict)

            try:
                cur.execute(
                    "update i_idisk set capabilities=%s "
                    "where id=%s",
                    (d_new_capab, d['id']))
            except Exception as e:
                LOG.exception("Error: %s" % str(e))
                raise

    # Update i_system capabilities.
    cur.execute("select i_system.id, i_system.capabilities "
                "from i_system")
    systems = cur.fetchall()
    for s in systems:
        s_json_dict = json.loads(s['capabilities'])
        if 'cinder_backend' in s_json_dict:
            del s_json_dict['cinder_backend']
            s_new_capab = json.dumps(s_json_dict)
            cur.execute(
                "update i_system set capabilities=%s "
                "where id=%s",
                (s_new_capab, s['id']))


def update_stors(cur):
    # Get the stors
    cur.execute("select i_istor.id, i_istor.idisk_uuid, "
                "i_istor.function, i_istor.forihostid "
                "from i_istor ")
    stors = cur.fetchall()

    for stor in stors:
        if stor['function'] == constants.STOR_FUNCTION_CINDER:
            # remove cinder stors
            try:
                cur.execute(
                    "update i_idisk set foristorid=null where uuid=%s",
                    (stor['idisk_uuid'],))
                cur.execute(
                    "delete from i_istor where id=%s",
                    (stor['id'],))
            except Exception as e:
                LOG.exception("Error: %s" % str(e))
                raise
        elif stor['function'] == constants.STOR_FUNCTION_OSD:
            # link OSDs to the primary storage tier
            try:
                cur.execute(
                    "update i_istor set fortierid=1 where id=%s",
                    (stor['id'],))
            except Exception as e:
                LOG.exception("Error: %s" % str(e))
                raise


def add_primary_storage_tier(cur):
    # A cluster and a primary tier are always present even if we don't have
    # a ceph backend currently enabled. So make sure on upgrade we add the tier
    # referencing the existing cluster.
    new_storage_tier_uuid = uuidutils.generate_uuid()
    try:
        # Currently only 1 cluster ever defined, id must be 1
        cur.execute("insert into storage_tiers(uuid, id, name, type, status, "
                    "capabilities, forclusterid) "
                    "values(%s, %s, %s, %s, %s, %s, %s)",
                    (new_storage_tier_uuid, '1',
                     constants.SB_TIER_DEFAULT_NAMES[
                         constants.SB_TIER_TYPE_CEPH],
                     constants.SB_TIER_TYPE_CEPH,
                     constants.SB_TIER_STATUS_DEFINED,
                     '{}', '1'))
    except Exception as e:
        LOG.exception("Error inserting into storage_tiers: %s" % str(e))

    LOG.info("Primary Storage Tier added.")


def update_storage_backends(cur):
    global CINDER_BACKEND
    cur.execute("select storage_backend.id, storage_backend.backend, "
                "storage_backend.state, "
                "storage_backend.forisystemid, storage_backend.services, "
                "storage_backend.capabilities from storage_backend")
    storage_backend = cur.fetchone()
    LOG.info("storage_backend: %s" % str(storage_backend))
    if not storage_backend:
        LOG.exception("No storage backend present, exiting.")
        raise

    backend = storage_backend['backend']

    if backend == "ceph":
        CINDER_BACKEND = constants.SB_TYPE_CEPH
        LOG.info("Ceph backend")
        cur.execute(
            "select storage_ceph.id, storage_ceph.object_gateway "
            "from storage_ceph")
        storage_ceph = cur.fetchone()
        if not storage_ceph:
            LOG.exception("No storage_ceph entry, exiting.")
            raise

        services = "{0}, {1}".format(constants.SB_SVC_CINDER,
                                     constants.SB_SVC_GLANCE)
        if storage_ceph['object_gateway'] == "t":
            services = "cinder, glance, swift"
        LOG.info("Services ran on ceph: %s" % services)

        try:
            cur.execute(
                "update storage_backend set state=%s, services=%s, "
                "capabilities=%s where id=%s",
                (constants.SB_DEFAULT_NAMES[constants.SB_TYPE_CEPH],
                 constants.SB_STATE_CONFIGURED, services,
                 '{"replication":"2", "min_replication":"1"}',
                 storage_backend['id']))

            cur.execute(
                "update storage_ceph set tier_id=%s where id=%s",
                ('1', storage_backend['id']))
        except Exception as e:
            LOG.exception("Error: %s" % str(e))
            raise

    elif backend == "lvm":
        CINDER_BACKEND = constants.SB_TYPE_LVM
        LOG.info("LVM backend")
        cur.execute(
            "update storage_backend set name=%s, state=%s, services=%s, "
            "capabilities=%s where id=%s",
            (constants.SB_DEFAULT_NAMES[constants.SB_TYPE_LVM],
             constants.SB_STATE_CONFIGURED, constants.SB_SVC_CINDER, '{}',
             storage_backend['id']))
    else:
        LOG.info("Other backend present: %s" % backend)
        return

    new_storage_backend_uuid = uuidutils.generate_uuid()
    cur.execute(
        "insert into storage_backend(uuid, name, backend, state, "
        "forisystemid, services, capabilities) "
        "values(%s, %s, %s, %s, %s, %s, %s)",
        (new_storage_backend_uuid,
         constants.SB_DEFAULT_NAMES[constants.SB_TYPE_FILE],
         constants.SB_TYPE_FILE, constants.SB_STATE_CONFIGURED,
         storage_backend['forisystemid'], constants.SB_SVC_GLANCE, '{}'))
    try:
        cur.execute(
            "select storage_backend.id, storage_backend.name, "
            "storage_backend.backend, storage_backend.state, "
            "storage_backend.forisystemid, storage_backend.services, "
            "storage_backend.capabilities from storage_backend where "
            "services=%s", (constants.SB_SVC_GLANCE,))
    except Exception as e:
        LOG.exception("Error selecting the storage backend for glance: %s"
                      % str(e))
    storage_backend_glance = cur.fetchone()

    try:
        cur.execute("insert into storage_file(id) values(%s)",
                    (storage_backend_glance['id'],))
    except Exception as e:
        LOG.exception("Error inserting into storage file: %s" % str(e))

    LOG.info("Backends updated")


def update_legacy_cache_tier(cur):
    feature_enabled = constants.SERVICE_PARAM_CEPH_CACHE_TIER_FEATURE_ENABLED
    cur.execute("select * from service_parameter where service=%s and "
                "name=%s", (constants.SERVICE_TYPE_CEPH, feature_enabled,))
    parameters = cur.fetchall()
    if parameters is None or len(parameters) == 0:
        LOG.exception("Failed to fetch ceph service_parameter data")
        raise

    # Make sure that cache tiering is disabled: Not supported but not removed
    LOG.info("Updating ceph service parameters")
    cur.execute("update service_parameter set value='false' where "
                "service=%s and name=%s",
                (constants.SERVICE_TYPE_CEPH, feature_enabled,))


def update_lvm_type(cur, from_release):
    lvm_type = None
    packstack_config = utils.get_packstack_config(from_release)

    try:
        config_cinder_lvm_type = packstack_config.get(
            'general', CONFIG_CINDER_LVM_TYPE)
    except Exception:
        # For upgrades from R2, this value may be missing
        # If so we log and use the default value of thin
        LOG.info("No %s option. Using Default thin." % CONFIG_CINDER_LVM_TYPE)
        config_cinder_lvm_type = constants.CINDER_LVM_TYPE_THIN

    # Determine the lvm_type from the packstack-answers.txt file.
    # If this information is missing, just give a warning and continue
    # with the upgrade since this is not critical.
    if constants.CINDER_LVM_TYPE_THIN in config_cinder_lvm_type.lower():
        lvm_type = constants.CINDER_LVM_TYPE_THIN
    elif constants.CINDER_LVM_TYPE_THICK in config_cinder_lvm_type.lower():
        lvm_type = constants.CINDER_LVM_TYPE_THICK
    else:
        LOG.warning("No %s or %s LVM type" % (constants.CINDER_LVM_TYPE_THIN,
                                              constants.CINDER_LVM_TYPE_THICK))

    if not lvm_type:
        LOG.warning("No %s option" % CONFIG_CINDER_LVM_TYPE)
        lvm_type = constants.CINDER_LVM_TYPE_THIN

    LOG.info("lvm_type: %s" % lvm_type)
    capabilities = '{"lvm_type": "%s"}' % lvm_type
    cur.execute("update i_lvg set capabilities=%s where lvm_vg_name=%s",
                (capabilities, constants.LVG_CINDER_VOLUMES))


def set_backends(from_release):
    conn = psycopg2.connect("dbname=sysinv user=postgres")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            update_stors(cur)
            update_capabilities(cur)
            add_primary_storage_tier(cur)
            update_storage_backends(cur)
            if CINDER_BACKEND == constants.SB_TYPE_CEPH:
                update_legacy_cache_tier(cur)
            if CINDER_BACKEND == constants.SB_TYPE_LVM:
                update_lvm_type(cur, from_release)


if __name__ == "__main__":
    sys.exit(main())
