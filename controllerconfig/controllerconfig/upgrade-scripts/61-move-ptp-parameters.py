#!/usr/bin/env python
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script moves legacy PTP configuration (contents) from other tables:
# - Global (system-wide) ptp4l configuration in 'ptp' table, by creating
#   a "legacy" 'ptp4l' entry in 'ptp_instances' table and inserting the
#   corresponding entries in 'ptp_parameters';
# - If advanced (specialized) ptp4l configuration is found in
#   'service_parameter' table, it inserts the corresponding entry(ies) in
#   'ptp_parameters' and refers to the "legacy" 'ptp4l' instance created
#   for global (system-wide) configuration;
# - If phc2sys configuration is found in 'service_parameter' table, it
#   inserts a 'phc2sys' entry in 'ptp_instances' table and inserts the
#   corresponding entry(ies) in 'ptp_parameters';
# - If any interface has 'ptp_role' not equal to 'none', it inserts a
#   'ptp4l' entry in 'ptp_instances' and inserts the corresponding entry
#   in 'ptp_parameters'.

import sys
import psycopg2
from controllerconfig.common import log
from datetime import datetime
from oslo_utils import uuidutils
from psycopg2.extras import DictCursor

LOG = log.get_logger(__name__)

PTP_PARAMETER_OWNER_INSTANCE = 'ptp-instance'

# PTP instance types
PTP_INSTANCE_TYPE_PTP4L = 'ptp4l'
PTP_INSTANCE_TYPE_PHC2SYS = 'phc2sys'

# PTP instances created during migration from service parameters
PTP_INSTANCE_LEGACY_PTP4L = 'ptp4l-legacy'
PTP_INSTANCE_LEGACY_PHC2SYS = 'phc2sys-legacy'

# Global PTP configuration migrated to legacy instance
PTP_PARAMETER_MECHANISM = 'mechanism'
PTP_PARAMETER_MODE = 'mode'
PTP_PARAMETER_TRANSPORT = 'transport'

# PTP service parameter sections
SERVICE_PARAM_SECTION_PTP_GLOBAL = 'global'
SERVICE_PARAM_SECTION_PTP_PHC2SYS = 'phc2sys'

# Special PTP service parameters migrated from legacy configuration
PTP_PARAMETER_UDS_ADDRESS = 'uds_address'
PTP_PARAMETER_DOMAIN_NUMBER = 'domainNumber'
PTP_PARAMETER_DEFAULT_DOMAIN = '0'


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
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()

    LOG.info("%s invoked from_release = %s to_release = %s action = %s"
             % (sys.argv[0], from_release, to_release, action))
    if action == "migrate" and (
       from_release == '21.05' or from_release == '21.12'):
        conn = psycopg2.connect("dbname=sysinv user=postgres")
        try:
            if _legacy_ptp4l_not_found(conn):
                _move_ptp_parameters(conn)
            res = 0
        except psycopg2.Error as ex:
            LOG.exception(ex)
            res = 1
        except Exception as ex:
            LOG.exception(ex)
            res = 1
        finally:
            conn.close()
            return res


def _legacy_ptp4l_not_found(connection):
    with connection.cursor(cursor_factory=DictCursor) as cur:
        # Look for legacy ptp4l instance already in database, which is an
        # indication this migration was performed before (probably when
        # applying an update/patch)
        cur.execute("SELECT id FROM ptp_instances WHERE name = %s;",
                    (PTP_INSTANCE_LEGACY_PTP4L,))
        ptp4l_instance = cur.fetchone()
        if ptp4l_instance is not None:
            LOG.info("Legacy ptp4l instance found with id = %s" %
                     ptp4l_instance['id'])
            return False

        LOG.info("No legacy ptp4l instance found")
        return True


def _insert_ptp_parameter_owner(connection,
                                type=PTP_PARAMETER_OWNER_INSTANCE,
                                capabilities=None):
    owner_uuid = uuidutils.generate_uuid()

    with connection.cursor(cursor_factory=DictCursor) as cur:
        LOG.debug("Creating PTP parameter owner %s" % owner_uuid)
        cur.execute("INSERT INTO ptp_parameter_owners "
                    "(created_at, uuid, type, capabilities)"
                    "VALUES (%s, %s, %s, %s);",
                    (datetime.now(), owner_uuid, type, capabilities))
        cur.execute("SELECT id FROM ptp_parameter_owners WHERE uuid = %s;",
                    (owner_uuid,))
        row = cur.fetchone()
        owner_id = row['id']

        return (owner_id, owner_uuid)


def _insert_ptp_instance(connection,
                         id,
                         name,
                         service,
                         extra_info=None):
    with connection.cursor(cursor_factory=DictCursor) as cur:
        LOG.debug("Creating PTP instance %s id %d" % (name, id))
        cur.execute("INSERT INTO ptp_instances "
                    "(id, name, service, extra_info) "
                    "VALUES (%s, %s, %s, %s);",
                    (id, name, service, extra_info))


def _insert_ptp_parameter(connection, name, value):
    param_uuid = uuidutils.generate_uuid()

    with connection.cursor(cursor_factory=DictCursor) as cur:
        LOG.debug("Creating PTP parameter %s=%s" % (name, value))
        cur.execute("INSERT INTO ptp_parameters "
                    "(created_at, uuid, name, value) "
                    "VALUES (%s, %s, %s, %s);",
                    (datetime.now(), param_uuid, name, value))

        return param_uuid


def _add_parameter_to_instance(connection, owner_uuid, param_uuid):
    with connection.cursor(cursor_factory=DictCursor) as cur:
        LOG.debug("Adding PTP parameter %s to %s" % (param_uuid, owner_uuid))
        cur.execute("INSERT INTO ptp_parameter_ownerships "
                    "(created_at, uuid, parameter_uuid, owner_uuid) "
                    "VALUES (%s, %s, %s, %s);",
                    (datetime.now(), uuidutils.generate_uuid(), param_uuid,
                     owner_uuid))


def _assign_instance_to_host(connection, instance_id, host_id):
    with connection.cursor(cursor_factory=DictCursor) as cur:
        LOG.debug("Assigning PTP instance %d to host %d" %
                  (instance_id, host_id))
        cur.execute("INSERT INTO ptp_instance_maps "
                    "(created_at, uuid, host_id, ptp_instance_id) "
                    "VALUES (%s, %s, %s, %s);",
                    (datetime.now(), uuidutils.generate_uuid(), host_id,
                     instance_id))


def _move_ptp_parameters(connection):
    with connection.cursor(cursor_factory=DictCursor) as cur:
        # List all the hosts with clock_synchronization=ptp
        cur.execute("SELECT id FROM i_host "
                    "WHERE clock_synchronization = 'ptp';")
        ptp_hosts = cur.fetchall()
        LOG.debug("There are %d hosts with clock_synchronization=ptp" %
                  len(ptp_hosts))

    with connection.cursor(cursor_factory=DictCursor) as cur:
        # List all PTP parameters in service-parameters table
        cur.execute("SELECT section, name, value FROM service_parameter "
                    "WHERE service = 'ptp';")
        param_entries = cur.fetchall()
        LOG.debug("There are %d PTP rows in 'service_parameter' table" %
                  len(param_entries))

    if len(ptp_hosts) == 0 and len(param_entries) == 0:
        # No need for upgrade
        return

    LOG.info("Creating PTP instances for legacy parameters")

    with connection.cursor(cursor_factory=DictCursor) as cur:
        # Copy global PTP configuration
        cur.execute("SELECT mechanism, mode, transport FROM ptp;")
        ptp_config = cur.fetchone()

    # Legacy instance for system-wide parameters and those of
    # section "global" in service-parameters table
    (ptp4l_id, ptp4l_uuid) = _insert_ptp_parameter_owner(connection)
    _insert_ptp_instance(connection,
                         ptp4l_id,
                         PTP_INSTANCE_LEGACY_PTP4L,
                         PTP_INSTANCE_TYPE_PTP4L)

    # Legacy instance for parameters of section "phc2sys"
    (phc2sys_id, phc2sys_uuid) = _insert_ptp_parameter_owner(connection)
    _insert_ptp_instance(connection,
                         phc2sys_id,
                         PTP_INSTANCE_LEGACY_PHC2SYS,
                         PTP_INSTANCE_TYPE_PHC2SYS)

    # Add 'uds_address' parameter to phy2sys instance for linkage
    # with ptp4l instance
    uds_address_path = '/var/run/%s' % PTP_INSTANCE_LEGACY_PTP4L
    uds_address_uuid = _insert_ptp_parameter(connection,
                                             PTP_PARAMETER_UDS_ADDRESS,
                                             uds_address_path)
    _add_parameter_to_instance(connection, phc2sys_uuid, uds_address_uuid)

    # Assign legacy instances to all hosts with
    # clock_synchronization=ptp
    for host in ptp_hosts:
        _assign_instance_to_host(connection, ptp4l_id, host['id'])
        _assign_instance_to_host(connection, phc2sys_id, host['id'])

        ptp_mechanism_uuid = _insert_ptp_parameter(
            connection, PTP_PARAMETER_MECHANISM,
            ptp_config[PTP_PARAMETER_MECHANISM])
        _add_parameter_to_instance(connection, ptp4l_uuid, ptp_mechanism_uuid)
        ptp_mode_uuid = _insert_ptp_parameter(
            connection, PTP_PARAMETER_MODE,
            ptp_config[PTP_PARAMETER_MODE])
        _add_parameter_to_instance(connection, ptp4l_uuid, ptp_mode_uuid)
        ptp_transport_uuid = _insert_ptp_parameter(
            connection, PTP_PARAMETER_TRANSPORT,
            ptp_config[PTP_PARAMETER_TRANSPORT])
        _add_parameter_to_instance(connection, ptp4l_uuid, ptp_transport_uuid)

        # Copy service-parameter PTP entries, if any
        domain_number = PTP_PARAMETER_DEFAULT_DOMAIN
        for param in param_entries:

            if param['name'] == PTP_PARAMETER_DOMAIN_NUMBER:
                domain_number = param['value']  # overwrite default
                continue  # skip it for below

            if param['section'] == SERVICE_PARAM_SECTION_PTP_GLOBAL:
                owner_uuid = ptp4l_uuid
            elif param['section'] == SERVICE_PARAM_SECTION_PTP_PHC2SYS:
                owner_uuid = phc2sys_uuid
            else:
                raise Exception("Unexpected PTP section in "
                                "'service-parameter' table")

            param_uuid = _insert_ptp_parameter(connection,
                                               param['name'],
                                               param['value'])
            _add_parameter_to_instance(connection, owner_uuid, param_uuid)

            # Whatever 'global' parameter has been found, it must be
            # added also to phc2sys instance, since now this has own
            # configuration file
            if param['section'] == SERVICE_PARAM_SECTION_PTP_GLOBAL:
                _add_parameter_to_instance(connection,
                                           phc2sys_uuid,
                                           param_uuid)

        domain_number_uuid = _insert_ptp_parameter(
            connection, PTP_PARAMETER_DOMAIN_NUMBER, domain_number)
        _add_parameter_to_instance(connection, ptp4l_uuid, domain_number_uuid)
        _add_parameter_to_instance(connection,
                                   phc2sys_uuid,
                                   domain_number_uuid)


if __name__ == "__main__":
    sys.exit(main())