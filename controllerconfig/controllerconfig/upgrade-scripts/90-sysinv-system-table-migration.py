#!/usr/bin/env python
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This migration script converts the sdn_enabled field in the system table
# from y/n to True/False

import json
import sys
import uuid

import psycopg2
from netaddr import IPNetwork
from controllerconfig.common import log
from psycopg2.extras import RealDictCursor, DictCursor
from controllerconfig.upgrades import utils
from sysinv.common import constants


LOG = log.get_logger(__name__)


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
            LOG.info("Performing system migration from release %s to %s with "
                     "action: %s" % (from_release, to_release, action))
            packstack_config = utils.get_packstack_config(from_release)
            config_region = packstack_config.get('general', 'CONFIG_REGION')
            if config_region == 'y':
                region_name = packstack_config.get('general',
                                                   'CONFIG_REGION_2_NAME')
            else:
                region_name = packstack_config.get('general',
                                                   'CONFIG_KEYSTONE_REGION')
            project_name = packstack_config.get('general',
                                                'CONFIG_SERVICE_TENANT_NAME')
            multicast_subnet = IPNetwork(packstack_config.get(
                'general', 'CONFIG_MULTICAST_MGMT_SUBNET'))
            pxeboot_subnet = IPNetwork(packstack_config.get(
                'general', 'CONFIG_PLATFORM_PXEBOOT_SUBNET'))
            mtu = packstack_config.get('general', 'CONFIG_PLATFORM_MGMT_MTU')
            conn = psycopg2.connect("dbname='sysinv' user='postgres'")
            with conn:
                update_system_table(conn, region_name, project_name)
                populate_multicast_address_records(conn, multicast_subnet, mtu)
                populate_pxeboot_address_records(conn, pxeboot_subnet, mtu)
        except Exception as ex:
            LOG.exception(ex)
            print ex
            return 1


def update_system_table(conn, region_name, project_name):
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("select capabilities from i_system WHERE id = 1;")
        capabilities = cur.fetchone()
        if capabilities is None:
            LOG.exception("Failed to fetch i_system data")
            raise

        fields_str = capabilities.get('capabilities')
        fields_dict = json.loads(fields_str)

        if fields_dict.get('region_config') == 'True':
            new_vals = {'region_config': True}
        else:
            new_vals = {'region_config': False}
        fields_dict.update(new_vals)

        new_cap = json.dumps(fields_dict)

        LOG.info("Updating system capabilities %s to %s"
                 % (capabilities, new_cap))
        cur.execute("update i_system set capabilities=%s, "
                    "region_name=%s, service_project_name=%s WHERE id=1",
                    (new_cap, region_name, project_name))


def populate_multicast_address_records(conn, multicast_subnet, mtu):
    pool_name = 'multicast-subnet'
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute('insert into address_pools(uuid,name,family,network,'
                    'prefix,"order") VALUES(%s, %s, %s, %s, %s, %s)',
                    (str(uuid.uuid4()), pool_name, multicast_subnet.version,
                     str(multicast_subnet.network), multicast_subnet.prefixlen,
                     'random'))
        cur.execute("select id from address_pools WHERE name=%s;",
                    (pool_name,))
        pool_row = cur.fetchone()
        if pool_row is None:
            LOG.exception("Failed to fetch pool id for %s", pool_name)
            raise

        pool_id = pool_row['id']
        cur.execute('insert into address_pool_ranges(address_pool_id,uuid,'
                    'start,"end") VALUES(%s, %s, %s, %s)',
                    (pool_id, str(uuid.uuid4()),
                     str(multicast_subnet[1]),
                     str(multicast_subnet[-2])))
        cur.execute("insert into networks(id, address_pool_id, uuid,"
                    "type, mtu, dynamic) values(%s, %s, %s, %s, %s, False)",
                    (pool_id, pool_id, str(uuid.uuid4()),
                     constants.NETWORK_TYPE_MULTICAST, mtu))
        addresses = {
            constants.SM_MULTICAST_MGMT_IP_NAME:
                str(multicast_subnet[1]),
            constants.MTCE_MULTICAST_MGMT_IP_NAME:
                str(multicast_subnet[2]),
            constants.PATCH_CONTROLLER_MULTICAST_MGMT_IP_NAME:
                str(multicast_subnet[3]),
            constants.PATCH_AGENT_MULTICAST_MGMT_IP_NAME:
                str(multicast_subnet[4]),
        }
        for name, address in addresses.iteritems():
            address_name = "%s-%s" % (name, constants.NETWORK_TYPE_MULTICAST)
            cur.execute("insert into addresses(uuid, address_pool_id, address,"
                        "prefix, name, family, enable_dad) values(%s, %s, %s,"
                        "%s, %s, %s, False)",
                        (str(uuid.uuid4()), pool_id, str(address),
                         multicast_subnet.prefixlen, address_name,

                         multicast_subnet.version))


def populate_pxeboot_address_records(conn, pxeboot_subnet, mtu):
    pool_name = 'pxeboot'
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute('select id from address_pools where name=%s;',
                    (pool_name,))
        pool_row = cur.fetchone()
        if pool_row:
            LOG.info("existing pxeboot pool found, skip adding pxeboot "
                     "network. pool id = (%s)" % pool_row['id'])
            return

        cur.execute('insert into address_pools(uuid,name,family,network,'
                    'prefix,"order") VALUES(%s, %s, %s, %s, %s, %s)',
                    (str(uuid.uuid4()), pool_name, pxeboot_subnet.version,
                     str(pxeboot_subnet.network), pxeboot_subnet.prefixlen,
                     'random'))
        cur.execute("select id from address_pools WHERE name=%s;",
                    (pool_name,))
        pool_row = cur.fetchone()
        if pool_row is None:
            LOG.exception("Failed to fetch pool id for %s", pool_name)
            raise

        pool_id = pool_row['id']
        cur.execute('insert into address_pool_ranges(address_pool_id,uuid,'
                    'start,"end") VALUES(%s, %s, %s, %s)',
                    (pool_id, str(uuid.uuid4()),
                     str(pxeboot_subnet[1]),
                     str(pxeboot_subnet[-2])))
        cur.execute("insert into networks(id, address_pool_id, uuid,"
                    "type, mtu, dynamic) values(%s, %s, %s, %s, %s, False)",
                    (pool_id, pool_id, str(uuid.uuid4()),
                     constants.NETWORK_TYPE_PXEBOOT, mtu))
        addresses = {
            constants.CONTROLLER_HOSTNAME:
                str(pxeboot_subnet[2]),
            constants.CONTROLLER_0_HOSTNAME:
                str(pxeboot_subnet[3]),
            constants.CONTROLLER_1_HOSTNAME:
                str(pxeboot_subnet[4]),
        }
        for name, address in addresses.iteritems():
            address_name = "%s-%s" % (name, constants.NETWORK_TYPE_PXEBOOT)
            cur.execute("insert into addresses(uuid, address_pool_id, address,"
                        "prefix, name, family, enable_dad) values(%s, %s, %s,"
                        "%s, %s, %s, False)",
                        (str(uuid.uuid4()), pool_id, str(address),
                         pxeboot_subnet.prefixlen, address_name,
                         pxeboot_subnet.version))


if __name__ == "__main__":
    sys.exit(main())
