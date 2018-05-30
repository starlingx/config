# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import Integer
from sysinv.common import constants
from sysinv.common import utils as cutils
from sysinv.openstack.common import log
from sysinv.api.controllers.v1 import address_pool
from tsconfig.tsconfig import system_mode

LOG = log.getLogger(__name__)


def _populate_address_fields(address_pool_table, addresses_table, networks_table):
    prefix_to_field_name = {
        constants.CONTROLLER_HOSTNAME: address_pool.ADDRPOOL_FLOATING_ADDRESS_ID,
        constants.CONTROLLER_0_HOSTNAME: address_pool.ADDRPOOL_CONTROLLER0_ADDRESS_ID,
        constants.CONTROLLER_1_HOSTNAME: address_pool.ADDRPOOL_CONTROLLER1_ADDRESS_ID,
        constants.CONTROLLER_GATEWAY: address_pool.ADDRPOOL_GATEWAY_ADDRESS_ID,
    }
    networks = list(networks_table.select().execute())
    if len(networks) > 0:
        for net in networks:
            fields = {}
            for prefix, field_name in prefix_to_field_name.iteritems():
                address_name = cutils.format_address_name(prefix,
                                                          net.type)
                addr = list(addresses_table.select().
                            where(addresses_table.c.name == address_name).
                            execute())
                if len(addr) > 0:
                    fields.update({field_name: addr[0].id})
            if fields:
                address_pool_table.update().where(
                    address_pool_table.c.id == net.address_pool_id).values(
                    fields).execute()


def _update_addresses(addresses_table, interface_table, host_table):
    interfaces = list(interface_table.select().where(
        (interface_table.c.networktype == constants.NETWORK_TYPE_OAM) |
        (interface_table.c.networktype == constants.NETWORK_TYPE_PXEBOOT)).
                      execute())
    simplex = (system_mode == constants.SYSTEM_MODE_SIMPLEX)

    for interface in interfaces:
        host = list(host_table.select().
                    where(host_table.c.id == interface.forihostid).
                    execute())

        if not simplex:
            hostname = host[0].hostname
        else:
            hostname = constants.CONTROLLER

        address_name = cutils.format_address_name(hostname,
                                                  interface.networktype)
        address = list(addresses_table.select().
                       where(addresses_table.c.name == address_name).
                       execute())
        if len(address) > 0:
            addresses_table.update().where(
                addresses_table.c.id == address[0].id).values(
                {'interface_id': interface.id}).execute()


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Create new columns
    address_pool = Table('address_pools', meta, autoload=True)
    address_pool.create_column(Column('controller0_address_id', Integer))
    address_pool.create_column(Column('controller1_address_id', Integer))
    address_pool.create_column(Column('floating_address_id', Integer))
    address_pool.create_column(Column('gateway_address_id', Integer))

    # The following is for R4 to R5 upgrade.
    # Populate the new columns
    addresses_table = Table('addresses', meta, autoload=True)
    networks_table = Table('networks', meta, autoload=True)
    _populate_address_fields(address_pool, addresses_table, networks_table)
    # Update controller oam and pxeboot addresses with their interface id
    interface_table = Table('interfaces', meta, autoload=True)
    host_table = Table('i_host', meta, autoload=True)
    _update_addresses(addresses_table, interface_table, host_table)


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
