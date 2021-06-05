#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

import netaddr

from sysinv.common import constants
from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils

ADDRESS_FORMAT_ARGS = (constants.CONTROLLER_HOSTNAME,
                       constants.NETWORK_TYPE_OAM)


class OAMNetwork(base.SysinvObject):
    """OAM network object wrapper to address pool and addresses."""

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,
            'forisystemid': utils.int_or_none,
            'isystem_uuid': utils.str_or_none,

            'oam_subnet': utils.str_or_none,
            'oam_start_ip': utils.str_or_none,
            'oam_end_ip': utils.str_or_none,

            'oam_c0_ip': utils.str_or_none,
            'oam_c1_ip': utils.str_or_none,
            'oam_gateway_ip': utils.str_or_none,
            'oam_floating_ip': utils.str_or_none,
             }

    # NOTE: names must match those assigned by config_controller
    address_names = {
        'oam_c0_ip': "%s-0-%s" % ADDRESS_FORMAT_ARGS,
        'oam_c1_ip': "%s-1-%s" % ADDRESS_FORMAT_ARGS,
        'oam_floating_ip': "%s-%s" % ADDRESS_FORMAT_ARGS,
        'oam_gateway_ip': "%s-gateway-%s" % ADDRESS_FORMAT_ARGS,
    }

    @staticmethod
    def _from_db_object(obj, network):
        """Converts a database 'network' entity to a formal iextoam object."""

        # force iteration of a list of networks (refer to object.objectify)
        if type(network) == list:
            raise TypeError

        system = OAMNetwork.dbapi.isystem_get_one()

        address_pool = network.address_pool
        address_range = address_pool.ranges[0]
        addresses = OAMNetwork._get_pool_addresses(address_pool)

        subnet = address_pool.network + '/' + str(address_pool.prefix)

        # update system and pool fields
        obj.update({
            'forisystemid': system.id,
            'isystem_uuid': system.uuid,
            'oam_subnet': subnet,
            'oam_start_ip': address_range.start,
            'oam_end_ip': address_range.end,
        })

        # update standard DB fields (i.e. id, uuid)
        for field in obj.fields:
            if hasattr(network, field):
                obj[field] = network[field]

        # update address specific fields
        for field, name in obj.address_names.items():
            address = addresses.get(name)
            obj[field] = address.address if address else None

        obj.obj_reset_changes()
        return obj

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        db_object = cls.dbapi._network_get(uuid)
        return cls.from_db_object(db_object)

    @base.remotable
    def save(self, context):
        """Save updates to this object.

        :param context: Security context
        """
        network = self.dbapi._network_get(self.uuid)  # pylint: disable=no-member
        address_pool = network.address_pool
        addresses = OAMNetwork._get_pool_addresses(address_pool)

        subnet = netaddr.IPNetwork(self['oam_subnet'])

        # update address pool
        values = {
            'family': subnet.version,
            'network': str(subnet.network),
            'prefix': subnet.prefixlen,
            'ranges': [(self['oam_start_ip'], self['oam_end_ip'])],
        }
        self.dbapi.address_pool_update(address_pool.uuid, values)

        # update address entries
        for field, name in self.address_names.items():
            address = addresses.get(name)
            if address:
                values = {'address': self[field],
                          'family': subnet.version,
                          'prefix': subnet.prefixlen}
                self.dbapi.address_update(address.uuid, values)

        self.obj_reset_changes()

    @base.remotable
    def migrate_to_duplex(self, context):
        """Add controller unit IPs for OAM configuration when transitioning to
           a duplex system.

        :param context: Security context
        """
        network = self.dbapi._network_get(self.uuid)  # pylint: disable=no-member
        address_pool = network.address_pool
        addresses = OAMNetwork._get_pool_addresses(address_pool)

        subnet = netaddr.IPNetwork(self['oam_subnet'])

        # Add address entry
        values = {
                'address_pool_id': address_pool.id,
                'family': subnet.version,
                'prefix': subnet.prefixlen,
                'enable_dad': False
        }
        address_pool_values = {}

        if self['oam_c0_ip']:
            if self.address_names['oam_c0_ip'] in addresses:
                self.dbapi.address_update(addresses.get(self.address_names['oam_c0_ip']).uuid,
                                          {'address': self['oam_c0_ip']})
            else:
                # Only update the floating address entry if the controller-0
                # unit IP is being added for the first time
                for name, address in addresses.items():
                    if (address.interface_id and
                            name == self.address_names['oam_floating_ip']):

                        # Clear the interface id for the floating oam address
                        self.dbapi.address_update(address.uuid, {'interface_id': None})

                        # Address values specific to controller-0
                        c0_values = {
                            'name': self.address_names['oam_c0_ip'],
                            'address': self['oam_c0_ip'],
                            'interface_id': address.interface_id
                        }
                        c0_values.update(values)
                        c0_address = self.dbapi.address_create(c0_values)
                        address_pool_values.update({'controller0_address_id': c0_address.id})
                        break

        if self['oam_c1_ip']:
            if self.address_names['oam_c1_ip'] in addresses:
                self.dbapi.address_update(addresses.get(self.address_names['oam_c1_ip']).uuid,
                                          {'address': self['oam_c1_ip']})
            else:
                # Address values specific to controller-1
                c1_values = {
                    'name': self.address_names['oam_c1_ip'],
                    'address': self['oam_c1_ip'],
                }
                c1_values.update(values)
                c1_address = self.dbapi.address_create(c1_values)
                address_pool_values.update({'controller1_address_id': c1_address.id})

        # Update address pool if new address entries for controllers were added
        if address_pool_values:
            self.dbapi.address_pool_update(address_pool.uuid, address_pool_values)

    @staticmethod
    def _get_pool_addresses(pool):
        """Return a dictionary of addresses for the supplied pool keyed by name
        """
        # NOTE: do not use the addresses relation to retrieve addresses since
        # the relationship is lazy loaded and hydration may result in an
        # invalid session access on the pool entity.
        addresses = OAMNetwork.dbapi.addresses_get_by_pool(pool.id)
        return {a['name']: a for a in addresses}
