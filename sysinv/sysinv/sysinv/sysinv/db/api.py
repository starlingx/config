# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- encoding: utf-8 -*-
#
#
# Copyright 2013 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Copyright (c) 2013-2021 Wind River Systems, Inc.
#


"""
Base classes for storage engines
"""

import abc
import six

from oslo_config import cfg
from oslo_db import api as db_api
from oslo_log import log

LOG = log.getLogger(__name__)

_BACKEND_MAPPING = {'sqlalchemy': 'sysinv.db.sqlalchemy.api'}
IMPL = db_api.DBAPI.from_config(cfg.CONF,
                                backend_mapping=_BACKEND_MAPPING,
                                lazy=True)


def get_instance():
    """Return a DB API instance."""
    return IMPL


@six.add_metaclass(abc.ABCMeta)
class Connection(object):
    """Base class for storage system connections."""

    @abc.abstractmethod
    def __init__(self):
        """Constructor."""

    # @abc.abstractmethod
    # def get_session(self, autocommit):
    #     """Create a new database session instance."""

    @abc.abstractmethod
    def isystem_create(self, values):
        """Create a new isystem.

        :param values: A dict containing several items used to identify
                       and track the node, and several dicts which are passed
                       into the Drivers when managing this node. For example:

                        {
                         'uuid': uuidutils.generate_uuid(),
                         'name': 'system-0',
                         'capabilities': { ... },
                        }
        :returns: A isystem.
        """

    @abc.abstractmethod
    def isystem_get(self, isystem):
        """Return a isystem.

        :param isystem: The id or uuid of a isystem.
        :returns: A isystem.
        """

    @abc.abstractmethod
    def isystem_get_one(self):
        """Return exactly one isystem.

        :returns: A isystem.
        """

    @abc.abstractmethod
    def isystem_get_list(self, limit=None, marker=None,
                         sort_key=None, sort_dir=None):
        """Return a list of isystems.

        :param limit: Maximum number of isystems to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def isystem_update(self, isystem, values):
        """Update properties of a isystem.

        :param node: The id or uuid of a isystem.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for a driver. For example:

                       {
                        'driver_info':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: A isystem.
        """

    @abc.abstractmethod
    def isystem_destroy(self, isystem):
        """Destroy a isystem and all associated leaves.

        :param isystem: The id or uuid of a isystem.
        """

    @abc.abstractmethod
    def ihost_create(self, values, software_load=None):
        """Create a new ihost.

        :param values: A dict containing several items used to identify
                       and track the node, and several dicts which are passed
                       into the Drivers when managing this node. For example:

                        {
                         'uuid': uuidutils.generate_uuid(),
                         'invprovision': 'provisioned',
                         'mgmt_mac': '01:34:67:9A:CD:FE',
                         'mgmt_ip': '192.168.24.11',
                         'provision_state': states.NOSTATE,
                         'administrative': 'locked',
                         'operational': 'disabled',
                         'availability': 'offduty',
                         'extra': { ... },
                        }
        :param: software_load.  The load software_version.
        :returns: A ihost.
        """

    @abc.abstractmethod
    def ihost_get(self, server, session=None):
        """Return a server.

        :param server: The id or uuid of a server.
        :param session: The db session.
        :returns: A server.
        """

    @abc.abstractmethod
    def ihost_get_list(self, limit=None, marker=None,
                       sort_key=None, sort_dir=None, recordtype=None):
        """Return a list of iHosts.

        :param limit: Maximum number of iHosts to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :param recordtype: recordtype to filter, default="standard"
        """

    @abc.abstractmethod
    def ihost_get_by_hostname(self, hostname):
        """Return a server by hostname.
            :param hostname: The hostname of the server
            returns: A server
        """

    @abc.abstractmethod
    def ihost_get_by_personality(self, personality,
                                 limit=None, marker=None,
                                 sort_key=None, sort_dir=None):
        """Return a list of servers by personality.
            :param personality: The personality of the server
            e.g. controller or worker
            returns: A server
        """

    @abc.abstractmethod
    def count_hosts_matching_criteria(
            self, personality=None, administrative=None,
            operational=None, availability=None, vim_progress_status=None):
        """Return the number of hosts matching provided criteria

        :param personality: Host personality to match.
            Can be a string like "controller" or a
            list of strings like ["controller", "worker"]
        :param administrative: Host administrative state
            to match. Can be a string like "locked" or a list.
        :param operational: Host operational state to match.
            Can be a string like "disabled" or a list.
        :param availability: Host availability to match.
            Can be a string like "available" or a
            list of strings like ["available", "online"]
        :param vim_progress_status: VIM status to match.
            Can be a string like "services-enabled" or a list.
        returns: The number of hosts matching criteria
        """

    @abc.abstractmethod
    def ihost_update(self, server, values):
        """Update properties of a server.

        :param node: The id or uuid of a server.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for a driver. For example:

                       {
                        'driver_info':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: A server.
        """

    @abc.abstractmethod
    def ihost_destroy(self, server):
        """Destroy a server and all associated leaves.

        :param server: The id or uuid of a server.
        """

    @abc.abstractmethod
    def inode_create(self, forihostid, values):
        """Create a new inode for a host.

        :param forihostid: uuid or id of an ihost
        :param values: A dict containing several items used to identify
                       and track the inode, and several dicts which
                       are passed when managing this inode.
                       For example:
                        {
                         'uuid': uuidutils.generate_uuid(),
                         'numa_node': '0',
                         'forihostid': 'uuid-1',
                         'capabilities': { ... },
                        }
        :returns: An inode.
        """

    @abc.abstractmethod
    def inode_get(self, inode_id):
        """Return an inode.

        :param inode_id: The id or uuid of an inode.
        :returns: An inode.
        """

    @abc.abstractmethod
    def inode_get_all(self, forihostid=None):
        """Return inodes.

        :param forihostid: The id or uuid of an ihost.
        :returns:  inode.
        """

    @abc.abstractmethod
    def inode_get_list(self, limit=None, marker=None,
                      sort_key=None, sort_dir=None):
        """Return a list of cpus.

        :param limit: Maximum number of cpus to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def inode_get_by_ihost(self, ihost, limit=None,
                                        marker=None, sort_key=None,
                                        sort_dir=None):
        """List all the cpus for a given ihost.

        :param ihost: The id or uuid of an ihost.
        :param limit: Maximum number of cpus to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of cpus.
        """

    @abc.abstractmethod
    def inode_update(self, inode_id, values):
        """Update properties of a cpu.

        :param inode_id: The id or uuid of an inode.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for capabilities. For example:

                       {
                        'capabilities':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An inode.
        """

    @abc.abstractmethod
    def inode_destroy(self, inode_id):
        """Destroy an inode leaf.

        :param inode_id: The id or uuid of an inode.
        """

    @abc.abstractmethod
    def icpu_create(self, forihostid, values):
        """Create a new icpu for a server.

        :param forihostid: cpu belongs to this host
        :param values: A dict containing several items used to identify
                       and track the cpu.
                        {
                         'cpu': '1',
                         'core': '0',
                         'thread': '0',
                         'capabilities': { ... },
                        }
        :returns: A cpu.
        """

    @abc.abstractmethod
    def icpu_get(self, cpu_id, forihostid=None):
        """Return a cpu.

        :param cpu: The id or uuid of a cpu.
        :returns: A cpu.
        """

    @abc.abstractmethod
    def icpu_get_list(self, limit=None, marker=None,
                      sort_key=None, sort_dir=None):
        """Return a list of cpus.

        :param limit: Maximum number of cpus to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def icpu_get_by_ihost(self, ihost, limit=None,
                          marker=None, sort_key=None,
                          sort_dir=None):
        """List all the cpus for a given ihost.

        :param node: The id or uuid of an ihost.
        :param limit: Maximum number of cpus to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of cpus.
        """

    @abc.abstractmethod
    def icpu_get_by_inode(self, inode, limit=None,
                          marker=None, sort_key=None,
                          sort_dir=None):
        """List all the cpus for a given inode.

        :param node: The id or uuid of an inode.
        :param limit: Maximum number of cpus to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of cpus.
        """

    @abc.abstractmethod
    def icpu_get_by_ihost_inode(self, ihost, inode,
                                limit=None, marker=None,
                                sort_key=None, sort_dir=None):
        """List all the cpus for a given ihost and or interface.

        :param ihost: The id or uuid of an ihost.
        :param inode: The id or uuid of an inode.
        :param limit: Maximum number of cpus to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of cpus.
        """

    @abc.abstractmethod
    def icpu_get_all(self, forihostid=None, forinodeid=None):
        """Return cpus belonging to host and or node.

        :param forihostid: The id or uuid of an ihost.
        :param forinodeid: The id or uuid of an inode.
        :returns:  cpus.
        """

    @abc.abstractmethod
    def icpu_update(self, cpu_id, values, forihostid=None):
        """Update properties of a cpu.

        :param node: The id or uuid of a cpu.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for a driver. For example:

                       {
                        'driver_info':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: A cpu.
        """

    @abc.abstractmethod
    def icpu_destroy(self, cpu_id):
        """Destroy a cpu and all associated leaves.

        :param cpu: The id or uuid of a cpu.
        """

    @abc.abstractmethod
    def imemory_create(self, forihostid, values):
        """Create a new imemory for a server.

        :param forihostid: memory belongs to this host
        :param values: A dict containing several items used to identify
                       and track the memory.
                        {
                         'memory': '1',
                         'core': '0',
                         'thread': '0',
                         'capabilities': { ... },
                        }
        :returns: A memory.
        """

    @abc.abstractmethod
    def imemory_get(self, memory_id, forihostid=None):
        """Return a memory.

        :param memory: The id or uuid of a memory.
        :returns: A memory.
        """

    @abc.abstractmethod
    def imemory_get_list(self, limit=None, marker=None,
                         sort_key=None, sort_dir=None):
        """Return a list of memorys.

        :param limit: Maximum number of memorys to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def imemory_get_by_ihost(self, ihost, limit=None,
                             marker=None, sort_key=None,
                             sort_dir=None):
        """List all the memorys for a given ihost.

        :param node: The id or uuid of an ihost.
        :param limit: Maximum number of memorys to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of memorys.
        """

    @abc.abstractmethod
    def imemory_get_by_inode(self, inode,
                             limit=None, marker=None,
                             sort_key=None, sort_dir=None):
        """List all the memorys for a given inode.

        :param node: The id or uuid of an inode.
        :param limit: Maximum number of memorys to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of memorys.
        """

    @abc.abstractmethod
    def imemory_get_by_ihost_inode(self, ihost, inode,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        """List all the memorys for a given ihost and or interface.

        :param ihost: The id or uuid of an ihost.
        :param inode: The id or uuid of an inode.
        :param limit: Maximum number of memorys to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of memorys.
        """

    @abc.abstractmethod
    def imemory_get_all(self, forihostid=None, forinodeid=None):
        """Return memorys belonging to host and or node.

        :param forihostid: The id or uuid of an ihost.
        :param forinodeid: The id or uuid of an inode.
        :returns:  memorys.
        """

    @abc.abstractmethod
    def imemory_update(self, memory_id, values, forihostid=None):
        """Update properties of a memory.

        :param node: The id or uuid of a memory.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for a driver. For example:

                       {
                        'driver_info':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: A memory.
        """

    @abc.abstractmethod
    def imemory_destroy(self, memory_id):
        """Destroy a memory and all associated leaves.

        :param memory: The id or uuid of a memory.
        """

    @abc.abstractmethod
    def port_get(self, portid, hostid=None):
        """Return a port

        :param portid: The name, id or uuid of a port.
        :param hostid: The id or uuid of a host.
        :returns: A port
        """

    @abc.abstractmethod
    def port_get_list(self, limit=None, marker=None,
                      sort_key=None, sort_dir=None):
        """Return a list of ports.

        :param limit: Maximum number of ports to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: Direction in which results should be sorted.
                         (asc, desc)
        :returns:  List of ports
        """

    @abc.abstractmethod
    def port_get_all(self, hostid=None, interfaceid=None):
        """Return ports associated with host and or interface.

        :param hostid: The id of a host.
        :param interfaceid: The id of an interface.
        :returns:  List of ports
        """

    @abc.abstractmethod
    def port_get_by_host(self, host,
                         limit=None, marker=None,
                         sort_key=None, sort_dir=None):
        """List all the ports for a given host.

        :param host: The id or uuid of an host.
        :param limit: Maximum number of ports to return.
        :param marker: The last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: Direction in which results should be sorted
                         (asc, desc)
        :returns: A list of ports.
        """

    @abc.abstractmethod
    def port_get_by_interface(self, interface,
                              limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        """List all the ports for a given interface.

        :param interface: The id or uuid of an interface.
        :param limit: Maximum number of ports to return.
        :param marker: The last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: Direction in which results should be sorted
                         (asc, desc)
        :returns: A list of ports.
        """

    @abc.abstractmethod
    def port_get_by_numa_node(self, node,
                              limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        """List all the ports for a given numa node.

        :param node: The id or uuid of a numa node.
        :param limit: Maximum number of ports to return.
        :param marker: The last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: Direction in which results should be sorted
                         (asc, desc)
        :returns: A list of ports.
        """

    @abc.abstractmethod
    def ethernet_port_create(self, hostid, values):
        """Create a new ethernet port for a server.

        :param hostid: The id, uuid or database object of the host to which
                       the ethernet port belongs.
        :param values: A dict containing several items used to identify
                       and track the node, and several dicts which are passed
                       into the Drivers when managing this node. For example:
                        {
                         'uuid': uuidutils.generate_uuid(),
                         'invprovision': 'provisioned',
                         'mgmt_mac': '01:34:67:9A:CD:FE',
                         'provision_state': states.NOSTATE,
                         'administrative': 'locked',
                         'operational': 'disabled',
                         'availability': 'offduty',
                         'extra': { ... },
                        }
        :returns: An ethernet port
        """

    @abc.abstractmethod
    def ethernet_port_get(self, portid, hostid=None):
        """Return an ethernet port

        :param portid: The name, id or uuid of a ethernet port.
        :param hostid: The id or uuid of a host.
        :returns: An ethernet port
        """

    @abc.abstractmethod
    def ethernet_port_get_by_mac(self, mac):
        """Retrieve an Ethernet port for a given mac address.

        :param mac: The Ethernet MAC address
        :returns: An ethernet port
        """

    @abc.abstractmethod
    def ethernet_port_get_list(self, limit=None, marker=None,
                               sort_key=None, sort_dir=None):
        """Return a list of ethernet ports.

        :param limit: Maximum number of ports to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: Direction in which results should be sorted.
                         (asc, desc)
        :returns:  List of ethernet ports
        """

    @abc.abstractmethod
    def ethernet_port_get_all(self, hostid=None, interfaceid=None):
        """Return ports associated with host and or interface.

        :param hostid: The id of a host.
        :param interfaceid: The id of an interface.
        :returns:  List of ethernet ports
        """

    @abc.abstractmethod
    def ethernet_port_get_by_host(self, host,
                                  limit=None, marker=None,
                                  sort_key=None, sort_dir=None):
        """List all the ethernet ports for a given host.

        :param host: The id or uuid of an host.
        :param limit: Maximum number of ports to return.
        :param marker: The last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: Direction in which results should be sorted
                         (asc, desc)
        :returns: A list of ethernet ports.
        """

    @abc.abstractmethod
    def ethernet_port_get_by_interface(self, interface,
                                       limit=None, marker=None,
                                       sort_key=None, sort_dir=None):
        """List all the ethernet ports for a given interface.

        :param interface: The id or uuid of an interface.
        :param limit: Maximum number of ports to return.
        :param marker: The last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: Direction in which results should be sorted
                         (asc, desc)
        :returns: A list of ethernet ports.
        """

    @abc.abstractmethod
    def ethernet_port_get_by_numa_node(self, node,
                                       limit=None, marker=None,
                                       sort_key=None, sort_dir=None):
        """List all the ethernet ports for a given numa node.

        :param node: The id or uuid of a numa node.
        :param limit: Maximum number of ports to return.
        :param marker: The last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: Direction in which results should be sorted
                         (asc, desc)
        :returns: A list of ethernet ports.
        """

    @abc.abstractmethod
    def ethernet_port_update(self, portid, values):
        """Update properties of an ethernet port.

        :param portid: The id or uuid of an ethernet port.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for a driver. For example:

                       {
                        'driver_info':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An ethernet port
        """

    @abc.abstractmethod
    def ethernet_port_destroy(self, port_d):
        """Destroy an ethernet port

        :param portid: The id or uuid of an ethernet port.
        """

    @abc.abstractmethod
    def iinterface_create(self, forihostid, values):
        """Create a new iinterface for a host.

        :param values: A dict containing several items used to identify
                       and track the iinterface, and several dicts which
                       are passed when managing this iinterface.
                       For example:
                        {
                         'uuid': uuidutils.generate_uuid(),
                         'ifname': 'bond1',
                         'aemode': 'balanced',
                         'schedpolicy': 'xor',
                         'txhashpolicy': 'L2',
                         'extra': { ... },
                        }
        :returns: An iinterface.
        """

    @abc.abstractmethod
    def iinterface_get(self, iinterface_id, ihost=None, network=None):
        """Return an iinterface.

        :param iinterface_id: The id or uuid of an iinterface.
        :param ihost: The id or uuid of an ihost.
        :param network: The network type ('mgmt', 'cluster-host', 'oam')
        :returns: An iinterface.
        """

    @abc.abstractmethod
    def iinterface_get_all(self, forihostid=None):
        """Return an iinterfaces.

        :param forihostid: The id or uuid of a host.
        :returns:  iinterface.
        """
    @abc.abstractmethod
    def iinterface_get_list(self, limit=None, marker=None,
                      sort_key=None, sort_dir=None):
        """Return a list of ports.

        :param limit: Maximum number of ports to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def iinterface_get_by_ihost(self, ihost, limit=None,
                                marker=None, sort_key=None,
                                sort_dir=None):
        """List all the ports for a given ihost.

        :param ihost: The id or uuid of an ihost.
        :param limit: Maximum number of ports to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of ports.
        """

    @abc.abstractmethod
    def iinterface_update(self, iinterface_id, values):
        """Update properties of a cpu.

        :param node: The id or uuid of a cpu.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for a driver. For example:

                       {
                        'driver_info':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An iinterface.
        """

    @abc.abstractmethod
    def iinterface_destroy(self, iinterface_id):
        """Destroy an iinterface leaf.

        :param cpu: The id or uuid of an iinterface.
        """

    @abc.abstractmethod
    def ethernet_interface_create(self, forihostid, values):
        """Create a new Ethernet interface for a host.

        :param values: A dict containing several items used to identify
                       and track the interface, and several dicts which
                       are passed when managing this interface.
                       For example:
                        {
                         'uuid': uuidutils.generate_uuid(),
                         'ifname': 'eth1',
                         'extra': { ... },
                        }
        :returns: An EthernetInterface.
        """

    @abc.abstractmethod
    def ethernet_interface_get(self, interface_id):
        """Return an EthernetInterface.

        :param interface_id: The id or uuid of an interface.
        :returns: An EthernetInterface.
        """

    @abc.abstractmethod
    def ethernet_interface_get_all(self, forihostid=None):
        """Return an Interface.

        :param forihostid: The id or uuid of an ihost.
        :returns:  An EthernetInterface.
        """
    @abc.abstractmethod
    def ethernet_interface_get_list(self, limit=None, marker=None,
                           sort_key=None, sort_dir=None):
        """Return a list of EthernetInterfaces.

        :param limit: Maximum number of interfaces to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns: A list of EthernetInterfaces.
        """

    @abc.abstractmethod
    def ethernet_interface_get_by_ihost(self, ihost, limit=None,
                               marker=None, sort_key=None,
                               sort_dir=None):
        """List all the Ethernet interfaces for a given ihost.

        :param ihost: The id or uuid of an ihost.
        :param limit: Maximum number of interfacess to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of EthernetInterfaces.
        """

    @abc.abstractmethod
    def ethernet_interface_update(self, interface_id, values):
        """Update properties of an Ethernet interface.

        :param interface_id: The id or uuid of an interface.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for a driver. For example:

                       {
                        'driver_info':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An EthernetInterface.
        """

    @abc.abstractmethod
    def ethernet_interface_destroy(self, interface_id):
        """Destroy an Ethernet interface leaf.

        :param interface_id: The id or uuid of an interface.
        """

    @abc.abstractmethod
    def idisk_create(self, forihostid, values):
        """Create a new idisk for a server.

        :param forihostid: disk belongs to this host
        :param values: A dict containing several items used to identify
                       and track the disk.
                        {
                         'device_node': '/dev/sdb',
                         'device_num': '0',
                         'device_type': 'disk',
                         'size_mib': '10240',
                         'serial_id': 'disk',
                         'forihostid': '1',
                         'forinodeid': '2',
                         'capabilities': { ... },
                        }
        :returns: A disk.
        """

    @abc.abstractmethod
    def idisk_get(self, disk_id, forihostid=None):
        """Return a disk.

        :param disk: The id or uuid of a disk.
        :returns: A disk.
        """

    @abc.abstractmethod
    def idisk_get_list(self, limit=None, marker=None,
                       sort_key=None, sort_dir=None):
        """Return a list of disks.

        :param limit: Maximum number of disks to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def idisk_get_by_ihost(self, ihost, limit=None,
                           marker=None, sort_key=None,
                           sort_dir=None):
        """List all the disks for a given ihost.

        :param node: The id or uuid of an ihost.
        :param limit: Maximum number of disks to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of disks.
        """

    @abc.abstractmethod
    def idisk_get_by_istor(self, istor_uuid,
                           limit=None, marker=None,
                           sort_key=None, sort_dir=None):
        """List all the disks for a given istor.

        :param node: The id or uuid of an istor.
        :param limit: Maximum number of disks to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of disks.
        """

    @abc.abstractmethod
    def idisk_get_by_ihost_istor(self, ihost, istor,
                                 limit=None, marker=None,
                                 sort_key=None, sort_dir=None):
        """List all the disks for a given ihost and stor.

        :param ihost: The id or uuid of an ihost.
        :param istor: The id or uuid of an istor.
        :param limit: Maximum number of disks to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of disks.
        """

    @abc.abstractmethod
    def idisk_get_by_ipv(self, ipv,
                         limit=None, marker=None,
                         sort_key=None, sort_dir=None):
        """List all the disks for a given ipv.

        :param node: The id or uuid of an ipv.
        :param limit: Maximum number of disks to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of disks.
        """

    @abc.abstractmethod
    def idisk_get_by_device_id(self, device_id,
                               limit=None, marker=None,
                               sort_key=None, sort_dir=None):
        """List disk for a given id.

        :param device_id: The id of a device, as shown in /dev/disk/by-id.
        :param limit: Maximum number of disks to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of disks.
        """

    @abc.abstractmethod
    def idisk_get_by_device_path(self, device_path,
                                 limit=None, marker=None,
                                 sort_key=None, sort_dir=None):
        """List disk for a given path.

        :param device_path: The path of a device, as shown in
                            /dev/disk/by-path.
        :param limit: Maximum number of disks to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of disks.
        """

    @abc.abstractmethod
    def idisk_get_by_device_wwn(self, device_wwn,
                                limit=None, marker=None,
                                sort_key=None, sort_dir=None):
        """List disk for a given wwn.

        :param device_wwn: The WWN of a device, as shown in
                           /dev/disk/by-id/wwn*
        :param limit: Maximum number of disks to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of disks.
        """

    @abc.abstractmethod
    def idisk_get_by_ihost_ipv(self, ihost, ipv,
                               limit=None, marker=None,
                               sort_key=None, sort_dir=None):
        """List all the disks for a given ihost and ipv.

        :param ihost: The id or uuid of an ihost.
        :param ipv: The id or uuid of an ipv.
        :param limit: Maximum number of disks to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of disks.
        """

    @abc.abstractmethod
    def idisk_get_all(self, forihostid=None, foristorid=None, foripvid=None):
        """Return disks belonging to host and or node.

        :param forihostid: The id or uuid of an ihost.
        :param foristorid: The id or uuid of an istor.
        :param foripvid: The id or uuid of an ipv.
        :returns:  disks.
        """

    @abc.abstractmethod
    def idisk_update(self, disk_id, values, forihostid=None):
        """Update properties of a disk.

        :param node: The id or uuid of a disk.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for capabilities. For example:

                       {
                        'capabilities':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: A disk.
        """

    @abc.abstractmethod
    def idisk_destroy(self, disk_id):
        """Destroy a disk and all associated leaves.

        :param disk: The id or uuid of a disk.
        """

    @abc.abstractmethod
    def partition_get_all(self, forihostid=None, foripvid=None):
        """Return partitions belonging to host and or node.

        :param forihostid: The id or uuid of an ihost.
        :param foripvid: The id or uuid of an ipv.
        :returns:  partitions.
        """

    @abc.abstractmethod
    def partition_get(self, partition_id, forihostid=None):
        """Return a partition.

        :param partition_id: The id or uuid of a partition.
        :returns: A partition.
        """

    @abc.abstractmethod
    def partition_get_by_ihost(self, ihost, limit=None,
                           marker=None, sort_key=None,
                           sort_dir=None):
        """List all the partitions for a given ihost.

        :param node: The id or uuid of an ihost.
        :param limit: Maximum number of partitions to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of partitions.
        """

    @abc.abstractmethod
    def partition_get_by_idisk(self, idisk, limit=None,
                               marker=None, sort_key=None,
                               sort_dir=None):
        """List all the partitions for a given disk.

        :param node: The id or uuid of an idisk.
        :param limit: Maximum number of partitions to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of partitions.
        """

    @abc.abstractmethod
    def partition_get_by_ipv(self, ipv,
                             limit=None, marker=None,
                             sort_key=None, sort_dir=None):
        """List all the partitions for a given ipv.

        :param node: The id or uuid of an ipv.
        :param limit: Maximum number of partitions to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of partitions.
        """

    @abc.abstractmethod
    def partition_create(self, forihostid, values):
        """Create a new partition for a server.

        :param forihostid: partition belongs to this host
        :param values: A dict containing several items used to identify
                       and track the partition.
                        {

                        }
        :returns: A partition.
        """

    @abc.abstractmethod
    def partition_update(self, partition_id, values, forihostid=None):
        """Update properties of a partition.

        :param node: The id or uuid of a partition.
        :param values: Dict of values to update.
                       May be a partial list.
        :returns: A partition.
        """

    @abc.abstractmethod
    def partition_destroy(self, partition_id):
        """Destroy a partition.

        :param partition: The id or uuid of a partition.
        """

    @abc.abstractmethod
    def istor_create(self, forihostid, values):
        """Create a new istor for a host.

        :param forihostid: uuid or id of an ihost
        :param values: A dict containing several items used to identify
                       and track the istor, and several dicts which
                       are passed when managing this istor.
                       For example:
                        {
                         'uuid': uuidutils.generate_uuid(),
                         'name': 'uuid-1',  # or int
                         'state': 'available',
                         'function': 'objectstord',
                         'capabilities': { ... },
                         'forihostid': 'uuid-1',
                        }
        :returns: An istor.
        """

    @abc.abstractmethod
    def istor_get(self, istor_id):
        """Return an istor.

        :param istor_id: The id or uuid of an istor.
        :returns: An istor.
        """

    @abc.abstractmethod
    def istor_get_all(self, forihostid=None):
        """Return istors.

        :param forihostid: The id or uuid of an ihost.
        :returns:  istor.
        """

    @abc.abstractmethod
    def istor_get_list(self, limit=None, marker=None,
                       sort_key=None, sort_dir=None):
        """Return a list of istors.

        :param limit: Maximum number of istors to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def istor_get_by_ihost(self, ihost, limit=None,
                           marker=None, sort_key=None,
                           sort_dir=None):
        """List all the istors for a given ihost.

        :param ihost: The id or uuid of an ihost.
        :param limit: Maximum number of istors to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of istors.
        """

    @abc.abstractmethod
    def istor_get_by_tier(self, tier, limit=None,
                          marker=None, sort_key=None,
                          sort_dir=None):
        """List all the istors for a given storage tier.

        :param tier: The id or uuid of a storage tier .
        :param limit: Maximum number of istors to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of istors.
        """

    @abc.abstractmethod
    def istor_update(self, istor_id, values):
        """Update properties of an istor.

        :param istor_id: The id or uuid of an istor.
        :param values: Dict of values to update.
        :returns: An istor.
        """

    @abc.abstractmethod
    def istor_destroy(self, istor_id):
        """Destroy an istor leaf.

        :param istor_id: The id or uuid of an istor.
        """

    @abc.abstractmethod
    def journal_create(self, foristorid, values):
        """Create a new journal for stor

        :param foristorid: uuid or id of an istor
        :param values: A dict containing several items used to identify
                       and track the journal, and several dicts which
                       are passed when managing this journal.
                       For example:
                        {
                         'uuid': uuidutils.generate_uuid(),
                         'device_node': '/dev/sd**',
                         'size_mib': int,
                         'onistor_uuid': uuid of an idisk,
                        }
        :returns: A journal.
        """

    @abc.abstractmethod
    def ilvg_create(self, forihostid, values):
        """Create a new ilvg for a host.

        :param forihostid: uuid or id of an ihost
        :param values: A dict containing several items used to identify
                       and track the ilvg, and several dicts which
                       are passed when managing this ilvg.
                       For example:
                        {
                         'uuid': uuidutils.generate_uuid(),
                         'lvm_vg_name': constants.LVG_NOVA_LOCAL,
                         'lvm_vg_uuid': 'uuid-1',
                         'capabilities': { ... },
                         'forihostid': 'uuid-1',
                        }
        :returns: An ilvg.
        """

    @abc.abstractmethod
    def ilvg_get(self, ilvg_id):
        """Return an ilvg.

        :param ilvg_id: The id or uuid of an ilvg.
        :returns: An ilvg.
        """

    @abc.abstractmethod
    def ilvg_get_all(self, forihostid=None):
        """Return ilvgs.

        :param forihostid: The id or uuid of an ihost.
        :returns:  ilvg.
        """

    @abc.abstractmethod
    def ilvg_get_list(self, limit=None, marker=None,
                       sort_key=None, sort_dir=None):
        """Return a list of cpus.

        :param limit: Maximum number of ilvgs to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def ilvg_get_by_ihost(self, ihost, limit=None,
                           marker=None, sort_key=None,
                           sort_dir=None):
        """List all the pvs for a given ihost.

        :param ihost: The id or uuid of an ihost.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of ilvgs.
        """

    @abc.abstractmethod
    def ilvg_update(self, ilvg_id, values):
        """Update properties of an ilvg.

        :param ilvg_id: The id or uuid of an ilvg.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for capabilities. For example:

                       {
                        'capabilities':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An ilvg.
        """

    @abc.abstractmethod
    def ilvg_destroy(self, ilvg_id):
        """Destroy an ilvg leaf.

        :param ilvg_id: The id or uuid of an ilvg.
        """

    @abc.abstractmethod
    def ipv_create(self, forihostid, values):
        """Create a new ipv for a host.

        :param forihostid: uuid or id of an ihost
        :param values: A dict containing several items used to identify
                       and track the ipv, and several dicts which
                       are passed when managing this ipv.
                       For example:
                        {
                         'uuid': uuidutils.generate_uuid(),
                         'pv_type': 'disk',
                         'disk_or_part_uuid': 'uuid-1',
                         'disk_or_part_device_node': '/dev/sdb',
                         'disk_or_part_device_path': 'pci-0000:00:0d.0-ata-1.0',
                         'capabilities': { ... },
                         'forihostid': 'uuid-1',
                        }
        :returns: An ipv.
        """

    @abc.abstractmethod
    def ipv_get(self, ipv_id):
        """Return an ipv.

        :param ipv_id: The id or uuid of an ipv.
        :returns: An ipv.
        """

    @abc.abstractmethod
    def ipv_get_all(self, forihostid=None):
        """Return ipvs.

        :param forihostid: The id or uuid of an ihost.
        :returns:  ipv.
        """

    @abc.abstractmethod
    def ipv_get_list(self, limit=None, marker=None,
                       sort_key=None, sort_dir=None):
        """Return a list of pvs.

        :param limit: Maximum number of ipvs to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def ipv_get_by_ihost(self, ihost, limit=None,
                           marker=None, sort_key=None,
                           sort_dir=None):
        """List all the pvs for a given ihost.

        :param ihost: The id or uuid of an ihost.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of ipvs.
        """

    @abc.abstractmethod
    def ipv_update(self, ipv_id, values):
        """Update properties of an ipv.

        :param ipv_id: The id or uuid of an ipv.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for capabilities. For example:

                       {
                        'capabilities':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An ipv.
        """

    @abc.abstractmethod
    def ipv_destroy(self, ipv_id):
        """Destroy an ipv leaf.

        :param ipv_id: The id or uuid of an ipv.
        """

    @abc.abstractmethod
    def iuser_create(self, values):
        """Create a new iuser for an isystem

        :param forihostid: iuser belongs to this isystem
        :param values: A dict containing several items used to identify
                       and track the iuser.
                        {
                         'root_sig': 'abracadabra',
                        }
        :returns: An iuser.
        """

    @abc.abstractmethod
    def iuser_get(self, server):
        """Return an iuser.

        :param isystem: The id or uuid of an iuser.
        :returns: An iuser.
        """

    @abc.abstractmethod
    def iuser_get_one(self):
        """Return exactly one iuser.

        :returns: A iuser.
        """

    @abc.abstractmethod
    def iuser_get_list(self, limit=None, marker=None,
                       sort_key=None, sort_dir=None):
        """Return a list of iuser.

        :param limit: Maximum number of iuser to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def iuser_get_by_isystem(self, isystem_id, limit=None, marker=None,
                             sort_key=None, sort_dir=None):
        """List all the iuser for a given isystem.

        :param isystem: The id or uuid of an isystem.
        :param limit: Maximum number of iuser to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of iuser.
        """

    @abc.abstractmethod
    def iuser_update(self, server, values):
        """Update properties of an iuser.

        :param iuser: The id or uuid of an iuser.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for capabilities. For example:

                       {
                        'capabilities':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An iconfig.
        """

    @abc.abstractmethod
    def iuser_destroy(self, server):
        """Destroy an iuser.

        :param id: The id or uuid of an iuser.
        """

    @abc.abstractmethod
    def idns_create(self, values):
        """Create a new idns for an isystem.

        :param forisystemid: idns belongs to this isystem
        :param values: A dict containing several items used to identify
                       and track the idns.
                        {
                         'nameservers': '8.8.8.8,8.8.4.4',
                         'forisystemid': '1'
                        }
        :returns: A idns.
        """

    @abc.abstractmethod
    def idns_get(self, server):
        """Return an idns.

        :param isystem: The id or uuid of a idns.
        :returns: An idns.
        """

    @abc.abstractmethod
    def idns_get_one(self):
        """Return exactly one idns.

        :returns: A idns.
        """

    @abc.abstractmethod
    def idns_get_list(self, limit=None, marker=None,
                      sort_key=None, sort_dir=None):
        """Return a list of idns.

        :param limit: Maximum number of idns to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def idns_get_by_isystem(self, isystem_id, limit=None, marker=None,
                            sort_key=None, sort_dir=None):
        """List all the idns for a given isystem.

        :param isystem: The id or uuid of an isystem.
        :param limit: Maximum number of idns to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of idns.
        """

    @abc.abstractmethod
    def idns_update(self, server, values):
        """Update properties of an idns.

        :param idns: The id or uuid of an idns.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for capabilities. For example:

                       {
                        'capabilities':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An idns.
        """

    @abc.abstractmethod
    def idns_destroy(self, server):
        """Destroy an idns.

        :param id: The id or uuid of an idns.
        """

    @abc.abstractmethod
    def intp_create(self, values):
        """Create a new intp for an isystem.

        :param values: A dict containing several items used to identify
                       and track the ntp settings.
                        {
                         'enabled': 'True'
                         'ntpservers': '0.pool.ntp.org,
                                        1.pool.ntp.org,
                                        2.pool.ntp.org',
                         'forisystemid': '1'
                        }
        :returns: An intp.
        """

    @abc.abstractmethod
    def intp_get(self, intp_id):
        """Return an intp.

        :param intp_id: The id or uuid of an intp.
        :returns: An intp.
        """

    @abc.abstractmethod
    def intp_get_one(self):
        """Return exactly one intp.

        :returns: An intp.
        """

    @abc.abstractmethod
    def intp_get_list(self, limit=None, marker=None,
                      sort_key=None, sort_dir=None):
        """Return a list of intp.

        :param limit: Maximum number of intp to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def intp_get_by_isystem(self, isystem_id, limit=None, marker=None,
                            sort_key=None, sort_dir=None):
        """List all the intp for a given isystem.

        :param isystem_id: The id or uuid of an isystem.
        :param limit: Maximum number of intp to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of intp.
        """

    @abc.abstractmethod
    def intp_update(self, intp_id, values):
        """Update properties of an intp.

        :param intp_id: The id or uuid of an intp.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for capabilities. For example:

                       {
                        'capabilities':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An intp.
        """

    @abc.abstractmethod
    def intp_destroy(self, intp_id):
        """Destroy an intp.

        :param intp_id: The id or uuid of an intp.
        """

    @abc.abstractmethod
    def ptp_create(self, values):
        """Create a new ptp for an isystem.

        :param values: A dict containing several items used to identify
                       and track the ptp settings.
                        {
                         'enabled': 'True',
                         'mode': 'hardware',
                         'transport': 'l2',
                         'mechanism': 'e2e',
                        }
        :returns: A ptp.
        """

    @abc.abstractmethod
    def ptp_get(self, ptp_id):
        """Return a ptp.

        :param ptp_id: The id or uuid of a ptp.
        :returns: A ptp.
        """

    @abc.abstractmethod
    def ptp_get_one(self):
        """Return exactly one ptp.

        :returns: A ptp.
        """

    @abc.abstractmethod
    def ptp_get_list(self, limit=None, marker=None,
                     sort_key=None, sort_dir=None):
        """Return a list of ptp.

        :param limit: Maximum number of ptp to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def ptp_get_by_isystem(self, isystem_id, limit=None, marker=None,
                           sort_key=None, sort_dir=None):
        """List all the ptp for a given isystem.

        :param isystem_id: The id or uuid of an isystem.
        :param limit: Maximum number of ptp to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of ptp.
        """

    @abc.abstractmethod
    def ptp_update(self, ptp_id, values):
        """Update properties of a ptp.

        :param ptp_id: The id or uuid of a ptp.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for capabilities. For example:

                       {
                        'capabilities':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: A ptp.
        """

    @abc.abstractmethod
    def ptp_destroy(self, ptp_id):
        """Destroy a ptp.

        :param ptp_id: The id or uuid of a ptp.
        """

    @abc.abstractmethod
    def ptp_fill_empty_system_id(self, system_id):
        """fills all empty system_id in a ptp.
         ptp did not always fill this entry in properly
         so existing systems might still have no value in the
         system_id field. This function fills in the system_id
         in existing systems that were missing this value.

        :param system_id: The value to fill system_id with
        """

    @abc.abstractmethod
    def ptp_instance_create(self, values):
        """Creates a new PTP service instance for an ihost.

        :param values: A dict containing several items used to identify
                       and track the PTP instance settings.
                        {
                         'name': 'default',
                         'service': 'ptp4l',
                         'capabilities': { ... }
                        }
        :returns: A PTP service instance.
        """

    @abc.abstractmethod
    def ptp_instance_get(self, ptp_instance_id):
        """Returns a PTP service instance.

        :param ptp_instance_id: The id or uuid of a PTP instance.
        :returns: A PTP service instance.
        """

    @abc.abstractmethod
    def ptp_instance_get_by_name(self, name):
        """Returns a PTP service instance given its name.

        :param name: The name of a PTP instance.
        :returns: A PTP service instance.
        """

    @abc.abstractmethod
    def ptp_instances_get_list(self, host=None, limit=None, marker=None,
                               sort_key=None, sort_dir=None):
        """Returns a list of PTP service instances.

        :param host: id or uuid of host.
        :param limit: Maximum number of PTP instances to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns: A list of PTP instances.
        """

    @abc.abstractmethod
    def ptp_instance_assign(self, values):
        """Set the PTP instance to some host.

        :param values: A dict containing the IDs used to associate
                       the PTP instance to the host.
                    {
                     'host_id': 1,
                     'ptp_instance_id': 3
                    }
        :returns: A PTP instance mapping.
        """

    @abc.abstractmethod
    def ptp_instance_remove(self, values):
        """Remove the association between a PTP instance and a host.

        :param values: A dict containing the IDs used to associate
                       the PTP instance to the host.
                    {
                     'host_id': 1,
                     'ptp_instance_id': 3
                    }
        """

    @abc.abstractmethod
    def ptp_instance_get_assignees(self, ptp_instance_id, limit=None,
                                   marker=None, sort_key=None, sort_dir=None):
        """Returns a list of all hosts associated to the PTP instance.

        :param ptp_instance_id: The id or uuid of a PTP instance.
        :param limit: Maximum number of hosts to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of hosts for the given PTP instance.
        """

    @abc.abstractmethod
    def ptp_instance_parameter_add(self, ptp_instance, ptp_parameter):
        """Add reference/association to PTP parameter.

        :param ptp_instance: The UUID of a PTP instance.
        :param ptp_parameter: The UUID of PTP parameter to be added.
        """

    @abc.abstractmethod
    def ptp_instance_parameter_remove(self, ptp_instance, ptp_parameter):
        """Remove reference/association to PTP parameter.

        :param ptp_instance: The UUID of a PTP instance.
        :param ptp_parameter: The UUID of PTP parameter to be removed.
        """

    @abc.abstractmethod
    def ptp_instance_destroy(self, ptp_instance_id):
        """Destroys a PTP service instance.

        :param ptp_instance_id: The id or uuid of a PTP instance.
        """

    @abc.abstractmethod
    def ptp_instance_destroy_by_name(self, name):
        """Destroys a PTP service instance based on name.

        :param name: The name given for a PTP instance.
        """

    @abc.abstractmethod
    def ptp_instance_map_get(self, ptp_instance_map_id):
        """Returns a PTP instance mapping.

        :param ptp_instance_map_id: The id or uuid of a PTP instance map.
        :returns: A PTP instance map.
        """

    @abc.abstractmethod
    def ptp_interface_create(self, values):
        """Creates a new PTP association between an interface
           and a PTP instance.

        :param values: A dict containing several items used to identify
                       and track the PTP association to an interface.
                        {
                         'interface_id': 101,
                         'ptp_instance_id': 10,
                         'capabilities': { ... }
                        }
        :returns: A PTP interface association.
        """

    @abc.abstractmethod
    def ptp_interface_get(self, ptp_interface_id):
        """Returns a PTP interface association.

        :param ptp_interface_id: The id or uuid of a PTP interface.
        :returns: A PTP interface association.
        """

    @abc.abstractmethod
    def ptp_interfaces_get_list(self, host=None, interface=None,
                                ptp_instance=None, limit=None, marker=None,
                                sort_key=None, sort_dir=None):
        """Returns a list of PTP interface associations.

        :param host: id or uuid of host.
        :param interface: id or uuid of interface.
        :param ptp_instance: id or uuid of PTP instance.
        :param limit: Maximum number of PTP interfaces to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns: A list of PTP interface associations.
        """

    @abc.abstractmethod
    def ptp_interface_assign(self, values):
        """Set the PTP interface to some interface.

        :param values: A dict containing the IDs used to associate
                       the PTP interface to the interface.
                    {
                     'interface_id': 1,
                     'ptp_interface_id': 3
                    }
        :returns: A PTP interface mapping.
        """

    @abc.abstractmethod
    def ptp_interface_remove(self, values):
        """Remove the association between a PTP interface and a interface.

        :param values: A dict containing the IDs used to associate
                       the PTP interface to the interface.
                    {
                     'interface_id': 1,
                     'ptp_interface_id': 3
                    }
        """

    @abc.abstractmethod
    def ptp_interface_get_assignees(self, ptp_interface_id, limit=None,
                                    marker=None, sort_key=None, sort_dir=None):
        """Returns a list of all interfaces associated to the PTP interface.

        :param ptp_interface_id: The id or uuid of a PTP interface.
        :param limit: Maximum number of interfaces to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of interfaces for the given PTP interface.
        """

    @abc.abstractmethod
    def ptp_interface_parameter_add(self, ptp_interface, ptp_parameter):
        """Add reference/association to PTP parameter.

        :param ptp_interface: The UUID of a PTP interface.
        :param ptp_parameter: The UUID of PTP parameter to be added.
        """

    @abc.abstractmethod
    def ptp_interface_parameter_remove(self, ptp_interface, ptp_parameter):
        """Remove reference/association to PTP parameter.

        :param ptp_interface: The UUID of a PTP interface.
        :param ptp_parameter: The UUID of PTP parameter to be removed.
        """

    @abc.abstractmethod
    def ptp_interface_destroy(self, ptp_interface_id):
        """Destroys a PTP interface association.

        :param ptp_interface_id: The id or uuid of a PTP interface association.
        """

    @abc.abstractmethod
    def ptp_interface_destroy_by_name(self, name):
        """Destroys a PTP interface association based on name.

        :param name: The name given for a PTP interface.
        """

    @abc.abstractmethod
    def ptp_interface_map_get(self, ptp_interface_map_id):
        """Returns a PTP interface mapping.

        :param ptp_interface_map_id: The id or uuid of a PTP interface map.
        :returns: A PTP interface map.
        """

    @abc.abstractmethod
    def ptp_parameter_create(self, values):
        """Creates a new PTP parameter to be applied later either to some
           instance(s) or PTP interface(s).

        :param values: A dict containing several items used to identify
                       and track the PTP parameter.
                        {
                         'name': 'domain',
                         'value': '24'
                        }
        :returns: A PTP parameter.
        """

    @abc.abstractmethod
    def ptp_parameter_get(self, ptp_parameter_id):
        """Returns a PTP parameter.

        :param ptp_parameter_id: The id or uuid of a PTP parameter.
        :returns: A PTP parameter.
        """

    @abc.abstractmethod
    def ptp_parameter_get_by_namevalue(self, name, value):
        """Returns the PTP parameter entry that matches the pair name-value.

        :param name: Name of a PTP parameter.
        :param value: Value of a PTP parameter.
        :returns: A PTP parameter.
        """

    @abc.abstractmethod
    def ptp_parameters_get_list(self, ptp_instance=None, ptp_interface=None,
                                limit=None, marker=None, sort_key=None,
                                sort_dir=None):
        """Returns a list of PTP parameters.

        :param ptp_instance: UUID of PTP instance that uses the parameter.
        :param ptp_interface: UUID of PTP interface that uses the parameter.
        :param limit: Maximum number of PTP parameters to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns: A list of PTP parameters.
        """

    @abc.abstractmethod
    def ptp_parameter_get_owners(self, ptp_parameter_uuid, limit=None,
                                 marker=None, sort_key=None, sort_dir=None):
        """Returns a list of all PTP instances and PTP interfaces that use
           (point to) the PTP parameter.

        :param ptp_parameter_id: The uuid of a PTP parameter.
        :param limit: Maximum number of hosts to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of owners for the given PTP parameter.
        """

    @abc.abstractmethod
    def ptp_parameters_get_list_by_type(self, type, limit=None, marker=None,
                                        sort_key=None, sort_dir=None):
        """Returns a list of all PTP parameters of a given owner type.

        :param type: Type of the parameter owner (either 'ptp-instance' or
                     'ptp-interface')
        :param limit: Maximum number of PTP parameters to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of PTP parameters for a specific owner type.
        """

    @abc.abstractmethod
    def ptp_parameter_update(self, ptp_parameter_id, values):
        """Updates properties of a PTP parameter.

        :param ptp_parameter_id: The id or uuid of a PTP parameter.
        :param values: May be a partial dict containing the items to update
                        {
                         'value': '12' # new value for 'domain'
                        }
        :returns: A PTP parameter.
        """

    @abc.abstractmethod
    def ptp_parameter_destroy(self, ptp_parameter_id):
        """Destroys a PTP parameter.

        :param ptp_parameter_id: The id or uuid of a PTP parameter.
        """

    @abc.abstractmethod
    def ptp_paramowner_get(self, ptp_paramowner_id):
        """Returns a PTP parameter owner (can be either a PTP instance or a
           PTP interface).

        :param ptp_paramowner_id: The id or uuid of a PTP parameter owner.
        :returns: A PTP parameter owner.
        """

    @abc.abstractmethod
    def ptp_paramownership_get(self, ptp_paramownership_id):
        """Returns a PTP parameter ownership.

        :param ptp_paramownership_id: The id or uuid of a PTP parameter
                                      ownership.
        :returns: A PTP parameter ownership.
        """

    @abc.abstractmethod
    def iextoam_get_one(self):
        """Return exactly one iextoam.

        :returns: A iextoam.
        """

    @abc.abstractmethod
    def iextoam_get_list(self, limit=None, marker=None,
                         sort_key=None, sort_dir=None):
        """Return a list of iextoam.

        :param limit: Maximum number of iextoam to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def storage_tier_get(self, storage_tier_uuid):
        """Return an storage tier.

        :param storage_tier_uuid: The id or uuid of a storage tier.
        :returns: An storage tier.
        """

    @abc.abstractmethod
    def storage_tier_get_by_cluster(self, cluster_id, limit=None,
                                    marker=None, sort_key=None,
                                    sort_dir=None):
        """List all the storage tiers for a given cluster.

        :param cluster_id: The id or uuid of an cluster.
        :param limit: Maximum number of storage tiers to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of storage tiers.
        """

    @abc.abstractmethod
    def storage_tier_create(self, values):
        """Create a new storage_tier for a cluster

        :param values: A dict containing several items used to identify
                       and track the storage tier.
                        {
                         'uuid': uuidutils.generate_uuid(),
                         'type': 'ceph',
                         'forclusterid': 1,
                         'status': 'defined',
                         'name': 'gold'}
                        }
        :returns: A storage backend.
        """

    @abc.abstractmethod
    def storage_tier_update(self, storage_tier_uuid, values):
        """Update properties of an storage tier.

        :param storage_tier_uuid: The id or uuid of a storage tier.
        :param values: Dict of values to update. May be a partial list.
        :returns: A storage tier.
        """

    @abc.abstractmethod
    def storage_tier_get_list(self, limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        """Return a list of storage tiers.

        :param limit: Maximum number of storage tiers to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def storage_tier_get_all(self, uuid=None, name=None, type=None):
        """Return storage_tiers.

        :param uuid: The id or uuid of a storage tier.
        :param name: The name of a storage tier.
        :param type: The type of a storage tier.
        :returns:  storage tier.
        """

    @abc.abstractmethod
    def storage_tier_destroy(self, storage_tier_uuid):
        """Destroy a storage_tier.

        :param storage_tier_uuid: The id or uuid of a storage_tier.
        """

    @abc.abstractmethod
    def storage_backend_create(self, values):
        """Create a new storage_backend for an isystem

        :param values: A dict containing several items used to identify
                       and track the storage backend.
                        {
                         'backend': 'lvm',
                         'state': None,
                         'task': None,
                        }
        :returns: A storage backend.
        """

    @abc.abstractmethod
    def storage_backend_get(self, storage_backend_id):
        """Return an storage backend.

        :param storage_backend_id: The id or uuid of a storage backend.
        :returns: An storage backend.
        """

    @abc.abstractmethod
    def storage_backend_get_by_name(self, name):
        """Return an storage backend based on name.

        :param name: The name of a storage backend.
        :returns: An storage backend.
        """

    @abc.abstractmethod
    def storage_backend_get_list(self, limit=None, marker=None,
                                 sort_key=None, sort_dir=None):
        """Return a list of storage backends.

        :param limit: Maximum number of storage backends to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def storage_backend_get_list_by_state(self, backend_state, limit=None,
                                          marker=None, sort_key=None,
                                          sort_dir=None):
        """Return a list of storage backends by backend state.

        :param backend_state: Storage backend state
        :param limit: Maximum number of storage backends to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def storage_backend_get_list_by_type(self, backend_type=None, limit=None,
                                         marker=None, sort_key=None,
                                         sort_dir=None):
        """List all the storage backends by backend type.

        :param backend_type: One of SB_SUPPORTED types
        :param limit: Maximum number of storage backends to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of storage backend.
        """

    @abc.abstractmethod
    def storage_backend_update(self, storage_backend_id, values):
        """Update properties of an storage backend.

        :param storage_backend_id: The id or uuid of a storage backend.
        :param values: Dict of values to update. May be a partial list.
        :returns: A storage backend.
        """

    @abc.abstractmethod
    def storage_backend_destroy(self, storage_backend_id):
        """Destroy a storage_backend.

        :param storage_backend_id: The id or uuid of a storage_backend.
        """

    @abc.abstractmethod
    def controller_fs_create(self, values):
        """Create a new controller_fs for an isystem

        :param values: A dict containing several items used to identify
                       and track the controller_fs.
            Example:
            values = {'name': constants.FILESYSTEM_NAME_DOCKER,
                      'size': 30,
                      'logical_volume': constants.FILESYSTEM_LV_DICT[
                           constants.FILESYSTEM_NAME_DOCKER],
                      'replicated': False}
        :returns: A controller_fs.
        """

    @abc.abstractmethod
    def controller_fs_get(self, controller_fs_id):
        """Return an controller_fs.

        :param controller_fs_id: The id or uuid of a controller_fs.
        :returns: An controller_fs.
        """

    @abc.abstractmethod
    def controller_fs_get_list(self, limit=None, marker=None,
                                 sort_key=None, sort_dir=None):
        """Return a list of controller_fss.

        :param limit: Maximum number of controller_fss to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def controller_fs_get_by_isystem(self, isystem_id, limit=None,
                                      marker=None, sort_key=None,
                                      sort_dir=None):
        """List all the controller_fss for a given isystem.

        :param isystem: The id or uuid of an isystem.
        :param limit: Maximum number of controller_fss to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of controller_fs.
        """

    @abc.abstractmethod
    def controller_fs_update(self, controller_fs_id, values):
        """Update properties of an controller_fs.

        :param controller_fs_id: The id or uuid of a controller_fs.
        :param values: Dict of values to update. May be a partial list.
            Example:
            values = {'name': constants.DEFAULT_DOCKER_STOR_SIZE,
                      'size': 30,
                      'logical_volume': constants.FILESYSTEM_LV_DICT[
                           constants.DEFAULT_DOCKER_STOR_SIZE],
                      'replicated': False}
        :returns: A controller_fs.
        """

    @abc.abstractmethod
    def controller_fs_destroy(self, controller_fs_id):
        """Destroy a controller_fs.

        :param controller_fs_id: The id or uuid of a controller_fs.
        """

    @abc.abstractmethod
    def ceph_mon_create(self, values):
        """Create a new ceph monitor for a server.

        :param values: A dict containing several items used to identify
                       and track the disk.
                        {
                         'device_path':
                             '/dev/disk/by-path/pci-0000:00:0d.0-ata-3.0',
                         'ceph_mon_gib': 20,
                         'forihostid': '1',

                        }
        :returns: A ceph monitor.
        """

    @abc.abstractmethod
    def ceph_mon_get(self, ceph_mon_id):
        """Return a ceph mon.

        :param ceph_mon_id: The id or uuid of a ceph mon.
        :returns: A ceph mon.
        """

    @abc.abstractmethod
    def ceph_mon_get_list(self, limit=None, marker=None,
                             sort_key=None, sort_dir=None):
        """Return a list of ceph_mon.

        :param limit: Maximum number of ceph_mons to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def ceph_mon_get_by_ihost(self, ihost_id_or_uuid, limit=None,
                              marker=None, sort_key=None,
                              sort_dir=None):
        """List all the ceph mons for a given host.

        :param ihost_id_or_uuid: The id or uuid of an ihost.
        :param limit: Maximum number of ceph mons to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A ceph mon list.
        """

    @abc.abstractmethod
    def ceph_mon_update(self, ceph_mon_id, values):
        """Update properties of a ceph_mon.

        :param ceph_mon_id: The id or uuid of a ceph_mon.
        :param values: Dict of values to update. May be a partial list.
        :returns: A ceph_mon.
        """

    @abc.abstractmethod
    def ceph_mon_destroy(self, ceph_mon_id):
        """Destroy a ceph_mon.

        :param ceph_mon_id: The id or uuid of a ceph_mon.
        """

    @abc.abstractmethod
    def storage_external_create(self, values):
        """Create a new storage_external

        :param values: A dict containing several items used to identify
                       and track the storage_external.
        :returns: An storage_external.
        """

    @abc.abstractmethod
    def storage_external_get(self, storage_external_id):
        """Return an storage_external.

        :param storage_external_id: The id or uuid of an storage_external.
        :returns: An storage_external.
        """

    @abc.abstractmethod
    def storage_external_get_list(self, limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        """Return a list of storage_external.

        :param limit: Maximum number of storage_external to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def storage_external_update(self, server, values):
        """Update properties of an storage_external.

        :param storage_external: The id or uuid of an storage_external.
        :param values: Dict of values to update. May be a partial list.
        :returns: An storage_external.
        """

    @abc.abstractmethod
    def storage_file_create(self, values):
        """Create a new storage_file

        :param values: A dict containing several items used to identify
                       and track the storage_file.
        :returns: An storage_file.
        """

    @abc.abstractmethod
    def storage_file_get(self, storage_file_id):
        """Return a storage_file.

        :param storage_file_id: The id or uuid of an storage_file.
        :returns: A storage_file.
        """

    @abc.abstractmethod
    def storage_file_get_list(self, limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        """Return a list of storage_file.

        :param limit: Maximum number of storage_file to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def storage_file_update(self, server, values):
        """Update properties of a storage_file.

        :param storage_file: The id or uuid of an storage_file.
        :param values: Dict of values to update. May be a partial list.
        :returns: A storage_file.
        """

    @abc.abstractmethod
    def storage_lvm_create(self, values):
        """Create a new storage_lvm

        :param values: A dict containing several items used to identify
                       and track the storage_lvm.
        :returns: An storage_lvm.
        """

    @abc.abstractmethod
    def storage_lvm_get(self, storage_lvm_id):
        """Return an storage_lvm.

        :param storage_lvm_id: The id or uuid of an storage_lvm.
        :returns: An storage_lvm.
        """

    @abc.abstractmethod
    def storage_lvm_get_list(self, limit=None, marker=None,
                             sort_key=None, sort_dir=None):
        """Return a list of storage_lvm.

        :param limit: Maximum number of storage_lvm to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def storage_lvm_update(self, server, values):
        """Update properties of an storage_lvm.

        :param storage_lvm: The id or uuid of an storage_lvm.
        :param values: Dict of values to update. May be a partial list.
        :returns: An storage_lvm.
        """

    @abc.abstractmethod
    def storage_ceph_create(self, values):
        """Create a new storage_ceph

        :param forihostid: storage_ceph belongs to this isystem
        :param values: A dict containing several items used to identify
                       and track the storage_ceph.
        :returns: An storage_ceph.
        """

    @abc.abstractmethod
    def storage_ceph_get(self, storage_ceph_id):
        """Return an storage_ceph.

        :param storage_ceph_id: The id or uuid of an storage_ceph.
        :returns: An storage_ceph.
        """

    @abc.abstractmethod
    def storage_ceph_get_list(self, limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        """Return a list of ceph storage backends.

        :param limit: Maximum number of ceph storage backends to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def storage_ceph_update(self, stor_ceph_id, values):
        """Update properties of an ceph storage backend.

        :param stor_ceph_id: The id or uuid of a ceph storage backend.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for capabilities. For example:

                       {
                        'cinder_pool_gib': 10,
                        'glance_pool_gib':10,
                        'ephemeral_pool_gib: 10,
                        'object_pool_gib': 0,
                        'object_gateway': False
                       }
        :returns: An ceph storage backend.
        """

    @abc.abstractmethod
    def storage_ceph_external_create(self, values):
        """Create a new external ceph storage backend.

        :param forihostid: the external ceph belongs to this isystem
        :param values: A dict containing several items used to identify
                       and track the external_ceph.
        :returns: An external storage_ceph.
        """

    @abc.abstractmethod
    def storage_ceph_external_get(self, storage_ceph_id):
        """Return an external ceph storage.

        :param storage_ceph_id: The id or uuid of the external_ceph storage.
        :returns: An external storage_ceph.
        """

    @abc.abstractmethod
    def storage_ceph_external_get_list(self, limit=None, marker=None,
                                      sort_key=None, sort_dir=None):
        """Return a list of external ceph storage backends.

        :param limit: Maximum number of external ceph storage backends to
                      return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def storage_ceph_external_update(self, stor_ceph_ext_id, values):
        """Update properties of an external ceph storage backend.

        :param stor_ceph_ext_id: The id or uuid of a ceph storage backend.
        :param values: Dict of values to update.
                       {
                        'ceph_conf': '3p_ceph1.conf'
                       }
        :returns: An external ceph storage backend.
        """

    @abc.abstractmethod
    def storage_ceph_rook_create(self, values):
        """Create a new storage_ceph_rook

        :param values: A dict containing several items used to identify
                       and track the storage_ceph_rook.
        :returns: An storage_ceph_rook.
        """

    @abc.abstractmethod
    def storage_ceph_rook_get(self, storage_ceph_rook_id):
        """Return a storage_ceph_rook.

        :param storage_ceph_rook_id: The id or uuid of an storage_ceph_rook.
        :returns: A storage_ceph_rook.
        """

    @abc.abstractmethod
    def storage_ceph_rook_get_list(self, limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        """Return a list of storage_ceph_rook.

        :param limit: Maximum number of storage_ceph_rook to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def storage_ceph_rook_update(self, stor_ceph_rook_id, values):
        """Update properties of a storage_ceph_rook.

        :param storage_ceph_rook: The id or uuid of an storage_ceph_rook.
        :param values: Dict of values to update. May be a partial list.
        :returns: A storage_ceph_rook.
        """

    @abc.abstractmethod
    def drbdconfig_create(self, values):
        """Create a new drbdconfig for an isystem

        :param forihostid: drbdconfig belongs to this isystem
        :param values: A dict containing several items used to identify
                       and track the drbdconfig.
                        {
                         'link_util': 40,
                         'num_parallel': 1,
                         'rtt_ms': 0.2,
                        }
        :returns: An drbdconfig.
        """

    @abc.abstractmethod
    def drbdconfig_get(self, server):
        """Return an drbdconfig.

        :param isystem: The id or uuid of an drbdconfig.
        :returns: An drbdconfig.
        """

    @abc.abstractmethod
    def drbdconfig_get_one(self):
        """Return exactly one drbdconfig.

        :returns: A drbdconfig.
        """

    @abc.abstractmethod
    def drbdconfig_get_list(self, limit=None, marker=None,
                            sort_key=None, sort_dir=None):
        """Return a list of drbdconfig.

        :param limit: Maximum number of drbdconfig to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def drbdconfig_get_by_isystem(self, isystem_id, limit=None, marker=None,
                                  sort_key=None, sort_dir=None):
        """List all the drbdconfig for a given isystem.

        :param isystem: The id or uuid of an isystem.
        :param limit: Maximum number of drbdconfig to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of drbdconfig.
        """

    @abc.abstractmethod
    def drbdconfig_update(self, server, values):
        """Update properties of an drbdconfig.

        :param drbdconfig: The id or uuid of an drbdconfig.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for capabilities. For example:

                       {
                        'capabilities':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An drbdconfig.
        """

    @abc.abstractmethod
    def drbdconfig_destroy(self, server):
        """Destroy an drbdconfig.

        :param id: The id or uuid of an drbdconfig.
        """

    @abc.abstractmethod
    def remotelogging_create(self, values):
        """Create a new remotelogging for an isystem.

        :param forisystemid: remotelogging belongs to this isystem
        :param values: A dict containing several items used to identify
                       and track the remotelogging mechanism. For example:

                        {
                         'uuid': uuidutils.generate_uuid(),
                         'enabled': 'True',
                         'transport': 'udp',
                         'ip_address'   : '10.10.10.99',
                         'port'  : '514',
                         'key_file'  : 'machine-key.pem',
                        }
        :returns: A remotelogging.
        """

    @abc.abstractmethod
    def remotelogging_get(self, server):
        """Return an remotelogging.

        :param isystem: The id or uuid of an remotelogging.
        :returns: A remotelogging.
        """

    @abc.abstractmethod
    def remotelogging_get_one(self):
        """Return exactly one remotelogging.

        :returns: A remotelogging.
        """

    @abc.abstractmethod
    def remotelogging_get_list(self, limit=None, marker=None,
                      sort_key=None, sort_dir=None):
        """Return a list of remotelogging.

        :param limit: Maximum number of remotelogging to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def remotelogging_get_by_isystem(self, isystem_id, limit=None, marker=None,
                            sort_key=None, sort_dir=None):
        """List all the remotelogging for a given isystem.

        :param isystem: The id or uuid of an isystem.
        :param limit: Maximum number of remotelogging to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of remotelogging.
        """

    @abc.abstractmethod
    def remotelogging_update(self, server, values):
        """Update properties of an remotelogging.

        :param remotelogging_id: The id or uuid of an remotelogging.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for capabilities. For example:

                       {
                        'capabilities':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An remotelogging.
        """

    @abc.abstractmethod
    def remotelogging_destroy(self, server):
        """Destroy an remotelogging.

        :param id: The id or uuid of an remotelogging.
        """

    @abc.abstractmethod
    def remotelogging_fill_empty_system_id(self, system_id):
        """fills all empty system_id in a remotelogging.
         remotelogging did not always fill this entry in properly
         so existing systems might still have no value in the
         system_id field. This function fills in the system_id
         in existing systems that were missing this value.

        :param system_id: The value to fill system_id with
        """

    @abc.abstractmethod
    def service_create(self, values):
        """Create a new service

        :param values: A dict containing several items used to identify
                       and track the Services
                        {
                         'service': 'some_new_service',
                         'enabled': 'False',
                        }
        :returns: A Services.
        """

    @abc.abstractmethod
    def service_get(self, name):
        """Return a Services.

        :returns: A Services.
        """

    @abc.abstractmethod
    def service_get_one(self):
        """Return exactly one Services.

        :returns: A Services.
        """

    @abc.abstractmethod
    def service_get_list(self, limit=None, marker=None,
                      sort_key=None, sort_dir=None):
        """Return a list of service.

        :param limit: Maximum number of remotelogging to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def service_get_all(self):
        """Returns list of service.

        :returns:  List of service
        """

    @abc.abstractmethod
    def service_update(self, name, values):
        """Update properties of an service.

        :param name: The name of an service.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for capabilities. For example:

                       {
                        'capabilities':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An Services.
        """

    @abc.abstractmethod
    def service_destroy(self, service):
        """Destroy an service.

        :param name: The name of an service
        """

    # SENSORS
    @abc.abstractmethod
    def isensor_analog_create(self, hostid, values):
        """Create an isensor.
        :param hostid: id (PK) of the host.
        :param values: Dict of values to update.
        :returns:      an isensor
        """

    @abc.abstractmethod
    def isensor_analog_get(self, sensorid, hostid=None):
        """Return an analog isensor.
        :param sensorid: id (PK) of the sensor.
        :param hostid:   id (PK) of the host.
        :returns:        an analog isensor
        """

    @abc.abstractmethod
    def isensor_analog_get_list(self, limit=None, marker=None,
                                sort_key=None, sort_dir=None):
        """Return a list of analog isensors.

        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def isensor_analog_get_all(self, hostid=None, sensorgroupid=None):
        """Return list of analog isensors.
        :param hostid:   id (PK) of the host.
        :param sensorgroupid: id (PK) of the sensorgroup.
        :returns:        a list of analog isensors
        """

    @abc.abstractmethod
    def isensor_analog_get_by_host(self, host,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        """Return list of analog isensors for the host.
        :param host:   id (PK) of the host.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of analog isensors
        """

    @abc.abstractmethod
    def isensor_analog_get_by_isensorgroup(self, sensorgroup,
                                         limit=None, marker=None,
                                         sort_key=None, sort_dir=None):
        """Return list of analog isensors for the host.
        :param sensorgroup:   id (PK) of the sensorgroup.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of analog isensors
        """

    @abc.abstractmethod
    def isensor_analog_get_by_host_isensorgroup(self, host, sensorgroup,
                                              limit=None, marker=None,
                                              sort_key=None, sort_dir=None):
        """Return list of analog isensors for the host.
        :param host:   id (PK) of the host.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of analog isensors
        """

    @abc.abstractmethod
    def isensor_analog_update(self, sensorid, values, hostid=None):
        """Update properties of an isensor.

        :param sensorid: The id or uuid of a isensor.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for a driver. For example:

                       {
                        'capabilities':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An isensor.
        """

    @abc.abstractmethod
    def isensor_analog_destroy(self, sensorid):
        """Destroy an isensor.
        :param sensorid: id (PK) of the sensor.
        """

    @abc.abstractmethod
    def isensor_discrete_create(self, hostid, values):
        """Create an isensor.
        :param hostid: id (PK) of the host.
        :param values: Dict of values to update.
        :returns:      an isensor
        """

    @abc.abstractmethod
    def isensor_discrete_get(self, sensorid, hostid=None):
        """Return an isensor.

        :param sensorid: The id or uuid of a sensor.
        :returns: A sensor.
        """

    @abc.abstractmethod
    def isensor_discrete_get_list(self, limit=None, marker=None,
                                  sort_key=None, sort_dir=None):
        """Return list of discrete isensors.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of discrete isensors
        """

    @abc.abstractmethod
    def isensor_discrete_get_all(self, hostid=None, sensorgroupid=None):
        """Return list of analog isensors for the host.
        :param hostid:   id (PK) of the host.
        :param sensorgroupid:   id (PK) of the sensorgroupid.
        :returns:        a list of analog isensors
        """

    @abc.abstractmethod
    def isensor_discrete_get_by_host(self, host,
                                     limit=None, marker=None,
                                     sort_key=None, sort_dir=None):

        """Return list of analog isensors for the host.
        :param host:   id (PK) of the host.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of analog isensors
        """

    @abc.abstractmethod
    def isensor_discrete_get_by_isensorgroup(self, sensorgroup,
                                           limit=None, marker=None,
                                           sort_key=None, sort_dir=None):

        """Return list of analog isensors for the host.
        :param sensorgroup:   id (PK) of the sensorgroup.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of analog isensors
        """

    @abc.abstractmethod
    def isensor_discrete_get_by_host_isensorgroup(self, host, sensorgroup,
                                                limit=None, marker=None,
                                                sort_key=None, sort_dir=None):
        """Return list of analog isensors for the host.
        :param host:   id (PK) of the host.
        :param sensorgroup:   id (PK) of the sensorgroup.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of analog isensors
        """

    @abc.abstractmethod
    def isensor_discrete_update(self, sensorid, values, hostid=None):
        """Update properties of an isensor.

        :param sensorid: The id or uuid of a isensor.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for a driver. For example:

                       {
                        'capabilities':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An isensor.
        """

    @abc.abstractmethod
    def isensor_discrete_destroy(self, sensorid):
        """Destroy an isensor.
        :param sensorid: id (PK) of the sensor.
        """

    @abc.abstractmethod
    def isensor_create(self, hostid, values):
        """Create an isensor.
        :param hostid: id (PK) of the host.
        :param values: Dict of values to update.
        :returns:      an isensor
        """

    @abc.abstractmethod
    def isensor_get(self, sensorid, hostid=None):
        """Return a sensor.

        :param sensorid: The id or uuid of a sensor.
        :param hostid: The id of the host.
        :returns: A sensor.
        """

    @abc.abstractmethod
    def isensor_get_list(self, limit=None, marker=None,
                         sort_key=None, sort_dir=None):
        """Return list of isensors.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of isensors
        """

    @abc.abstractmethod
    def isensor_get_all(self, host_id=None, sensorgroupid=None):
        """Return list of isensors for the host and sensorgroup.
        :param host_id:   id (PK) of the host.
        :param sensorgroupid:   id (PK) of the sensorgroupid.
        :returns:        a list of isensors
        """

    @abc.abstractmethod
    def isensor_get_by_ihost(self, ihost,
                             limit=None, marker=None,
                             sort_key=None, sort_dir=None):
        """Return list of isensors for the host.
        :param ihost:   id (PK) of the host.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of isensors
        """

    @abc.abstractmethod
    def isensor_get_by_sensorgroup(self, sensorgroup,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        """Return list of isensors for the host.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of isensors
        """

    @abc.abstractmethod
    def isensor_get_by_ihost_sensorgroup(self, ihost, sensorgroup,
                                       limit=None, marker=None,
                                       sort_key=None, sort_dir=None):
        """Return list of isensors for the host.
        :param ihost:   id (PK) of the host.
        :param sensorgroup:   id (PK) of the sensorgroup.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of isensors
        """

    @abc.abstractmethod
    def isensor_update(self, isensor_id, values):
        """Update properties of an isensor.

        :param isensor_id: The id or uuid of a isensor.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for a driver. For example:

                       {
                        'capabilities':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An isensor.
        """

    @abc.abstractmethod
    def isensor_destroy(self, sensor_id):
        """Destroy an isensor.
        :param sensor_id: id (PK) of the sensor.
        """

    # SENSOR GROUPS
    @abc.abstractmethod
    def isensorgroup_create(self, ihost_id, values):
        """Create an isensor.
        :param ihost_id: id (PK) of the host.
        :param values: Dict of values to update.
        :returns:      an isensor
        """

    @abc.abstractmethod
    def isensorgroup_get(self, isensorgroup_id, host_id=None):
        """Return a sensor.

        :param isensorgroup_id: The id or uuid of a sensor.
        :param host_id: The id of the host.
        :returns: A sensor.
        """

    @abc.abstractmethod
    def isensorgroup_get_list(self, limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        """Return list of analog isensors for the host.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of analog isensors
        """

    @abc.abstractmethod
    def isensorgroup_get_by_ihost_sensor(self, ihost, sensor,
                                         limit=None, marker=None,
                                         sort_key=None, sort_dir=None):
        """Return list of analog isensors for the host.
        :param ihost:   id (PK) of the host.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of analog isensors
        """

    @abc.abstractmethod
    def isensorgroup_get_by_ihost(self, ihost,
                                limit=None, marker=None,
                                sort_key=None, sort_dir=None):
        """Return list of analog isensors for the host.
        :param ihost:   id (PK) of the host.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of analog isensors
        """

    @abc.abstractmethod
    def isensorgroup_update(self, isensorgroup_id, values):
        """Update properties of an isensorgroup.

        :param isensorgroup_id: The id or uuid of a isensor.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for a driver. For example:

                       {
                        'capabilities':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An isensorgroup.
        """

    @abc.abstractmethod
    def isensorgroup_propagate(self, sensorgroup_id, values):
        """Progagate properties from sensorgroup to sensors.
        :param isensorgroup_id: The id or uuid of the sensorgroup.
        :param values: Dict of values to update.
        """

    @abc.abstractmethod
    def isensorgroup_destroy(self, sensorgroup_id):
        """Destroy an isensor.
        :param sensorgroup_id: id (PK) of the sensor.
        """

    @abc.abstractmethod
    def isensorgroup_analog_create(self, ihost_id, values):
        """Create an isensor.
        :param ihost_id: id (PK) of the host.
        :param values: Dict of values to update.
        :returns:      an isensor
        """

    @abc.abstractmethod
    def isensorgroup_analog_get_all(self, ihost_id=None):
        """Return list of analog isensors for the host.
        :param ihost_id:   id (PK) of the host.
        :returns:        a list of analog isensors
        """

    @abc.abstractmethod
    def isensorgroup_analog_get(self, sensorgroup_id):
        """Return a sensorgroup.

        :param sensorgroup_id: The id or uuid of a sensorgroup.
        :returns: A sensorgroup.
        """

    @abc.abstractmethod
    def isensorgroup_analog_get_list(self, limit=None, marker=None,
                                     sort_key=None, sort_dir=None):
        """Return list of analog isensors.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of analog isensors
        """

    @abc.abstractmethod
    def isensorgroup_analog_get_by_ihost(self, ihost,
                                         limit=None, marker=None,
                                         sort_key=None, sort_dir=None):
        """Return list of analog isensors for the host.
        :param ihost:   id (PK) of the host.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of analog isensors
        """

    @abc.abstractmethod
    def isensorgroup_analog_update(self, sensorgroup_id, values):
        """Update properties of an isensorgroup.

        :param sensorgroup_id: The id or uuid of a isensor.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for a driver. For example:

                       {
                        'capabilities':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An isensor.
        """

    @abc.abstractmethod
    def isensorgroup_analog_destroy(self, sensorgroup_id):
        """Destroy an isensor.
        :param sensorgroup_id: id (PK) of the sensor.
        """

    @abc.abstractmethod
    def isensorgroup_discrete_create(self, ihost_id, values):
        """Create an isensor.
        :param ihost_id: id (PK) of the host.
        :param values: Dict of values to update.
        :returns:      an isensor
        """

    @abc.abstractmethod
    def isensorgroup_discrete_get_all(self, ihost_id=None):
        """Return list of discrete isensors for the host.
        :param ihost_id:   id (PK) of the host.
        :returns:        a list of discrete isensors
        """

    @abc.abstractmethod
    def isensorgroup_discrete_get(self, sensorgroup_id):
        """Return an isensorgroup.

        :param sensorgroup_id: The id or uuid of a isensorgroup.
        :returns: An isensorgroup.
        """

    @abc.abstractmethod
    def isensorgroup_discrete_get_list(self, limit=None, marker=None,
                                       sort_key=None, sort_dir=None):
        """Return list of discrete isensor groups for the host.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of isensorgoups
        """

    @abc.abstractmethod
    def isensorgroup_discrete_get_by_ihost(self, ihost,
                                           limit=None, marker=None,
                                           sort_key=None, sort_dir=None):
        """Return list of isensorgoups for the host.
        :param ihost:   id (PK) of the host.
        :param limit: Maximum number of isensors to return.
        :param marker: the last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        :returns:        a list of isensorgoups
        """

    @abc.abstractmethod
    def isensorgroup_discrete_update(self, sensorgroup_id, values):
        """Update properties of an isensor.

        :param sensorgroup_id: The id or uuid of a isensor.
        :param values: Dict of values to update.
                       May be a partial list, eg. when setting the
                       properties for a driver. For example:

                       {
                        'capabilities':
                            {
                             'my-field-1': val1,
                             'my-field-2': val2,
                            }
                       }
        :returns: An isensor.
        """

    @abc.abstractmethod
    def isensorgroup_discrete_destroy(self, sensorgroup_id):
        """Destroy an isensorgroup.
        :param sensorgroup_id: id (PK) of the sensorgroup.
        """

    @abc.abstractmethod
    def load_create(self, values):
        """Create a new Load.

        :param values: A dict containing several items used to identify
                       and track the load
                        {
                         'software_version': '16.10',
                         'compatible_version': '15.10',
                         'required_patches': '001,002,003',
                        }
        :returns: A load.
        """

    @abc.abstractmethod
    def load_get(self, load):
        """Returns a load.

        :param load: The id or uuid of a load.
        :returns: A load.
        """

    @abc.abstractmethod
    def load_get_by_version(self, version):
        """Returns the load with the specified version.

        :param version: The software version of a load.
        :returns: A load.
        """

    @abc.abstractmethod
    def load_get_list(self, limit=None, marker=None, sort_key=None,
                      sort_dir=None):
        """Return a list of loads.

        :param limit: Maximum number of loads to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def load_update(self, load, values):
        """Update properties of a load.

        :param load: The id or uuid of a load.
        :param values: Dict of values to update.
                       May be a partial list,
        :returns: A load.
        """

    @abc.abstractmethod
    def load_destroy(self, load):
        """Destroy a load.

        :param load: The id or uuid of a load.
        """

    @abc.abstractmethod
    def set_upgrade_loads_state(self, upgrade, to_state, from_state):
        """Change the states of the loads in an upgrade.

        :param upgrade: An upgrade object.
        :param to_state: The state of the 'to' load.
        :param from_state: The state of the 'from' load.
        """

    @abc.abstractmethod
    def fpga_device_create(self, hostid, values):
        """Create a new FPGA device for a host.

        :param hostid: The id, uuid or database object of the host to which
                       the device belongs.
        :param values: A dict containing several items used to identify
                       and track the device. For example:
                        {
                         'uuid': uuidutils.generate_uuid(),
                         'pciaddr': '0000:0b:01.0',
                         'pvendor_id': '8086',
                         'pdevice_id': '0b30',
                         ...etc...
                        }
        :returns: An FPGA device
        """

    @abc.abstractmethod
    def fpga_device_get(self, deviceid, hostid=None):
        """Return an FPGA device

        :param deviceid: The id or uuid of an FPGA device.
        :param hostid: The id or uuid of a host.
        :returns: An FPGA device
        """

    @abc.abstractmethod
    def fpga_device_update(self, deviceid, values, hostid=None):
        """Update properties of an FPGA device.

        :param deviceid: The id or uuid of an FPGA device.
        :param values: Dict of values to update.
                       For example:
                        {
                         'boot_page': 'user',
                         'bitstream_id': '0x23000410010309',
                        }
        :param hostid: The id or uuid of the host to which the FPGA
                       device belongs.
        :returns: An FPGA device
        """

    @abc.abstractmethod
    def pci_device_create(self, hostid, values):
        """Create a new pci device for a host.

        :param hostid: The id, uuid or database object of the host to which
                       the device belongs.
        :param values: A dict containing several items used to identify
                       and track the device. For example:
                        {
                         'uuid': uuidutils.generate_uuid(),
                         'name': 'pci_dev_1',
                         'pciaddr': '0000:0b:01.0',
                         'pclass_id': '060100',
                         'pvendor_id': '8086',
                         'pdevice_id': '0443',
                         'enabled': 'True',
                         'extra_info': { ... },
                        }
        :returns: A pci device
        """

    @abc.abstractmethod
    def pci_device_get(self, deviceid, hostid=None):
        """Return a pci device

        :param deviceid: The id or uuid of a pci device.
        :param hostid: The id or uuid of a host.
        :returns: A pci device
        """

    @abc.abstractmethod
    def pci_device_get_list(self, limit=None, marker=None,
                            sort_key=None, sort_dir=None):
        """Return a list of pci devices.

        :param limit: Maximum number of pci devices to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: Direction in which results should be sorted.
                         (asc, desc)
        :returns:  List of pci devices
        """

    @abc.abstractmethod
    def pci_device_get_all(self, hostid=None):
        """Return pci devices associated with host.

        :param hostid: The id of a host.
        :returns:  List of pci devices
        """

    @abc.abstractmethod
    def pci_device_get_by_host(self, host,
                               limit=None, marker=None,
                               sort_key=None, sort_dir=None):
        """List all the pci devices for a given host.

        :param host: The id or uuid of an host.
        :param limit: Maximum number of pci devices to return.
        :param marker: The last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: Direction in which results should be sorted
                         (asc, desc)
        :returns: A list of pci devices.
        """

    @abc.abstractmethod
    def pci_device_update(self, deviceid, values, hostid=None):
        """Update properties of a pci device.

        :param deviceid: The id or uuid of a pci device.
        :param values: Dict of values to update.
                       For example:
                        {
                         'name': 'pci_dev_2',
                         'enabled': 'True',
                        }
        :param hostid: The id or uuid of the host to which the pci
                       device belongs.
        :returns: A pci device
        """

    @abc.abstractmethod
    def pci_device_destroy(self, deviceid):
        """Destroy a pci_device

        :param deviceid: The id or uuid of a pci device.
        """

    @abc.abstractmethod
    def software_upgrade_create(self, values):
        """Create a new software_upgrade entry

        :param values: A dict containing several items used to identify
                       and track the entry, and several dicts which are passed
                       into the Drivers when managing this node. For example:

                        {
                         'uuid': uuidutils.generate_uuid(),
                         'state': 'start', 'migration_complete', 'activated',
                                  'complete',
                         'from_load': '15.10',
                         'to_load'  : '16.10',
                        }
        :returns: A software_uprade record.
        """

    @abc.abstractmethod
    def software_upgrade_get(self, id):
        """Return a software_upgrade entry for a given id

        :param _id: The id or uuid of a software_upgrade entry
        :returns: a software_upgrade entry
        """

    @abc.abstractmethod
    def software_upgrade_get_list(self, limit=None, marker=None,
                                  sort_key=None, sort_dir=None):
        """Return a list of software_upgrade entries.

        :param limit: Maximum number of software_upgrade entries to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def software_upgrade_get_one(self):
        """Return exactly one software_upgrade.

        :returns: A software_upgrade.
        """

    @abc.abstractmethod
    def software_upgrade_update(self, uuid, values):
        """Update properties of a software_upgrade.

        :param node: The uuid of a software_upgrade entry.
        :param values: Dict of values to update.
                       {
                         'state': 'complete',
                        }
        :returns: A software_upgrade entry.
        """

    @abc.abstractmethod
    def software_upgrade_destroy(self, id):
        """Destroy a software_upgrade entry.

        :param id: The id or uuid of a software_upgrade entry.
        """

    @abc.abstractmethod
    def host_upgrade_create(self, host_id, values):
        """Create host_upgrade entry.
        :param ihost_id: id of the host.
        :param values: Dict of values to update.
                       {
                         'software_load': 'load.id',
                        }
        :returns:      a host_upgrade
        """

    @abc.abstractmethod
    def host_upgrade_get(self, id):
        """Return a host_upgrade entry for a given host

        :param id: id or uuid of the host_upgrade entry.
        :returns: a host_upgrade
        """

    @abc.abstractmethod
    def host_upgrade_get_by_host(self, host_id):
        """Return a host_upgrade entry for a given host

        :param id: id of the host entry.
        :returns: a host_upgrade
        """

    @abc.abstractmethod
    def host_upgrade_get_list(self, limit=None, marker=None, sort_key=None,
                              sort_dir=None):
        """Return a list of host_upgrade entries.

        :param limit: Maximum number of host_upgrade to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def host_upgrade_update(self, host_id, values):
        """Update properties of a host_upgrade entry.

        :param host_id: The id of a host entry.
        :param values: Dict of values to update.
                       {
                        'software_load': 'load.id'
                       }
        :returns: A host_upgrade entry.
        """

    @abc.abstractmethod
    def service_parameter_create(self, values):
        """Create a new service_parameter entry

        :param values: A dict containing several items used to identify
                       and track the entry, and several dicts which are passed
                       into the Drivers when managing this node. For example:

                        {
                         'uuid': uuidutils.generate_uuid(),
                         'service': 'identity',
                         'section': 'ldap',
                         'name'   : 'parameter_name',
                         'value'  : 'parameter_value',
                         'personality' : 'personality',
                         'resource' : 'resource',
                        }
        :returns: A service parameter record.
        """

    @abc.abstractmethod
    def service_parameter_get(self, id):
        """Return a service_parameter entry for a given id

        :param id: The id or uuid of a service_parameter entry
        :returns: a service_parameter entry
        """

    @abc.abstractmethod
    def service_parameter_get_list(self, limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        """Return a list of service_parameter entries.

        :param limit: Maximum number of service_parameter entries to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def service_parameter_get_all(self, uuid=None, service=None,
                                  section=None, name=None, limit=None,
                                  sort_key=None, sort_dir=None):
        """Return service_parameter(s) entry(ies) matching some criteria.

        :param uuid: UUID to filter by.
        :param service: Service to filter by.
        :param section: Section to filter by.
        :param name: Name to filter by.
        :param limit: Maximum number of service_parameter entries to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def service_parameter_get_one(self, service=None, section=None, name=None,
                                  personality=None, resource=None):
        """Return a service parameter.

        :param service: name of service.
        :param section: name of section.
        :param name: name of parameter.
        :param personality: personality filter for custom parameter.
        :param resource: resource for custom parameter.
        :returns: A service parameter.
        """

    @abc.abstractmethod
    def service_parameter_update(self, uuid, values):
        """Update properties of a service_parameter.

        :param uuid: The uuid of a service_parameter entry.
        :param values: Dict of values to update.
                       {
                         'value': 'value',
                        }
        :returns: A service_parameter entry.
        """

    @abc.abstractmethod
    def service_parameter_destroy_uuid(self, id):
        """Destroy a service_parameter entry.

        :param id: The id or uuid of a service_parameter entry.
        """

    @abc.abstractmethod
    def service_parameter_destroy(self, name, service, section):
        """Destroy a service_parameter entry.

        :param name: The name of a service_parameter entry.
        :param name: The service of a service_parameter entry.
        :param name: The section of a service_parameter entry.
        """

    @abc.abstractmethod
    def clusters_get_all(self, uuid=None, name=None, type=None):
        """Return clusters associated with id, name, or type

        :param uuid: The id or uuid of a cluster.
        :param name: The name of a cluster
        :param type: The type of a cluster
        :returns:  List clusters
        """

    @abc.abstractmethod
    def lldp_agent_create(self, portid, hostid, values):
        """Create a new lldp agent for a server.

        :param portid: The id, uuid or database object of the port to which
                       the lldp agent belongs.
        :param hostid: The id, uuid or database object of the host to which
                       the lldp agent belongs.
        :param values: A dict containing several items used to identify
                       and track the node, and several dicts which are passed
                       into the Drivers when managing this node. For example:
                        {
                         'uuid': uuidutils.generate_uuid(),
                         'status': 'enabled',
                        }
        :returns: An lldp agent
        """

    @abc.abstractmethod
    def lldp_agent_get(self, agentid, hostid=None):
        """Return an lldp agent

        :param agentid: The id or uuid of an lldp agent.
        :param hostid: The id or uuid of a host.
        :returns: An lldp agent
        """

    @abc.abstractmethod
    def lldp_agent_get_list(self, limit=None, marker=None,
                            sort_key=None, sort_dir=None):
        """Return a list of lldp agents.

        :param limit: Maximum number of lldp agents to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: Direction in which results should be sorted.
                         (asc, desc)
        :returns:  List of lldp agents
        """

    @abc.abstractmethod
    def lldp_agent_get_all(self, hostid=None, portid=None):
        """Return lldp agents associated with host and or port.

        :param hostid: The id or uuid of a host.
        :param portid: The id or uuid of a port
        :returns:  List of lldp agents
        """

    @abc.abstractmethod
    def lldp_agent_get_by_host(self, hostid,
                               limit=None, marker=None,
                               sort_key=None, sort_dir=None):
        """List all the lldp agents for a given host.

        :param hostid: The id or uuid of an host.
        :param limit: Maximum number of lldp agents to return.
        :param marker: The last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: Direction in which results should be sorted
                         (asc, desc)
        :returns: A list of lldp agents.
        """

    @abc.abstractmethod
    def lldp_agent_get_by_port(self, portid):
        """List all the lldp agents for a given port.

        :param portid: The id or uuid of an port.
        :param limit: Maximum number of lldp agents to return.
        :param marker: The last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: Direction in which results should be sorted
                         (asc, desc)
        :returns: A list of lldp agents.
        """

    @abc.abstractmethod
    def lldp_agent_update(self, agentid, values):
        """Update properties of an lldp agent.

        :param agentid: The id or uuid of an lldp agent.
        :param values: Dict of values to update.
        :returns: An lldp agent
        """

    @abc.abstractmethod
    def lldp_agent_destroy(self, agentid):
        """Destroy an lldp agent

        :param agentid: The id or uuid of an lldp agent.
        """

    @abc.abstractmethod
    def lldp_neighbour_create(self, portid, hostid, values):
        """Create a new lldp neighbour for a server.

        :param portid: The id, uuid or database object of the port to which
                       the lldp neighbour belongs.
        :param hostid: The id, uuid or database object of the host to which
                       the lldp neighbour belongs.
        :param values: A dict containing several items used to identify
                       and track the neighbour. For example:
                        {
                         'uuid': uuidutils.generate_uuid(),
                         'msap': 'chassis_id:port_id',
                        }
        :returns: An lldp neighbour
        """

    @abc.abstractmethod
    def lldp_neighbour_get(self, neighbourid, hostid=None):
        """Return an lldp neighbour

        :param neighbourid: The id or uuid of an lldp neighbour.
        :param hostid: The id or uuid of a host.
        :returns: An lldp neighbour
        """

    @abc.abstractmethod
    def lldp_neighbour_get_list(self, limit=None, marker=None,
                                sort_key=None, sort_dir=None):
        """Return a list of lldp neighbours.

        :param limit: Maximum number of lldp neighbours to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: Direction in which results should be sorted.
                         (asc, desc)
        :returns:  List of lldp neighbours
        """

    @abc.abstractmethod
    def lldp_neighbour_get_all(self, hostid=None, interfaceid=None):
        """Return lldp neighbours associated with host and or port.

        :param hostid: The id or uuid of a host.
        :param portid: The id or uuid of a port
        :returns:  List of lldp neighbours
        """

    @abc.abstractmethod
    def lldp_neighbour_get_by_host(self, host,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        """List all the lldp neighbours for a given host.

        :param hostid: The id or uuid of an host.
        :param limit: Maximum number of lldp neighbours to return.
        :param marker: The last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: Direction in which results should be sorted
                         (asc, desc)
        :returns: A list of lldp neighbours.
        """

    @abc.abstractmethod
    def lldp_neighbour_get_by_port(self, port,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        """List all the lldp neighbours for a given port.

        :param portid: The id or uuid of an port.
        :param limit: Maximum number of lldp neighbours to return.
        :param marker: The last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: Direction in which results should be sorted
                         (asc, desc)
        :returns: A list of lldp neighbours.
        """

    @abc.abstractmethod
    def lldp_neighbour_get_by_msap(self, msap,
                                   portid=None,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        """List all the lldp neighbours for a given MAC service access

           point identifier (MSAP).

        :param msap: The mac service access point identifier
        :param portid: The id or uuid of an port.
        :param limit: Maximum number of lldp neighbours to return.
        :param marker: The last item of the previous page; we return
                       the next result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: Direction in which results should be sorted
                         (asc, desc)
        :returns: An lldp neighbour.
        """

    @abc.abstractmethod
    def lldp_neighbour_update(self, uuid, values):
        """Update properties of an lldp neighbour.

        :param agentid: The id or uuid of an lldp neighbour.
        :param values: Dict of values to update.
        :param hostid: The id or uuid of the host to which the lldp
                       neighbour belong.
        :returns: An lldp neighbour
        """

    @abc.abstractmethod
    def lldp_neighbour_destroy(self, neighbourid):
        """Destroy an lldp neighbour

        :param neighbourid: The id or uuid of an lldp neighbour.
        """

    @abc.abstractmethod
    def lldp_tlv_create(self, values, agentid=None, neighbourid=None):
        """Create a new lldp tlv for a given agent or neighbour.

        :param values: A dict containing several items used to identify
                       and track the tlv. For example:
                        {
                         'type': 'system_name',
                         'value': 'switchA',
                        }
        :param agentid: The id, uuid of the LLDP agent to which
                       the lldp tlv belongs.
        :param neighbourid: The id, uuid of the LLDP neighbour to which
                       the lldp tlv belongs.

        :returns: An lldp tlv
        """

    @abc.abstractmethod
    def lldp_tlv_get(self, type, agentid=None, neighbourid=None):
        """Return an lldp tlv of a certain type for a given agent

           or neighbour

        :param type: The TLV type
        :param agentid: The id or uuid of an lldp agent.
        :param neighbourid: The id or uuid of an lldp neighbour.
        :returns: An lldp tlv
        """

    @abc.abstractmethod
    def lldp_tlv_get_by_id(self, id, agentid=None, neighbourid=None):
        """Return an lldp tlv

        :param id: The id of the TLV
        :param agentid: The id or uuid of an lldp agent.
        :param neighbourid: The id or uuid of an lldp neighbour.
        :returns: An lldp tlv
        """

    @abc.abstractmethod
    def lldp_tlv_get_list(self, limit=None, marker=None,
                          sort_key=None, sort_dir=None):
        """Return a list of lldp tlvs.

        :param limit: Maximum number of lldp tlvs to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: Direction in which results should be sorted.
                         (asc, desc)
        :returns:  List of lldp tlvs
        """

    @abc.abstractmethod
    def lldp_tlv_get_all(self, agentid=None, neighbourid=None):
        """Return lldp tlvs associated with an agent or neighbour.

        :param agentid: The id or uuid of an lldp agent.
        :param neighbourid: The id or uuid of an lldp neighbour
        :returns:  List of lldp tlvs
        """

    @abc.abstractmethod
    def lldp_tlv_get_by_agent(self, agentid,
                              limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        """Return lldp tlvs associated with an lldp agent.

        :param agentid: The id or uuid of an lldp agent.
        :param limit: Maximum number of lldp tlvs to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: Direction in which results should be sorted.
                         (asc, desc)
        :returns:  List of lldp tlvs
        """

    @abc.abstractmethod
    def lldp_tlv_get_by_neighbour(self, neighbourid,
                                  limit=None, marker=None,
                                  sort_key=None, sort_dir=None):
        """Return lldp tlvs associated with an lldp neighbour.

        :param neighbourid: The id or uuid of an lldp neighbour.
        :param limit: Maximum number of lldp tlvs to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: Direction in which results should be sorted.
                         (asc, desc)
        :returns:  List of lldp tlvs
        """

    @abc.abstractmethod
    def lldp_tlv_update(self, values, agentid=None, neighbourid=None):
        """Update properties of an lldp tlv.

        :param values: Dict of TLV values to update.
        :param agentid: The id or uuid of an lldp agent to which the tlv
                        belongs.
        :param neighbourid: The id or uuid of and lldp neighbour to which
                            the tlv belongs
        :returns: An lldp tlv
        """

    @abc.abstractmethod
    def lldp_tlv_update_bulk(self, values, agentid=None, neighbourid=None):
        """Update properties of a list of lldp tlvs.

        :param values: List of dicts of TLV values to update.
        :param agentid: The id or uuid of an lldp agent to which the tlv
                        belongs.
        :param neighbourid: The id or uuid of and lldp neighbour to which
                            the tlv belongs
        :returns: A list of lldp tlvs
        """

    @abc.abstractmethod
    def lldp_tlv_create_bulk(self, values, agentid=None, neighbourid=None):
        """Create TLVs in bulk from a list of lldp tlvs.

        :param values: List of dicts of TLV values to create.
        :param agentid: The id or uuid of an lldp agent to which the tlv
                        belongs.
        :param neighbourid: The id or uuid of and lldp neighbour to which
                            the tlv belongs
        :returns: A list of lldp tlvs
        """

    @abc.abstractmethod
    def lldp_tlv_destroy(self, id):
        """Destroy an lldp tlv

        :param id: The id of an lldp tlv.
        """

    @abc.abstractmethod
    def sdn_controller_create(self, values):
        """Create a new SDN controller configuration.

        :param values: A dict containing several items used to identify
                       and track the sdn controller. For example:
                        {
                         'uuid': uuidutils.generate_uuid(),
                         'ip_address': 'FQDN or IP address',
                         'port' : 'listening port on remote SDN controller',
                         'transport' : 'TCP | UDP | TLS',
                         'state' : 'administrative state',
                         'username' : 'login username',
                         'password' : 'login password',
                         'vendor' : 'the SDN controller vendor type',
                        }
        :returns: An SDN controller
        """

    @abc.abstractmethod
    def sdn_controller_get(self, uuid):
        """Return an SDN controller

        :param uuid: The uuid of an SDN controller.
        :returns: An SDN controller
        """

    @abc.abstractmethod
    def sdn_controller_get_list(self, limit=None, marker=None,
                                sort_key=None, sort_dir=None):
        """Return a list of SDN controllers .

        :param limit: Maximum number of SDN controllers to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: Direction in which results should be sorted.
                         (asc, desc)
        :returns:  List of SDN controllers
        """

    @abc.abstractmethod
    def sdn_controller_update(self, uuid, values):
        """Update properties of an SDN controller.

        :param uuid: The uuid of an SDN controller.
        :param values: Dict of values to update.
        :returns: An SDN controller
        """

    @abc.abstractmethod
    def sdn_controller_destroy(self, uuid):
        """Destroy an SDN controller

        :param uuid: The uuid of an SDN controller.
        """

    @abc.abstractmethod
    def tpmconfig_get(self, uuid):
        """Return a TPM configuration

        :param uuid: The uuid of an tpmconfig.
        :returns: A TPM configuration
        """

    @abc.abstractmethod
    def tpmconfig_get_one(self):
        """Return exactly one TPM configuration.

        :returns: A TPM configuration
        """

    @abc.abstractmethod
    def tpmconfig_get_list(self, limit=None, marker=None,
                           sort_key=None, sort_dir=None):
        """Return a list of TPM configurations.

        :param limit: Maximum number of TPM configurations to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: Direction in which results should be sorted.
                         (asc, desc)
        :returns:  List of TPM configurations
        """

    @abc.abstractmethod
    def tpmconfig_update(self, uuid, values):
        """Update properties of a TPM configuration.

        :param uuid: The uuid of an tpmconfig.
        :param values: Dict of values to update.
        :returns: A TPM configuration
        """

    @abc.abstractmethod
    def tpmconfig_destroy(self, uuid):
        """Destroy a TPM configuration

        :param uuid: The uuid of an tpmconfig.
        """

    @abc.abstractmethod
    def tpmdevice_create(self, forihostid, values):
        """Create a new TPM Device configuration.

        :param values: A dict containing several items used to identify
                       and track the TPM device. For example:
                        {
                         'uuid'     : uuidutils.generate_uuid(),
                         'state'    : 'configuration state of the system',
                        }
        :returns: A TPM Device configuration
        """

    @abc.abstractmethod
    def tpmdevice_get(self, uuid):
        """Return a TPM Device configuration

        :param uuid: The uuid of a tpmdevice.
        :returns: A TPM Device configuration
        """

    @abc.abstractmethod
    def tpmdevice_get_list(self, limit=None, marker=None,
                           sort_key=None, sort_dir=None):
        """Return a list of TPM Device configurations.

        :param limit: Maximum number of TPM Device configurations to return.
        :param marker: The last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: Direction in which results should be sorted.
                         (asc, desc)
        :returns:  List of TPM Device configurations
        """

    @abc.abstractmethod
    def tpmdevice_get_by_host(self, host_id,
                               limit=None, marker=None,
                               sort_key=None, sort_dir=None):
        """List all the tpmdevices for a given host_id.

        :param host_id: The id or uuid of an ihost.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of tpmdevices.
        """

    @abc.abstractmethod
    def tpmdevice_update(self, uuid, values):
        """Update properties of a TPM Device configuration.

        :param uuid: The uuid of an tpmdevice.
        :param values: Dict of values to update.
        :returns: A TPM Device configuration
        """

    @abc.abstractmethod
    def tpmdevice_destroy(self, uuid):
        """Destroy a TPM Device configuration

        :param uuid: The uuid of a tpmdevice.
        """

    @abc.abstractmethod
    def interface_network_create(self, values):
        """Create a new interface to network association.

        :param values: A dict containing several items used to identify
                       and track the interface to network association. For example:
                        {
                         'interface_id'  : id of the interface,
                         'network_id'    : id of the network,
                        }
        :returns: An interface network association
        """

    @abc.abstractmethod
    def interface_network_get_by_interface(self, interface_id,
                                           limit=None, marker=None,
                                           sort_key=None, sort_dir=None):
        """List all the interface networks for a given interface.

        :param interface_id: The id or uuid of an interface.
        :param limit: Maximum number of items to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of interface-network.
        """

    @abc.abstractmethod
    def interface_network_destroy(self, uuid):
        """Destroy an interface network association

        :param uuid: The uuid of an interface network association.
        """

    @abc.abstractmethod
    def host_fs_create(self, forihostid, values):
        """Create a new filesystem for a host.

        :param forihostid: uuid or id of an ihost
        :param values: A dict containing several items used to identify
                       and track the filesystem.
            Example:
            values = {'name': constants.FILESYSTEM_NAME_DOCKER,
                      'size': 30,
                      'logical_volume': constants.FILESYSTEM_LV_DICT[
                           constants.FILESYSTEM_NAME_DOCKER],
                      'forihostid': 1}
        :returns: A filesystem.
        """

    @abc.abstractmethod
    def host_fs_get(self, fs_id):
        """Return a filesystem.

        :param fs_id: The id or uuid of a filesystem.
        :returns: A filesystem.
        """

    @abc.abstractmethod
    def host_fs_get_all(self, forihostid=None):
        """Return filesystems.

        :param forihostid: The id or uuid of an ihost.
        :returns:  filesystem.
        """

    @abc.abstractmethod
    def host_fs_get_list(self, limit=None, marker=None,
                         sort_key=None, sort_dir=None):
        """Return a list of filesystems.

        :param limit: Maximum number of filesystems to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def host_fs_get_by_ihost(self, ihost, limit=None,
                             marker=None, sort_key=None,
                             sort_dir=None):
        """List all the filesystems for a given ihost.

        :param ihost: The id or uuid of an ihost.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted
        :param sort_dir: direction in which results should be sorted
                         (asc, desc)
        :returns: A list of filesystems.
        """

    @abc.abstractmethod
    def host_fs_update(self, fs_id, values):
        """Update properties of a filesystem.

        :param fs_id: The id or uuid of an filesystem.
        :param values: Dict of values to update. May be a partial list.
            Example:
            values = {'name': constants.FILESYSTEM_NAME_DOCKER,
                      'size': 30,
                      'logical_volume': constants.FILESYSTEM_LV_DICT[
                           constants.FILESYSTEM_NAME_DOCKER
                           ],
                      'forihostid': 1}
        :returns: A filesystem.
        """

    @abc.abstractmethod
    def host_fs_destroy(self, fs_id):
        """Destroy a filesystem.

        :param fs_id: The id or uuid of a filesystem.
        """

    @abc.abstractmethod
    def kube_host_upgrade_create(self, forhostid, values):
        """Create a new kube_host_upgrade for a host.

        :param forhostid: uuid or id of an ihost
        :param values: A dict containing several items used to identify
                       and track the kube_host_upgrade.
        :returns: A kube_host_upgrade.
        """

    @abc.abstractmethod
    def kube_host_upgrade_get(self, host_upgrade_id):
        """Return kube_host_upgrade.

        :param host_upgrade_id: The id or uuid of a kube_host_upgrade.
        :returns: A kube_host_upgrade.
        """

    @abc.abstractmethod
    def kube_host_upgrade_get_list(self, limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        """Return a list of kube_host_upgrade.

        :param limit: Maximum number of kube_host_upgrade to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def kube_host_upgrade_get_by_host(self, host_id):
        """List all the kube_host_upgrade for a given ihost.

        :param host_id: The id or uuid of an ihost.
        :returns: A list of kube_host_upgrade.
        """

    @abc.abstractmethod
    def kube_host_upgrade_update(self, host_upgrade_id, values):
        """Update properties of a kube_host_upgrade.

        :param host_upgrade_id: The id or uuid of a kube_host_upgrade.
        :param values: Dict of values to update. May be a partial list.
        :returns: A kube_host_upgrade.
        """

    @abc.abstractmethod
    def kube_host_upgrade_destroy(self, host_upgrade_id):
        """Destroy a kube_host_upgrade.

        :param host_upgrade_id: The id or uuid of a kube_host_upgrade.
        """

    @abc.abstractmethod
    def kube_upgrade_create(self, values):
        """Create a new kube_upgrade for an isystem.

        :param values: A dict containing several items used to identify
                       and track the kube_upgrade settings.
        :returns: A kube_upgrade.
        """

    @abc.abstractmethod
    def kube_upgrade_get(self, upgrade_id):
        """Return an kube_upgrade.

        :param upgrade_id: The id or uuid of an kube_upgrade.
        :returns: A kube_upgrade.
        """

    @abc.abstractmethod
    def kube_upgrade_get_one(self):
        """Return exactly one kube_upgrade.

        :returns: A kube_upgrade.
        """

    @abc.abstractmethod
    def kube_upgrade_get_list(self, limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        """Return a list of kube_upgrade.

        :param limit: Maximum number of kube_upgrade to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def kube_upgrade_update(self, upgrade_id, values):
        """Update properties of an kube_upgrade.

        :param upgrade_id: The id or uuid of a kube_upgrade.
        :param values: Dict of values to update.
        :returns: A kube_upgrade.
        """

    @abc.abstractmethod
    def kube_upgrade_destroy(self, upgrade_id):
        """Destroy an kube_upgrade.

        :param upgrade_id: The id or uuid of a kube_upgrade.
        """

    @abc.abstractmethod
    def restore_create(self, values):
        """Create a new restore entry

        :param values: A dict containing several items used to identify
                       and track the entry.

                        {
                         'uuid': uuidutils.generate_uuid(),
                        }
        :returns: A restore record.
        """

    @abc.abstractmethod
    def restore_get(self, id):
        """Return a restore entry for a given id

        :param _id: The id or uuid of a restore entry
        :returns: a restore entry
        """

    @abc.abstractmethod
    def restore_get_list(self, limit=None, marker=None,
                         sort_key=None, sort_dir=None):
        """Return a list of restore entries.

        :param limit: Maximum number of restore entries to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def restore_get_one(self, filters):
        """Return exactly one restore.

        :param filters: A dict of filters to apply on the query.
                        The key of the entry is the column to search in.
                        The value of the entry is the value to search for.
                        Capable of simple filtering equivalent to `value in [values]`.
                        Eg: filters={'state': 'some-state-value'} is equivalent to
                            `model.MyModel.state in ['some-state-value']`

        :returns: A restore.
        """

    @abc.abstractmethod
    def restore_update(self, uuid, values):
        """Update properties of a restore.

        :param node: The uuid of a restore entry.
        :param values: Dict of values to update.
                       {'state': constants.RESTORE_STATE_COMPLETED
                       }
        :returns: A restore entry.
        """

    @abc.abstractmethod
    def restore_destroy(self, id):
        """Destroy a restore entry.

        :param id: The id or uuid of a restore entry.
        """

    @abc.abstractmethod
    def kube_rootca_host_update_create(self, host_id, values):
        """Create a new kubernetes rootca update entry on host db.

        :param host_id: The id or uuid of a host.
        :param values: Some values referencing fields of the object stored on DB.
        """

    @abc.abstractmethod
    def kube_rootca_host_update_get(self, rootca_host_update_id):
        """ Get a kubernetes rootca update host entry

        :param rootca_host_update_id:  The id or uuid of a host.
        """

    @abc.abstractmethod
    def kube_rootca_host_update_get_list(self, limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        """ Return a list of kubernetes rootca update entries per host.
            Allow users to see a complete report of the update procedure on each host.

        :param limit: Maximum number of kubernetes rootca update entries to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def kube_rootca_host_update_get_by_host(self, host_id):
        """ List all the kube_host_rootca_update for a given ihost.

        :param host_id: The id or uuid of an ihost.
        :returns: A list of kube_host_rootca_update.
        """

    @abc.abstractmethod
    def kube_rootca_host_update_update(self, rootca_host_update_id, values):
        """ Update a host entry for kubernetes rootca update.

        :param rootca_host_update_id: host id in which the entry is going to be updated.
        :param values: a dictionary with the values of each field of the entry to be modified.
        """

    @abc.abstractmethod
    def kube_rootca_host_update_destroy(self, rootca_host_update_id):
        """ Delete a host entry for kubernetes rootca update.

        :param rootca_host_update_id: host id of the host entry to be deleted
        """

    @abc.abstractmethod
    def kube_rootca_update_create(self, values):
        """ Create and start a procedure for kubernetes rootca update.

        :param values: dictionary with fields to be stored in the database table for this procedure.
        """

    @abc.abstractmethod
    def kube_rootca_update_get(self, rootca_update_id):
        """ Get a kubernetes rootca update entry

        :param rootca_update_id: identifier for the kubernetes rootca procedure.
        """

    @abc.abstractmethod
    def kube_rootca_update_get_one(self):
        """Get a rootca update entry."""

    @abc.abstractmethod
    def kube_rootca_update_get_list(self, limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        """ Return a list of kubernetes rootca update entries.

        :param limit: Maximum number of kubernetes rootca update entries to return.
        :param marker: the last item of the previous page; we return the next
                       result set.
        :param sort_key: Attribute by which results should be sorted.
        :param sort_dir: direction in which results should be sorted.
                         (asc, desc)
        """

    @abc.abstractmethod
    def kube_rootca_update_update(self, rootca_update_id, values):
        """ Update a kubernetes rootca update procedure entry.

        :param rootca_update_id:  id of the update entry on kubernetes rootca update table.
        :param values: a dictionary with the respective fields and values to be updated in the db entry.
        """

    @abc.abstractmethod
    def kube_rootca_update_destroy(self, rootca_update_id):
        """ Delete a kubernetes rootca update entry.

        :param rootca_update_id: id of the kubernetes rootca update entry to be deleted from database.
        """

    @abc.abstractmethod
    def kube_cmd_version_get(self):
        """ Get the kubernetes cmd version entry"""

    @abc.abstractmethod
    def kube_cmd_version_update(self, values):
        """ Update the kubernetes cmd version entry.

        :param values: a dictionary with the respective fields and values to be updated in the db entry.
        """
