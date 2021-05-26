# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- encoding: utf-8 -*-
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

"""SQLAlchemy storage backend."""


import eventlet
import re

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_db.sqlalchemy import enginefacade
from oslo_db.sqlalchemy import utils as db_utils

from sqlalchemy import inspect
from sqlalchemy import or_

from sqlalchemy.orm import contains_eager
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import subqueryload
from sqlalchemy.orm import with_polymorphic
from sqlalchemy.orm.exc import DetachedInstanceError
from sqlalchemy.orm.exc import MultipleResultsFound
from sqlalchemy.orm.exc import NoResultFound

from oslo_log import log
from oslo_utils import uuidutils
from sysinv._i18n import _
from sysinv import objects
from sysinv.common import constants
from sysinv.common import device as dconstants
from sysinv.common import exception
from sysinv.common import utils
from sysinv.db import api
from sysinv.db.sqlalchemy import models

CONF = cfg.CONF
CONF.import_opt('journal_min_size',
                'sysinv.api.controllers.v1.storage',
                group='journal')
CONF.import_opt('journal_max_size',
                'sysinv.api.controllers.v1.storage',
                group='journal')
CONF.import_opt('journal_default_size',
                'sysinv.api.controllers.v1.storage',
                group='journal')

LOG = log.getLogger(__name__)

IP_FAMILIES = {4: 'IPv4', 6: 'IPv6'}


context_manager = enginefacade.transaction_context()
context_manager.configure(sqlite_fk=True)


def get_session(autocommit=True, expire_on_commit=False, use_slave=False):
    """Helper method to grab session."""
    return context_manager.get_legacy_facade().get_session(
        autocommit=autocommit, expire_on_commit=expire_on_commit,
        use_slave=use_slave)


def get_backend():
    """The backend is this module itself."""
    return Connection()


def _session_for_read():
    _context = eventlet.greenthread.getcurrent()
    return enginefacade.reader.using(_context)


def _session_for_write():
    _context = eventlet.greenthread.getcurrent()
    LOG.debug("_session_for_write CONTEXT=%s" % _context)
    return enginefacade.writer.using(_context)


def _paginate_query(model, limit=None, marker=None, sort_key=None,
                    sort_dir=None, query=None):
    if not query:
        query = model_query(model)

    if not sort_key:
        sort_keys = []
    elif not isinstance(sort_key, list):
        sort_keys = [sort_key]
    else:
        sort_keys = sort_key

    if 'id' not in sort_keys:
        sort_keys.append('id')
    query = db_utils.paginate_query(query, model, limit, sort_keys,
                                    marker=marker, sort_dir=sort_dir)
    return query.all()


def model_query(model, *args, **kwargs):
    """Query helper for simpler session usage.

    :param session: if present, the session to use
    """

    session = kwargs.get('session')
    if session:
        query = session.query(model, *args)
    else:
        with _session_for_read() as session:
            query = session.query(model, *args)

    return query


def add_identity_filter(query, value,
                        use_ifname=False,
                        use_ipaddress=False,
                        use_community=False,
                        use_key=False,
                        use_name=False,
                        use_cname=False,
                        use_secname=False,
                        use_lvgname=False,
                        use_pvname=False,
                        use_sensorgroupname=False,
                        use_sensorname=False,
                        use_cluster_uuid=False,
                        use_pciaddr=False,
                        use_fsname=False):
    """Adds an identity filter to a query.

    Filters results by ID, if supplied value is a valid integer.
    Otherwise attempts to filter results by UUID.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    if utils.is_int_like(value):
        return query.filter_by(id=value)
    elif use_cluster_uuid:
        return query.filter_by(cluster_uuid=value)
    elif uuidutils.is_uuid_like(value):
        return query.filter_by(uuid=value)
    else:
        if use_ifname:
            return query.filter_by(ifname=value)
        elif use_ipaddress:
            return query.filter_by(ip_address=value)
        elif use_community:
            return query.filter_by(community=value)
        elif use_name:
            return query.filter_by(name=value)
        elif use_cname:
            return query.filter_by(cname=value)
        elif use_secname:
            return query.filter_by(secname=value)
        elif use_key:
            return query.filter_by(key=value)
        elif use_lvgname:
            return query.filter_by(lvm_vg_name=value)
        elif use_pvname:
            return query.filter_by(lvm_pv_name=value)
        elif use_sensorgroupname:
            return query.filter_by(sensorgroupname=value)
        elif use_sensorname:
            return query.filter_by(sensorname=value)
        elif use_pciaddr:
            return query.filter_by(pciaddr=value)
        elif use_fsname:
            return query.filter_by(name=value)
        else:
            return query.filter_by(hostname=value)


def add_filter_by_many_identities(query, model, values):
    """Adds an identity filter to a query for values list.

    Filters results by ID, if supplied values contain a valid integer.
    Otherwise attempts to filter results by UUID.

    :param query: Initial query to add filter to.
    :param model: Model for filter.
    :param values: Values for filtering results by.
    :return: tuple (Modified query, filter field name).
    """
    if not values:
        raise exception.InvalidIdentity(identity=values)
    value = values[0]
    if utils.is_int_like(value):
        return query.filter(getattr(model, 'id').in_(values)), 'id'
    elif uuidutils.is_uuid_like(value):
        return query.filter(getattr(model, 'uuid').in_(values)), 'uuid'
    else:
        raise exception.InvalidIdentity(identity=value)


def add_host_options(query):
    return query. \
        options(joinedload(models.ihost.system)). \
        options(joinedload(models.ihost.host_upgrade).
                joinedload(models.HostUpgrade.load_software)). \
        options(joinedload(models.ihost.host_upgrade).
                joinedload(models.HostUpgrade.load_target))


def add_inode_filter_by_ihost(query, value):
    if utils.is_int_like(value):
        return query.filter_by(forihostid=value)
    # else:    # possibly hostname
    #     query = query.join(models.ihost,
    #             models.inode.forihostid == models.ihost.id)
    #     return query.filter(models.ihost.hostname == value)
    #
    # elif uuidutils.is_uuid_like(value):
    else:
        query = query.join(models.ihost,
                models.inode.forihostid == models.ihost.id)
        return query.filter(models.ihost.uuid == value)


def add_filter_by_ihost_inode(query, ihostid, inodeid):
    if utils.is_int_like(ihostid) and utils.is_int_like(inodeid):
        return query.filter_by(forihostid=ihostid, forinodeid=inodeid)

    if utils.is_uuid_like(ihostid) and utils.is_uuid_like(inodeid):
        ihostq = model_query(models.ihost).filter_by(uuid=ihostid).first()
        inodeq = model_query(models.inode).filter_by(uuid=inodeid).first()

        query = query.filter_by(forihostid=ihostq.id,
                                forinodeid=inodeq.id)

        return query


def add_icpu_filter_by_ihost(query, value):
    if utils.is_int_like(value):
        return query.filter_by(forihostid=value)
    else:
        query = query.join(models.ihost,
                           models.icpu.forihostid == models.ihost.id)
        return query.filter(models.ihost.uuid == value)


def add_icpu_filter_by_ihost_inode(query, ihostid, inodeid):
    if utils.is_int_like(ihostid) and utils.is_int_like(inodeid):
        return query.filter_by(forihostid=ihostid, forinodeid=inodeid)

    # gives access to joined tables... nice to have unique col name
    if utils.is_uuid_like(ihostid) and utils.is_uuid_like(inodeid):
        query = query.join(models.ihost,
                           models.icpu.forihostid == models.ihost.id,
                           models.inode.forihostid == models.ihost.id)

        return query.filter(models.ihost.uuid == ihostid,
                            models.inode.uuid == inodeid)

    LOG.error("cpu_filter_by_ihost_inode: No match for id int or ids uuid")


def add_icpu_filter_by_inode(query, inodeid):
    if utils.is_int_like(inodeid):
        return query.filter_by(forinodeid=inodeid)
    else:
        query = query.join(models.inode,
                models.icpu.forinodeid == models.inode.id)
        return query.filter(models.inode.uuid == inodeid)


def add_imemory_filter_by_ihost(query, value):
    if utils.is_int_like(value):
        return query.filter_by(forihostid=value)
    else:
        query = query.join(models.ihost,
                           models.imemory.forihostid == models.ihost.id)
        return query.filter(models.ihost.uuid == value)


def add_imemory_filter_by_ihost_inode(query, ihostid, inodeid):
    if utils.is_int_like(ihostid) and utils.is_int_like(inodeid):
        return query.filter_by(forihostid=ihostid, forinodeid=inodeid)

    # gives access to joined tables... nice to have unique col name
    if utils.is_uuid_like(ihostid) and utils.is_uuid_like(inodeid):
        ihostq = model_query(models.ihost).filter_by(uuid=ihostid).first()
        inodeq = model_query(models.inode).filter_by(uuid=inodeid).first()

        query = query.filter_by(forihostid=ihostq.id,
                                forinodeid=inodeq.id)

        return query

    LOG.error("memory_filter_by_ihost_inode: No match for id or uuid")


def add_imemory_filter_by_inode(query, inodeid):
    if utils.is_int_like(inodeid):
        return query.filter_by(forinodeid=inodeid)
    else:
        query = query.join(models.inode,
                models.imemory.forinodeid == models.inode.id)
        return query.filter(models.inode.uuid == inodeid)


def add_device_filter_by_host(query, hostid):
    """Adds a device-specific ihost filter to a query.

    Filters results by host id if supplied value is an integer,
    otherwise attempts to filter results by host uuid.

    :param query: Initial query to add filter to.
    :param hostid: host id or uuid to filter results by.
    :return: Modified query.
    """
    if utils.is_int_like(hostid):
        return query.filter_by(host_id=hostid)

    elif utils.is_uuid_like(hostid):
        query = query.join(models.ihost)
        return query.filter(models.ihost.uuid == hostid)


def add_interface_filter(query, value):
    """Adds a interface-specific filter to a query.

    Filters results by mac, if supplied value is a valid MAC
    address. Otherwise attempts to filter results by identity.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    if utils.is_valid_mac(value):
        return query.filter(models.Interfaces.imac == value)
    elif uuidutils.is_uuid_like(value):
        return query.filter(models.Interfaces.uuid == value)
    elif utils.is_int_like(value):
        return query.filter(models.Interfaces.id == value)
    else:
        return add_identity_filter(query, value, use_ifname=True)


def add_interface_filter_by_port(query, value):
    """Adds an interface-specific filter to a query.

    Filters results by port id if supplied value is an integer.
    Filters results by port UUID if supplied value is a UUID.
    Otherwise attempts to filter results by name

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    query = query.join(models.Ports)
    if utils.is_int_like(value):
        return query.filter(models.Ports.id == value)
    elif uuidutils.is_uuid_like(value):
        return query.filter(models.Ports.uuid == value)
    else:
        return query.filter(models.Ports.name == value)


def add_interface_filter_by_ihost(query, value):
    """Adds an interface-specific filter to a query.

    Filters results by hostid, if supplied value is an integer.
    Otherwise attempts to filter results by UUID.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    if utils.is_int_like(value):
        return query.filter_by(forihostid=value)
    else:
        query = query.join(models.ihost,
                models.Interfaces.forihostid == models.ihost.id)
        return query.filter(models.ihost.uuid == value)


def add_datanetwork_filter(query, value):
    """Adds a datanetwork-specific filter to a query.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """

    if uuidutils.is_uuid_like(value):
        return query.filter(or_(models.DataNetworksFlat.uuid == value,
                                models.DataNetworksVlan.uuid == value,
                                models.DataNetworksVXlan.uuid == value))
    elif utils.is_int_like(value):
        return query.filter(or_(models.DataNetworksFlat.id == value,
                                models.DataNetworksVlan.id == value,
                                models.DataNetworksVXlan.id == value))
    else:
        return add_identity_filter(query, value, use_name=True)


def add_port_filter_by_numa_node(query, nodeid):
    """Adds a port-specific numa node filter to a query.

    Filters results by numa node id if supplied nodeid is an integer,
    otherwise attempts to filter results by numa node uuid.

    :param query: Initial query to add filter to.
    :param nodeid: numa node id or uuid to filter results by.
    :return: Modified query.
    """
    if utils.is_int_like(nodeid):
        #
        # Should not need join due to polymorphic ports table
        # query = query.join(models.Ports,
        #                    models.EthernetPorts.id == models.Ports.id)
        #
        # Query of ethernet_ports table should return data from
        # corresponding ports table entry so should be able to
        # use filter_by() rather than filter()
        #
        return query.filter_by(node_id=nodeid)

    elif utils.is_uuid_like(nodeid):
        #
        # Should be able to join on foreign key without specifying
        # explicit join condition since only a single foreign key
        # between tables.
        # query = (query.join(models.inode,
        #                 models.EthernetPorts.node_id == models.inode.id))
        #
        query = query.join(models.inode)
        return query.filter(models.inode.uuid == nodeid)

    LOG.debug("port_filter_by_numa_node: "
              "No match for supplied filter id (%s)" % str(nodeid))


def add_port_filter_by_host(query, hostid):
    """Adds a port-specific ihost filter to a query.

    Filters results by host id if supplied value is an integer,
    otherwise attempts to filter results by host uuid.

    :param query: Initial query to add filter to.
    :param hostid: host id or uuid to filter results by.
    :return: Modified query.
    """
    if utils.is_int_like(hostid):
        #
        # Should not need join due to polymorphic ports table
        # query = query.join(models.Ports,
        #                    models.EthernetPorts.id == models.Ports.id)
        #
        # Query of ethernet_ports table should return data from
        # corresponding ports table entry so should be able to
        # use filter_by() rather than filter()
        #
        return query.filter_by(host_id=hostid)

    elif utils.is_uuid_like(hostid):
        #
        # Should be able to join on foreign key without specifying
        # explicit join condition since only a single foreign key
        # between tables.
        # query = (query.join(models.ihost,
        #                 models.EthernetPorts.host_id == models.ihost.id))
        #
        query = query.join(models.ihost)
        return query.filter(models.ihost.uuid == hostid)

    LOG.debug("port_filter_by_host: "
              "No match for supplied filter id (%s)" % str(hostid))


def add_port_filter_by_interface(query, interfaceid):
    """Adds a port-specific interface filter to a query.

    Filters results by interface id if supplied value is an integer,
    otherwise attempts to filter results by interface uuid.

    :param query: Initial query to add filter to.
    :param interfaceid: interface id or uuid to filter results by.
    :return: Modified query.
    """
    if utils.is_int_like(interfaceid):
        #
        # Should not need join due to polymorphic ports table
        # query = query.join(models.iinterface,
        #                    models.EthernetPorts.interface_id == models.iinterface.id)
        #
        # Query of ethernet_ports table should return data from
        # corresponding ports table entry so should be able to
        # use filter_by() rather than filter()
        #
        return query.filter_by(interface_id=interfaceid)

    elif utils.is_uuid_like(interfaceid):
        #
        # Should be able to join on foreign key without specifying
        # explicit join condition since only a single foreign key
        # between tables.
        # query = query.join(models.iinterface,
        #                    models.EthernetPorts.interface_id == models.iinterface.id)
        #
        query = query.join(models.Interfaces,
                           models.Ports.interface_id == models.Interfaces.id)

        return query.filter(models.Interfaces.uuid == interfaceid)

    LOG.debug("port_filter_by_interface: "
              "No match for supplied filter id (%s)" % str(interfaceid))


def add_port_filter_by_host_interface(query, hostid, interfaceid):
    """Adds a port-specific host and interface filter to a query.

    Filters results by host id and interface id if supplied hostid and
    interfaceid are integers, otherwise attempts to filter results by
    host uuid and interface uuid.

    :param query: Initial query to add filter to.
    :param hostid: host id or uuid to filter results by.
    :param interfaceid: interface id or uuid to filter results by.
    :return: Modified query.
    """
    if utils.is_int_like(hostid) and utils.is_int_like(interfaceid):
        return query.filter_by(host_id=hostid, interface_id=interfaceid)

    elif utils.is_uuid_like(hostid) and utils.is_uuid_like(interfaceid):
        query = query.join(models.ihost,
                           models.Interfaces)
        return query.filter(models.ihost.uuid == hostid,
                            models.Interfaces.uuid == interfaceid)

    LOG.debug("port_filter_by_host_iinterface: "
              "No match for supplied filter ids (%s, %s)"
              % (str(hostid), str(interfaceid)))


def add_istor_filter(query, value):
    """Adds an istor-specific filter to a query.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    return add_identity_filter(query, value)


def add_istor_filter_by_ihost(query, value):
    if utils.is_int_like(value):
        return query.filter_by(forihostid=value)
    else:
        query = query.join(models.ihost,
                models.istor.forihostid == models.ihost.id)
        return query.filter(models.ihost.uuid == value)


def add_istor_filter_by_tier(query, value):
    if utils.is_int_like(value):
        return query.filter_by(fortierid=value)
    else:
        query = query.join(models.StorageTier,
                           models.istor.fortierid == models.StorageTier.id)
        return query.filter(models.StorageTier.uuid == value)


def add_journal_filter_by_foristor(query, value):
    if utils.is_int_like(value):
        return query.filter_by(foristorid=value)
    else:
        query = query.join(models.istor,
                models.journal.foristorid == models.istor.id)
        return query.filter(models.istor.id == value)


def add_istor_filter_by_inode(query, inodeid):
    if utils.is_int_like(inodeid):
        return query.filter_by(forinodeid=inodeid)
    else:
        query = query.join(models.inode,
                models.istor.forinodeid == models.inode.id)
        return query.filter(models.inode.uuid == inodeid)


def add_ceph_mon_filter_by_ihost(query, value):
    if utils.is_int_like(value):
        return query.filter_by(forihostid=value)
    else:
        query = query.join(models.ihost,
                           models.CephMon.forihostid == models.ihost.id)
        return query.filter(models.ihost.uuid == value)


def add_ilvg_filter(query, value):
    """Adds an ilvg-specific filter to a query.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    return add_identity_filter(query, value, use_lvgname=True)


def add_ilvg_filter_by_ihost(query, value):
    if utils.is_int_like(value):
        return query.filter_by(forihostid=value)
    else:
        query = query.join(models.ihost,
                           models.ilvg.forihostid == models.ihost.id)
        return query.filter(models.ihost.uuid == value)


def add_ipv_filter(query, value):
    """Adds an ipv-specific filter to a query.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    return add_identity_filter(query, value, use_pvname=True)


def add_ipv_filter_by_ihost(query, value):
    if utils.is_int_like(value):
        return query.filter_by(forihostid=value)
    else:
        query = query.join(models.ihost,
                           models.ipv.forihostid == models.ihost.id)
        return query.filter(models.ihost.uuid == value)


def add_idisk_filter(query, value):
    """Adds an idisk-specific filter to a query.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    return add_identity_filter(query, value)


def add_idisk_filter_by_ihost(query, value):
    if utils.is_int_like(value):
        return query.filter_by(forihostid=value)
    else:
        query = query.join(models.ihost,
                models.idisk.forihostid == models.ihost.id)
        return query.filter(models.ihost.uuid == value)


def add_idisk_filter_by_istor(query, istorid):
    query = query.join(models.istor,
            models.idisk.foristorid == models.istor.id)
    return query.filter(models.istor.uuid == istorid)


def add_idisk_filter_by_ihost_istor(query, ihostid, istorid):
    # gives access to joined tables... nice to have unique col name
    if utils.is_uuid_like(ihostid) and utils.is_uuid_like(istorid):
        ihostq = model_query(models.ihost).filter_by(uuid=ihostid).first()
        istorq = model_query(models.istor).filter_by(uuid=istorid).first()

        query = query.filter_by(forihostid=ihostq.id,
                                foristorid=istorq.id)

        return query

    LOG.error("idisk_filter_by_ihost_istor: No match for uuid")


def add_idisk_filter_by_ipv(query, ipvid):
    query = query.join(models.ipv,
                       models.idisk.foripvid == models.ipv.id)
    return query.filter(models.ipv.uuid == ipvid)


def add_idisk_filter_by_device_id(query, device_id):
    return query.filter(models.idisk.device_id == device_id)


def add_idisk_filter_by_device_path(query, device_path):
    return query.filter(models.idisk.device_path == device_path)


def add_idisk_filter_by_device_wwn(query, device_wwn):
    return query.filter(models.idisk.device_wwn == device_wwn)


def add_idisk_filter_by_ihost_ipv(query, ihostid, ipvid):
    # gives access to joined tables... nice to have unique col name
    if utils.is_uuid_like(ihostid) and utils.is_uuid_like(ipvid):
        ihostq = model_query(models.ihost).filter_by(uuid=ihostid).first()
        ipvq = model_query(models.ipv).filter_by(uuid=ipvid).first()

        query = query.filter_by(forihostid=ihostq.id,
                                foripvid=ipvq.id)

        return query

    LOG.error("idisk_filter_by_ihost_ipv: No match for uuid")


def add_partition_filter_by_ihost(query, value):
    if utils.is_int_like(value):
        return query.filter_by(forihostid=value)
    else:
        query = query.join(models.ihost,
                           models.partition.forihostid == models.ihost.id)
        return query.filter(models.ihost.uuid == value)


def add_partition_filter_by_idisk(query, value):
    if utils.is_int_like(value):
        return query.filter_by(idisk_id=value)
    else:
        query = query.join(models.idisk,
                           models.partition.idisk_id == models.idisk.id)
        return query.filter(models.idisk.uuid == value)


def add_partition_filter_by_ipv(query, ipvid):
    query = query.join(models.ipv,
                       models.partition.foripvid == models.ipv.id)
    return query.filter(models.ipv.uuid == ipvid)


def add_storage_tier_filter_by_cluster(query, value):
    if utils.is_int_like(value):
        return query.filter_by(forclusterid=value)
    else:
        query = query.join(models.Clusters,
                           models.StorageTier.forclusterid == models.Clusters.id)
        return query.filter(models.Clusters.uuid == value)


def add_storage_backend_filter(query, value):
    """Adds a storage_backend filter to a query.

    Filters results by backend, if supplied value is a valid
    backend. Otherwise attempts to filter results by identity.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    if value in constants.SB_SUPPORTED:
        return query.filter(or_(models.StorageCeph.backend == value,
                                models.StorageCephExternal.backend == value,
                                models.StorageFile.backend == value,
                                models.StorageLvm.backend == value,
                                models.StorageExternal.backend == value))
    elif uuidutils.is_uuid_like(value):
        return query.filter(or_(models.StorageCeph.uuid == value,
                                models.StorageCephExternal.uuid == value,
                                models.StorageFile.uuid == value,
                                models.StorageLvm.uuid == value,
                                models.StorageExternal.uuid == value))
    else:
        return add_identity_filter(query, value)


def add_storage_backend_name_filter(query, value):
    """ Add a name based storage_backend filter to a query. """
    return query.filter(or_(models.StorageCeph.name == value,
                            models.StorageCephExternal.name == value,
                            models.StorageFile.name == value,
                            models.StorageLvm.name == value,
                            models.StorageExternal.name == value))


# SENSOR FILTERS
def add_sensorgroup_filter(query, value):
    """Adds a sensorgroup-specific filter to a query.

    Filters results by mac, if supplied value is a valid MAC
    address. Otherwise attempts to filter results by identity.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    if uuidutils.is_uuid_like(value):
        return query.filter(or_(models.SensorGroupsAnalog.uuid == value,
                                models.SensorGroupsDiscrete.uuid == value))
    elif utils.is_int_like(value):
        return query.filter(or_(models.SensorGroupsAnalog.id == value,
                                models.SensorGroupsDiscrete.id == value))
    else:
        return add_identity_filter(query, value, use_sensorgroupname=True)


def add_sensorgroup_filter_by_sensor(query, value):
    """Adds an sensorgroup-specific filter to a query.

    Filters results by sensor id if supplied value is an integer.
    Filters results by sensor UUID if supplied value is a UUID.
    Otherwise attempts to filter results by name

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    query = query.join(models.Sensors)
    if utils.is_int_like(value):
        return query.filter(models.Sensors.id == value)
    elif uuidutils.is_uuid_like(value):
        return query.filter(models.Sensors.uuid == value)
    else:
        return query.filter(models.Sensors.name == value)


def add_sensorgroup_filter_by_ihost(query, value):
    """Adds an sensorgroup-specific filter to a query.

    Filters results by hostid, if supplied value is an integer.
    Otherwise attempts to filter results by UUID.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    if utils.is_int_like(value):
        return query.filter_by(host_id=value)
    else:
        query = query.join(models.ihost,
                           models.SensorGroups.host_id == models.ihost.id)
        return query.filter(models.ihost.uuid == value)


def add_sensor_filter(query, value):
    """Adds a sensor-specific filter to a query.

    Filters results by identity.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    return add_identity_filter(query, value, use_sensorname=True)


def add_sensor_analog_filter(query, value):
    """Adds a sensor-specific filter to a query.

    Filters results by analog criteria, if supplied value is valid.
    Otherwise attempts to filter results by identity.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    return add_identity_filter(query, value, use_sensorname=True)


def add_sensor_discrete_filter(query, value):
    """Adds a sensor-specific filter to a query.

    Filters results by discrete criteria, if supplied value is valid.
    Otherwise attempts to filter results by identity.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    # if utils.is_valid_mac(value):
    #     return query.filter_by(mac=value)
    return add_identity_filter(query, value, use_sensorname=True)


def add_sensor_filter_by_ihost(query, hostid):
    """Adds a sensor-specific ihost filter to a query.

    Filters results by host id if supplied value is an integer,
    otherwise attempts to filter results by host uuid.

    :param query: Initial query to add filter to.
    :param hostid: host id or uuid to filter results by.
    :return: Modified query.
    """
    if utils.is_int_like(hostid):
        #
        # Should not need join due to polymorphic sensors table
        # query = query.join(models.sensors,
        #                    models.SensorsAnalog.id == models.sensors.id)
        #
        # Query of analog_sensors table should return data from
        # corresponding sensors table entry so should be able to
        # use filter_by() rather than filter()
        #
        return query.filter_by(host_id=hostid)

    elif utils.is_uuid_like(hostid):
        #
        # Should be able to join on foreign key without specifying
        # explicit join condition since only a single foreign key
        # between tables.
        # query = (query.join(models.ihost,
        #                 models.SensorsAnalog.host_id == models.ihost.id))
        #
        query = query.join(models.ihost)
        return query.filter(models.ihost.uuid == hostid)

    LOG.debug("sensor_filter_by_host: "
              "No match for supplied filter id (%s)" % str(hostid))


def add_sensor_filter_by_sensorgroup(query, sensorgroupid):
    """Adds a sensor-specific sensorgroup filter to a query.

    Filters results by sensorgroup id if supplied value is an integer,
    otherwise attempts to filter results by sensorgroup uuid.

    :param query: Initial query to add filter to.
    :param sensorgroupid: sensorgroup id or uuid to filter results by.
    :return: Modified query.
    """
    if utils.is_int_like(sensorgroupid):
        #
        # Should not need join due to polymorphic sensors table
        # query = query.join(models.isensorgroups,
        #                    models.SensorsAnalog.sensorgroup_id == models.isensorgroups.id)
        #
        # Query of analog_sensors table should return data from
        # corresponding sensors table entry so should be able to
        # use filter_by() rather than filter()
        return query.filter_by(sensorgroup_id=sensorgroupid)

    elif utils.is_uuid_like(sensorgroupid):
        #
        # Should be able to join on foreign key without specifying
        # explicit join condition since only a single foreign key
        # between tables.
        # query = query.join(models.isensorgroups,
        #                    models.SensorsAnalog.sensorgroup_id == models.isensorgroups.id)
        #
        # query = query.join(models.SensorGroups)
        #                   models.Sensors.sensorgroup_id == models.SensorGroups.id)
        query = query.join(models.SensorGroups,
                           models.Sensors.sensorgroup_id == models.SensorGroups.id)

        return query.filter(models.SensorGroups.uuid == sensorgroupid)

    LOG.warn("sensor_filter_by_sensorgroup: "
              "No match for supplied filter id (%s)" % str(sensorgroupid))


def add_sensor_filter_by_ihost_sensorgroup(query, hostid, sensorgroupid):
    """Adds a sensor-specific host and sensorgroup filter to a query.

    Filters results by host id and sensorgroup id if supplied hostid and
    sensorgroupid are integers, otherwise attempts to filter results by
    host uuid and sensorgroup uuid.

    :param query: Initial query to add filter to.
    :param hostid: host id or uuid to filter results by.
    :param sensorgroupid: sensorgroup id or uuid to filter results by.
    :return: Modified query.
    """
    if utils.is_int_like(hostid) and utils.is_int_like(sensorgroupid):
        return query.filter_by(host_id=hostid, sensorgroup_id=sensorgroupid)

    elif utils.is_uuid_like(hostid) and utils.is_uuid_like(sensorgroupid):
        query = query.join(models.ihost,
                           models.SensorGroups)
        return query.filter(models.ihost.uuid == hostid,
                            models.SensorGroups.uuid == sensorgroupid)

    LOG.debug("sensor_filter_by_host_isensorgroup: "
              "No match for supplied filter ids (%s, %s)"
              % (str(hostid), str(sensorgroupid)))


def add_lldp_filter_by_host(query, hostid):
    """Adds a lldp-specific ihost filter to a query.

    Filters results by host id if supplied value is an integer,
    otherwise attempts to filter results by host uuid.

    :param query: Initial query to add filter to.
    :param hostid: host id or uuid to filter results by.
    :return: Modified query.
    """
    if utils.is_int_like(hostid):
        return query.filter_by(host_id=hostid)
    elif utils.is_uuid_like(hostid):
        query = query.join(models.ihost)
        return query.filter(models.ihost.uuid == hostid)

    LOG.debug("lldp_filter_by_host: "
              "No match for supplied filter id (%s)" % str(hostid))


def add_lldp_filter_by_port(query, portid):
    """Adds a lldp-specific port filter to a query.

    Filters results by port id if supplied value is an integer,
    otherwise attempts to filter results by port uuid.

    :param query: Initial query to add filter to.
    :param portid: port id or uuid to filter results by.
    :return: Modified query.
    """
    if utils.is_int_like(portid):
        return query.filter_by(port_id=portid)
    elif utils.is_uuid_like(portid):
        query = query.join(models.Ports)
        return query.filter(models.Ports.uuid == portid)


def add_lldp_filter_by_agent(query, value):
    """Adds an lldp-specific filter to a query.

    Filters results by agent id if supplied value is an integer.
    Filters results by agent UUID if supplied value is a UUID.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    if utils.is_int_like(value):
        return query.filter(models.LldpAgents.id == value)
    elif uuidutils.is_uuid_like(value):
        return query.filter(models.LldpAgents.uuid == value)


def add_lldp_filter_by_neighbour(query, value):
    """Adds an lldp-specific filter to a query.

    Filters results by neighbour id if supplied value is an integer.
    Filters results by neighbour UUID if supplied value is a UUID.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    if utils.is_int_like(value):
        return query.filter(models.LldpNeighbours.id == value)
    elif uuidutils.is_uuid_like(value):
        return query.filter(models.LldpNeighbours.uuid == value)


def add_lldp_tlv_filter_by_neighbour(query, neighbourid):
    """Adds an lldp-specific filter to a query.

    Filters results by neighbour id if supplied value is an integer.
    Filters results by neighbour UUID if supplied value is a UUID.

    :param query: Initial query to add filter to.
    :param neighbourid: Value for filtering results by.
    :return: Modified query.
    """
    if utils.is_int_like(neighbourid):
        return query.filter_by(neighbour_id=neighbourid)
    elif uuidutils.is_uuid_like(neighbourid):
        query = query.join(
            models.LldpNeighbours,
            models.LldpTlvs.neighbour_id == models.LldpNeighbours.id)
        return query.filter(models.LldpNeighbours.uuid == neighbourid)


def add_lldp_tlv_filter_by_agent(query, agentid):
    """Adds an lldp-specific filter to a query.

    Filters results by agent id if supplied value is an integer.
    Filters results by agent UUID if supplied value is a UUID.

    :param query: Initial query to add filter to.
    :param agentid: Value for filtering results by.
    :return: Modified query.
    """
    if utils.is_int_like(agentid):
        return query.filter_by(agent_id=agentid)
    elif uuidutils.is_uuid_like(agentid):
        query = query.join(models.LldpAgents,
                           models.LldpTlvs.agent_id == models.LldpAgents.id)
        return query.filter(models.LldpAgents.uuid == agentid)


def add_label_filter_by_host(query, hostid):
    """Adds a label-specific ihost filter to a query.

    Filters results by host id if supplied value is an integer,
    otherwise attempts to filter results by host uuid.

    :param query: Initial query to add filter to.
    :param hostid: host id or uuid to filter results by.
    :return: Modified query.
    """
    if utils.is_int_like(hostid):
        return query.filter_by(host_id=hostid)

    elif utils.is_uuid_like(hostid):
        query = query.join(models.ihost)
        return query.filter(models.ihost.uuid == hostid)


def add_host_fs_filter(query, value):
    """Adds an fs-specific filter to a query.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    return add_identity_filter(query, value, use_fsname=True)


def add_kube_host_upgrade_filter_by_host(query, value):
    if utils.is_int_like(value):
        return query.filter_by(host_id=value)
    else:
        query = query.join(models.ihost,
                           models.KubeHostUpgrade.host_id == models.ihost.id)
        return query.filter(models.ihost.uuid == value)


def add_kube_rootca_host_update_filter_by_host(query, value):
    if utils.is_int_like(value):
        return query.filter_by(host_id=value)
    else:
        query = query.join(models.ihost,
                            models.KubeRootCAHostUpdate.host_id == models.ihost.id)
        return query.filter(models.ihost.uuid == value)


def add_kube_host_upgrade_filter(query, value):
    """Adds an upgrade-specific filter to a query.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """
    return add_identity_filter(query, value)


def add_host_fs_filter_by_ihost(query, value):
    if utils.is_int_like(value):
        return query.filter_by(forihostid=value)
    else:
        query = query.join(models.ihost,
                           models.HostFs.forihostid == models.ihost.id)
        return query.filter(models.ihost.uuid == value)


def add_deviceimage_filter(query, value):
    """Adds a deviceimage-specific filter to a query.

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :return: Modified query.
    """

    if uuidutils.is_uuid_like(value):
        return query.filter(or_(models.DeviceImageRootKey.uuid == value,
                                models.DeviceImageFunctional.uuid == value,
                                models.DeviceImageKeyRevocation.uuid == value))
    elif utils.is_int_like(value):
        return query.filter(or_(models.DeviceImageRootKey.id == value,
                                models.DeviceImageFunctional.id == value,
                                models.DeviceImageKeyRevocation.id == value))
    else:
        return add_identity_filter(query, value, use_name=True)


class Connection(api.Connection):
    """SqlAlchemy connection."""

    def __init__(self):
        pass

    def get_session(self, autocommit=True):
        return get_session(autocommit)

    @objects.objectify(objects.system)
    def isystem_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        if not values.get('software_version'):
            values['software_version'] = utils.get_sw_version()
        isystem = models.isystem()
        isystem.update(values)
        with _session_for_write() as session:
            try:
                session.add(isystem)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.SystemAlreadyExists(uuid=values['uuid'])
            return isystem

    @objects.objectify(objects.system)
    def isystem_get(self, server):
        query = model_query(models.isystem)
        query = add_identity_filter(query, server)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=server)

        return result

    @objects.objectify(objects.system)
    def isystem_get_one(self):
        query = model_query(models.isystem)

        try:
            return query.one()
        except NoResultFound:
            raise exception.NotFound()

    @objects.objectify(objects.system)
    def isystem_get_list(self, limit=None, marker=None,
                         sort_key=None, sort_dir=None):
        query = model_query(models.isystem)

        return _paginate_query(models.isystem, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.system)
    def isystem_get_by_systemname(self, systemname):
        result = model_query(models.isystem, read_deleted="no").\
                             filter_by(name=systemname).\
                             first()

        if not result:
            raise exception.NodeNotFound(node=systemname)

        return result

    @objects.objectify(objects.system)
    def isystem_update(self, server, values):
        with _session_for_write() as session:
            query = model_query(models.isystem, session=session)
            query = add_identity_filter(query, server)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.ServerNotFound(server=server)
            return query.one()

    def isystem_destroy(self, server):
        with _session_for_write() as session:
            query = model_query(models.isystem, session=session)
            query = add_identity_filter(query, server)

            try:
                query.one()
            except NoResultFound:
                raise exception.ServerNotFound(server=server)

            # skip cascade delete to leafs otherwise major issue!
            query.delete()

    def _host_get(self, server):
        query = model_query(models.ihost)
        query = add_host_options(query)
        query = add_identity_filter(query, server)
        try:
            return query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=server)

    @objects.objectify(objects.host)
    def ihost_create(self, values, software_load=None):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        host = models.ihost()
        host.update(values)
        with _session_for_write() as session:
            try:
                session.add(host)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.NodeAlreadyExists(uuid=values['uuid'])
            self._host_upgrade_create(host.id, software_load)
            self._kube_host_upgrade_create(host.id)
            return self._host_get(values['uuid'])

    @objects.objectify(objects.host)
    def ihost_get(self, server):
        return self._host_get(server)

    @objects.objectify(objects.host)
    def ihost_get_list(self, limit=None, marker=None,
                       sort_key=None, sort_dir=None, recordtype="standard"):
        query = model_query(models.ihost)
        query = add_host_options(query)
        if recordtype:
            query = query.filter_by(recordtype=recordtype)

        return _paginate_query(models.ihost, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.host)
    def ihost_get_by_hostname(self, hostname):
        query = model_query(models.ihost)
        query = add_host_options(query)
        query = query.filter_by(hostname=hostname)

        try:
            return query.one()
        except NoResultFound:
            raise exception.NodeNotFound(node=hostname)

    @objects.objectify(objects.host)
    def ihost_get_by_isystem(self, isystem_id, limit=None, marker=None,
                             sort_key=None, sort_dir=None):
        query = model_query(models.ihost)
        query = add_host_options(query)
        query = query.filter_by(forisystemid=isystem_id)
        return _paginate_query(models.ihost, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.host)
    def ihost_get_by_personality(self, personality,
                                 limit=None, marker=None,
                                 sort_key=None, sort_dir=None):
        query = model_query(models.ihost)
        query = add_host_options(query)
        query = query.filter_by(personality=personality, recordtype="standard")
        return _paginate_query(models.ihost, limit, marker,
                               sort_key, sort_dir, query)

    def count_hosts_matching_criteria(
            self, personality=None, administrative=None,
            operational=None, availability=None, vim_progress_status=None,
            reboot_needed=None):
        query = model_query(models.ihost)
        query = add_host_options(query)
        query = query.filter_by(recordtype="standard")
        if personality:
            if isinstance(personality, list):
                query = query.filter(models.ihost.personality.in_(personality))
            else:
                query = query.filter_by(personality=personality)
        if administrative:
            if isinstance(administrative, list):
                query = query.filter(models.ihost.administrative.in_(administrative))
            else:
                query = query.filter_by(administrative=administrative)
        if operational:
            if isinstance(operational, list):
                query = query.filter(models.ihost.operational.in_(operational))
            else:
                query = query.filter_by(operational=operational)
        if availability:
            if isinstance(availability, list):
                query = query.filter(models.ihost.availability.in_(availability))
            else:
                query = query.filter_by(availability=availability)
        if vim_progress_status:
            if isinstance(vim_progress_status, list):
                query = query.filter(
                    models.ihost.vim_progress_status.in_(vim_progress_status))
            else:
                query = query.filter_by(vim_progress_status=vim_progress_status)
        if reboot_needed:
            if isinstance(reboot_needed, list):
                query = query.filter(
                    models.ihost.reboot_needed.in_(reboot_needed))
            else:
                query = query.filter_by(reboot_needed=reboot_needed)
        return query.count()

    @objects.objectify(objects.host)
    def ihost_get_by_function(self, function,
                              limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        query = model_query(models.ihost)
        query = add_host_options(query)
        query = query.filter_by(recordtype="standard").filter(
            function in models.ihost.subfunctions)
        return _paginate_query(models.ihost, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.host)
    def ihost_get_by_mgmt_mac(self, mgmt_mac):

        try:
            mgmt_mac = mgmt_mac.rstrip()
            mgmt_mac = utils.validate_and_normalize_mac(mgmt_mac)
        except exception.SysinvException:
            raise exception.HostNotFound(node=mgmt_mac)

        query = model_query(models.ihost)
        query = add_host_options(query)
        query = query.filter_by(mgmt_mac=mgmt_mac)

        try:
            return query.one()
        except NoResultFound:
            raise exception.NodeNotFound(node=mgmt_mac)

    @objects.objectify(objects.host)
    def ihost_update(self, server, values, context=None):
        with _session_for_write() as session:
            query = model_query(models.ihost, session=session)
            query = add_identity_filter(query, server)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.ServerNotFound(server=server)
        return self._host_get(server)

    def ihost_destroy(self, server):
        with _session_for_write() as session:
            query = model_query(models.ihost, session=session)
            query = add_identity_filter(query, server)

            try:
                node_ref = query.one()
            except NoResultFound:
                raise exception.ServerNotFound(server=server)
            # if node_ref['reservation'] is not None:
            #     raise exception.NodeLocked(node=node)

            # Get node ID, if an UUID was supplied. The ID is
            # required for deleting all ports, attached to the node.
            # if uuidutils.is_uuid_like(server):
            server_id = node_ref['id']
            # else:
            #     server_id = server

            # cascade delete to leafs
            model_query(models.icpu, read_deleted="no").\
                filter_by(forihostid=server_id).\
                delete()
            model_query(models.imemory, read_deleted="no").\
                filter_by(forihostid=server_id).\
                delete()
            model_query(models.idisk, read_deleted="no").\
                filter_by(forihostid=server_id).\
                delete()
            model_query(models.inode, read_deleted="no").\
                filter_by(forihostid=server_id).\
                delete()
            model_query(models.SensorGroups, read_deleted="no").\
                filter_by(host_id=server_id).\
                delete()
            model_query(models.Sensors, read_deleted="no").\
                filter_by(host_id=server_id).\
                delete()

            query.delete()

    def interface_profile_get_list(self, limit=None, marker=None,
                                   sort_key=None, sort_dir=None, session=None):

        ports = with_polymorphic(models.Ports, '*', flat=True)
        interfaces = with_polymorphic(models.Interfaces, '*', flat=True)

        query = model_query(models.ihost, session=session).\
            filter_by(recordtype="profile"). \
            join(models.ihost.ports). \
            options(subqueryload(models.ihost.ports.of_type(ports)),
                    subqueryload(models.ihost.interfaces.of_type(interfaces)))

        return _paginate_query(models.ihost, limit, marker,
                               sort_key, sort_dir, query)

    def cpu_profile_get_list(self, limit=None, marker=None,
                             sort_key=None, sort_dir=None, session=None):

        query = model_query(models.ihost, session=session).\
            filter_by(recordtype="profile"). \
            join(models.ihost.cpus). \
            options(subqueryload(models.ihost.cpus),
                    subqueryload(models.ihost.nodes))

        return _paginate_query(models.ihost, limit, marker,
                               sort_key, sort_dir, query)

    def memory_profile_get_list(self, limit=None, marker=None,
                                sort_key=None, sort_dir=None, session=None):

        query = model_query(models.ihost, session=session).\
            filter_by(recordtype="profile"). \
            join(models.ihost.memory). \
            options(subqueryload(models.ihost.memory),
                    subqueryload(models.ihost.nodes))

        return _paginate_query(models.ihost, limit, marker,
                               sort_key, sort_dir, query)

    def storage_profile_get_list(self, limit=None, marker=None,
                                 sort_key=None, sort_dir=None, session=None):

        query = model_query(models.ihost, session=session).\
            filter_by(recordtype="profile").\
            join(models.ihost.disks).\
            outerjoin(models.ihost.partitions).\
            outerjoin(models.ihost.stors).\
            outerjoin(models.ihost.pvs).\
            outerjoin(models.ihost.lvgs)

        return _paginate_query(models.ihost, limit, marker,
                               sort_key, sort_dir, query)

    def _node_get(self, inode_id):
        query = model_query(models.inode)
        query = add_identity_filter(query, inode_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=inode_id)

        return result

    @objects.objectify(objects.node)
    def inode_create(self, forihostid, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        values['forihostid'] = int(forihostid)
        inode = models.inode()
        inode.update(values)
        with _session_for_write() as session:
            try:
                session.add(inode)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.NodeAlreadyExists(uuid=values['uuid'])

            return self._node_get(values['uuid'])

    @objects.objectify(objects.node)
    def inode_get_all(self, forihostid=None):
        query = model_query(models.inode, read_deleted="no")
        if forihostid:
            query = query.filter_by(forihostid=forihostid)
        return query.all()

    @objects.objectify(objects.node)
    def inode_get(self, inode_id):
        return self._node_get(inode_id)

    @objects.objectify(objects.node)
    def inode_get_list(self, limit=None, marker=None,
                       sort_key=None, sort_dir=None):
        return _paginate_query(models.inode, limit, marker,
                               sort_key, sort_dir)

    @objects.objectify(objects.node)
    def inode_get_by_ihost(self, ihost,
                           limit=None, marker=None,
                           sort_key=None, sort_dir=None):

        query = model_query(models.inode)
        query = add_inode_filter_by_ihost(query, ihost)
        return _paginate_query(models.inode, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.node)
    def inode_update(self, inode_id, values):
        with _session_for_write() as session:
            # May need to reserve in multi controller system; ref sysinv
            query = model_query(models.inode, read_deleted="no",
                                session=session)
            query = add_identity_filter(query, inode_id)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.ServerNotFound(server=inode_id)
            return query.one()

    def inode_destroy(self, inode_id):
        with _session_for_write() as session:
            # Delete physically since it has unique columns
            if uuidutils.is_uuid_like(inode_id):
                model_query(models.inode, read_deleted="no",
                            session=session).\
                    filter_by(uuid=inode_id).\
                    delete()
            else:
                model_query(models.inode, read_deleted="no").\
                    filter_by(id=inode_id).\
                    delete()

    def _cpu_get(self, cpu_id, forihostid=None):
        query = model_query(models.icpu)

        if forihostid:
            query = query.filter_by(forihostid=forihostid)

        query = add_identity_filter(query, cpu_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=cpu_id)

        return result

    @objects.objectify(objects.cpu)
    def icpu_create(self, forihostid, values):

        if utils.is_int_like(forihostid):
            values['forihostid'] = int(forihostid)
        else:
            # this is not necessary if already integer following not work
            ihost = self.ihost_get(forihostid.strip())
            values['forihostid'] = ihost['id']

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        cpu = models.icpu()
        cpu.update(values)

        with _session_for_write() as session:
            try:
                session.add(cpu)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.CPUAlreadyExists(cpu=values['cpu'])
            return self._cpu_get(values['uuid'])

    @objects.objectify(objects.cpu)
    def icpu_get_all(self, forihostid=None, forinodeid=None):
        query = model_query(models.icpu, read_deleted="no")
        if forihostid:
            query = query.filter_by(forihostid=forihostid)
        if forinodeid:
            query = query.filter_by(forinodeid=forinodeid)
        return query.all()

    @objects.objectify(objects.cpu)
    def icpu_get(self, cpu_id, forihostid=None):
        return self._cpu_get(cpu_id, forihostid)

    @objects.objectify(objects.cpu)
    def icpu_get_list(self, limit=None, marker=None,
                      sort_key=None, sort_dir=None):
        return _paginate_query(models.icpu, limit, marker,
                               sort_key, sort_dir)

    @objects.objectify(objects.cpu)
    def icpu_get_by_ihost(self, ihost,
                          limit=None, marker=None,
                          sort_key=None, sort_dir=None):

        query = model_query(models.icpu)
        query = add_icpu_filter_by_ihost(query, ihost)
        return _paginate_query(models.icpu, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.cpu)
    def icpu_get_by_inode(self, inode,
                          limit=None, marker=None,
                          sort_key=None, sort_dir=None):

        query = model_query(models.icpu)
        query = add_icpu_filter_by_inode(query, inode)
        return _paginate_query(models.icpu, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.cpu)
    def icpu_get_by_ihost_inode(self, ihost, inode,
                                limit=None, marker=None,
                                sort_key=None, sort_dir=None):

        query = model_query(models.icpu)
        query = add_icpu_filter_by_ihost_inode(query, ihost, inode)
        return _paginate_query(models.icpu, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.cpu)
    def icpu_update(self, cpu_id, values, forihostid=None):
        with _session_for_write() as session:
            # May need to reserve in multi controller system; ref sysinv
            query = model_query(models.icpu, read_deleted="no",
                                session=session)
            if forihostid:
                query = query.filter_by(forihostid=forihostid)

            query = add_identity_filter(query, cpu_id)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.ServerNotFound(server=cpu_id)
            return query.one()

    def icpu_destroy(self, cpu_id):
        with _session_for_write() as session:
            # Delete physically since it has unique columns
            if uuidutils.is_uuid_like(cpu_id):
                model_query(models.icpu, read_deleted="no",
                            session=session).\
                            filter_by(uuid=cpu_id).\
                            delete()
            else:
                model_query(models.icpu, read_deleted="no").\
                            filter_by(id=cpu_id).\
                            delete()

    def _memory_get(self, memory_id, forihostid=None):
        query = model_query(models.imemory)

        if forihostid:
            query = query.filter_by(forihostid=forihostid)

        query = add_identity_filter(query, memory_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=memory_id)

        return result

    @objects.objectify(objects.memory)
    def imemory_create(self, forihostid, values):
        if utils.is_int_like(forihostid):
            values['forihostid'] = int(forihostid)
        else:
            # this is not necessary if already integer following not work
            ihost = self.ihost_get(forihostid.strip())
            values['forihostid'] = ihost['id']

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        values.pop('numa_node', None)

        memory = models.imemory()
        memory.update(values)
        with _session_for_write() as session:
            try:
                session.add(memory)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.MemoryAlreadyExists(uuid=values['uuid'])
            return self._memory_get(values['uuid'])

    @objects.objectify(objects.memory)
    def imemory_get_all(self, forihostid=None, forinodeid=None):
        query = model_query(models.imemory, read_deleted="no")
        if forihostid:
            query = query.filter_by(forihostid=forihostid)
        if forinodeid:
            query = query.filter_by(forinodeid=forinodeid)
        return query.all()

    @objects.objectify(objects.memory)
    def imemory_get(self, memory_id, forihostid=None):
        return self._memory_get(memory_id, forihostid)

    @objects.objectify(objects.memory)
    def imemory_get_list(self, limit=None, marker=None,
                      sort_key=None, sort_dir=None):
        return _paginate_query(models.imemory, limit, marker,
                               sort_key, sort_dir)

    @objects.objectify(objects.memory)
    def imemory_get_by_ihost(self, ihost,
                          limit=None, marker=None,
                          sort_key=None, sort_dir=None):

        query = model_query(models.imemory)
        query = add_imemory_filter_by_ihost(query, ihost)
        return _paginate_query(models.imemory, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.memory)
    def imemory_get_by_inode(self, inode,
                             limit=None, marker=None,
                             sort_key=None, sort_dir=None):

        query = model_query(models.imemory)
        query = add_imemory_filter_by_inode(query, inode)
        return _paginate_query(models.imemory, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.memory)
    def imemory_get_by_ihost_inode(self, ihost, inode,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):

        query = model_query(models.imemory)
        query = add_imemory_filter_by_ihost_inode(query, ihost, inode)
        return _paginate_query(models.imemory, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.memory)
    def imemory_update(self, memory_id, values, forihostid=None):
        with _session_for_write() as session:
            # May need to reserve in multi controller system; ref sysinv
            query = model_query(models.imemory, read_deleted="no",
                                session=session)
            if forihostid:
                query = query.filter_by(forihostid=forihostid)

            query = add_identity_filter(query, memory_id)

            values.pop('numa_node', None)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.ServerNotFound(server=memory_id)
            return query.one()

    def imemory_destroy(self, memory_id):
        with _session_for_write() as session:
            # Delete physically since it has unique columns
            if uuidutils.is_uuid_like(memory_id):
                model_query(models.imemory, read_deleted="no",
                            session=session).\
                            filter_by(uuid=memory_id).\
                            delete()
            else:
                model_query(models.imemory, read_deleted="no",
                            session=session).\
                            filter_by(id=memory_id).\
                            delete()

    @objects.objectify(objects.fpga_device)
    def fpga_device_create(self, hostid, values):

        if utils.is_int_like(hostid):
            host = self.ihost_get(int(hostid))
        elif utils.is_uuid_like(hostid):
            host = self.ihost_get(hostid.strip())
        elif isinstance(hostid, models.ihost):
            host = hostid
        else:
            raise exception.NodeNotFound(node=hostid)

        values['host_id'] = host['id']

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        fpga_device = models.FpgaDevice()
        fpga_device.update(values)
        with _session_for_write() as session:
            try:
                session.add(fpga_device)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add FPGA device (uuid: %s), FPGA device with PCI "
                          "address %s on host %s already exists" %
                          (values['uuid'],
                           values['pciaddr'],
                           values['host_id']))
                raise exception.PCIAddrAlreadyExists(pciaddr=values['pciaddr'],
                                                     host=values['host_id'])
            return self._fpga_device_get(values['pciaddr'], values['host_id'])

    def _fpga_device_get(self, pciaddr, hostid=None):
        query = model_query(models.FpgaDevice)
        if hostid:
            query = query.filter_by(host_id=hostid)
        query = add_identity_filter(query, pciaddr, use_pciaddr=True)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.PCIAddrNotFound(pciaddr=pciaddr)

        return result

    @objects.objectify(objects.fpga_device)
    def fpga_device_get(self, deviceid, hostid=None):
        return self._fpga_device_get(deviceid, hostid)

    @objects.objectify(objects.fpga_device)
    def fpga_device_update(self, device_id, values, forihostid=None):
        with _session_for_write() as session:
            # May need to reserve in multi controller system; ref sysinv
            query = model_query(models.FpgaDevice, read_deleted="no",
                                session=session)

            if forihostid:
                query = query.filter_by(host_id=forihostid)

            try:
                query = add_identity_filter(query, device_id)
                result = query.one()
                for k, v in values.items():
                    setattr(result, k, v)
            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for device %s" % device_id)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for device %s" % device_id)

            return query.one()

    @objects.objectify(objects.fpga_device)
    def fpga_device_get_by_host(self, host, limit=None, marker=None,
                               sort_key=None, sort_dir=None):
        query = model_query(models.FpgaDevice)
        query = add_device_filter_by_host(query, host)
        return _paginate_query(models.FpgaDevice, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.pci_device)
    def pci_device_create(self, hostid, values):

        if utils.is_int_like(hostid):
            host = self.ihost_get(int(hostid))
        elif utils.is_uuid_like(hostid):
            host = self.ihost_get(hostid.strip())
        elif isinstance(hostid, models.ihost):
            host = hostid
        else:
            raise exception.NodeNotFound(node=hostid)

        values['host_id'] = host['id']

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        pci_device = models.PciDevice()
        pci_device.update(values)
        with _session_for_write() as session:
            try:
                session.add(pci_device)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add pci device %s:%s (uuid: %s), device with PCI "
                          "address %s on host %s already exists" %
                          (values['vendor'],
                           values['device'],
                           values['uuid'],
                           values['pciaddr'],
                           values['host_id']))
                raise exception.PCIAddrAlreadyExists(pciaddr=values['pciaddr'],
                                                     host=values['host_id'])
            return self._pci_device_get(values['pciaddr'], values['host_id'])

    @objects.objectify(objects.pci_device)
    def pci_device_get_all(self, hostid=None):
        query = model_query(models.PciDevice, read_deleted="no")
        if hostid:
            query = query.filter_by(host_id=hostid)
        return query.all()

    def _pci_device_get(self, deviceid, hostid=None):
        query = model_query(models.PciDevice)
        if hostid:
            query = query.filter_by(host_id=hostid)
        query = add_identity_filter(query, deviceid, use_pciaddr=True)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=deviceid)

        return result

    @objects.objectify(objects.pci_device)
    def pci_device_get(self, deviceid, hostid=None):
        return self._pci_device_get(deviceid, hostid)

    @objects.objectify(objects.pci_device)
    def pci_device_get_list(self, limit=None, marker=None,
                           sort_key=None, sort_dir=None):
        return _paginate_query(models.PciDevice, limit, marker,
                               sort_key, sort_dir)

    @objects.objectify(objects.pci_device)
    def pci_device_get_by_host(self, host, limit=None, marker=None,
                               sort_key=None, sort_dir=None):
        query = model_query(models.PciDevice)
        query = add_device_filter_by_host(query, host)
        return _paginate_query(models.PciDevice, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.pci_device)
    def pci_device_update(self, device_id, values, forihostid=None):
        with _session_for_write() as session:
            # May need to reserve in multi controller system; ref sysinv
            query = model_query(models.PciDevice, read_deleted="no",
                                session=session)

            if forihostid:
                query = query.filter_by(host_id=forihostid)

            try:
                query = add_identity_filter(query, device_id)
                result = query.one()
                for k, v in values.items():
                    setattr(result, k, v)
            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for device %s" % device_id)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for device %s" % device_id)

            return query.one()

    def pci_device_destroy(self, device_id):
        with _session_for_write() as session:
            if uuidutils.is_uuid_like(device_id):
                model_query(models.PciDevice, read_deleted="no",
                            session=session).\
                    filter_by(uuid=device_id).\
                    delete()
            else:
                model_query(models.PciDevice, read_deleted="no",
                            session=session).\
                    filter_by(id=device_id).\
                    delete()

    def _port_get(self, portid, hostid=None):
        query = model_query(models.Ports)

        if hostid:
            query = query.filter_by(host_id=hostid)

        query = add_identity_filter(query, portid, use_name=True)

        try:
            return query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=portid)

    @objects.objectify(objects.port)
    def port_get(self, portid, hostid=None):
        return self._port_get(portid, hostid)

    @objects.objectify(objects.port)
    def port_get_list(self, limit=None, marker=None,
                      sort_key=None, sort_dir=None):
        return _paginate_query(models.Ports, limit, marker,
                               sort_key, sort_dir)

    @objects.objectify(objects.port)
    def port_get_all(self, hostid=None, interfaceid=None):
        query = model_query(models.Ports, read_deleted="no")
        if hostid:
            query = query.filter_by(host_id=hostid)
        if interfaceid:
            query = query.filter_by(interface_id=interfaceid)
        return query.all()

    @objects.objectify(objects.port)
    def port_get_by_host(self, host,
                         limit=None, marker=None,
                         sort_key=None, sort_dir=None):
        query = model_query(models.Ports)
        query = add_port_filter_by_host(query, host)
        return _paginate_query(models.Ports, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.port)
    def port_get_by_interface(self, interface,
                              limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        query = model_query(models.Ports)
        query = add_port_filter_by_interface(query, interface)
        return _paginate_query(models.Ports, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.port)
    def port_get_by_host_interface(self, host, interface,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        query = model_query(models.Ports)
        query = add_port_filter_by_host_interface(query, host, interface)
        return _paginate_query(models.Ports, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.port)
    def port_get_by_numa_node(self, node,
                              limit=None, marker=None,
                              sort_key=None, sort_dir=None):

        query = model_query(models.Ports)
        query = add_port_filter_by_numa_node(query, node)
        return _paginate_query(models.Ports, limit, marker,
                               sort_key, sort_dir, query)

    def _ethernet_port_get(self, portid, hostid=None):
        query = model_query(models.EthernetPorts)

        if hostid:
            query = query.filter_by(host_id=hostid)

        query = add_identity_filter(query, portid, use_name=True)

        try:
            return query.one()
        except NoResultFound:
            raise exception.PortNotFound(port=portid)

    @objects.objectify(objects.ethernet_port)
    def ethernet_port_create(self, hostid, values):
        if utils.is_int_like(hostid):
            host = self.ihost_get(int(hostid))
        elif utils.is_uuid_like(hostid):
            host = self.ihost_get(hostid.strip())
        elif isinstance(hostid, models.ihost):
            host = hostid
        else:
            raise exception.NodeNotFound(node=hostid)

        values['host_id'] = host['id']

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        ethernet_port = models.EthernetPorts()
        ethernet_port.update(values)
        with _session_for_write() as session:
            try:
                session.add(ethernet_port)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add port %s (uuid: %s), port with MAC "
                          "address %s on host %s already exists" %
                          (values['name'],
                           values['uuid'],
                           values['mac'],
                           values['host_id']))
                raise exception.MACAlreadyExists(mac=values['mac'],
                                                 host=values['host_id'])

            return self._ethernet_port_get(values['uuid'])

    @objects.objectify(objects.ethernet_port)
    def ethernet_port_get(self, portid, hostid=None):
        return self._ethernet_port_get(portid, hostid)

    @objects.objectify(objects.ethernet_port)
    def ethernet_port_get_by_mac(self, mac):
        query = model_query(models.EthernetPorts).filter_by(mac=mac)
        try:
            return query.one()
        except NoResultFound:
            raise exception.PortNotFound(port=mac)

    @objects.objectify(objects.ethernet_port)
    def ethernet_port_get_list(self, limit=None, marker=None,
                               sort_key=None, sort_dir=None):
        return _paginate_query(models.EthernetPorts, limit, marker,
                               sort_key, sort_dir)

    @objects.objectify(objects.ethernet_port)
    def ethernet_port_get_all(self, hostid=None, interfaceid=None):
        query = model_query(models.EthernetPorts, read_deleted="no")
        if hostid:
            query = query.filter_by(host_id=hostid)
        if interfaceid:
            query = query.filter_by(interface_id=interfaceid)
        return query.all()

    @objects.objectify(objects.ethernet_port)
    def ethernet_port_get_by_host(self, host,
                                  limit=None, marker=None,
                                  sort_key=None, sort_dir=None):
        query = model_query(models.EthernetPorts)
        query = add_port_filter_by_host(query, host)
        return _paginate_query(models.EthernetPorts, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.ethernet_port)
    def ethernet_port_get_by_interface(self, interface,
                                       limit=None, marker=None,
                                       sort_key=None, sort_dir=None):
        query = model_query(models.EthernetPorts)
        query = add_port_filter_by_interface(query, interface)
        return _paginate_query(models.EthernetPorts, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.ethernet_port)
    def ethernet_port_get_by_numa_node(self, node,
                                       limit=None, marker=None,
                                       sort_key=None, sort_dir=None):
        query = model_query(models.EthernetPorts)
        query = add_port_filter_by_numa_node(query, node)
        return _paginate_query(models.EthernetPorts, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.ethernet_port)
    def ethernet_port_update(self, portid, values):
        with _session_for_write() as session:
            # May need to reserve in multi controller system; ref sysinv
            query = model_query(models.EthernetPorts, read_deleted="no",
                                session=session)
            query = add_identity_filter(query, portid)

            try:
                result = query.one()
                for k, v in values.items():
                    setattr(result, k, v)
            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for port %s" % portid)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for port %s" % portid)

            return query.one()

    def ethernet_port_destroy(self, portid):
        with _session_for_write() as session:
            # Delete port which should cascade to delete EthernetPort
            if uuidutils.is_uuid_like(portid):
                model_query(models.Ports, read_deleted="no",
                            session=session).\
                    filter_by(uuid=portid).\
                    delete()
            else:
                model_query(models.Ports, read_deleted="no",
                            session=session).\
                    filter_by(id=portid).\
                    delete()

    @objects.objectify(objects.interface)
    def iinterface_create(self, forihostid, values):
        if values['iftype'] == constants.INTERFACE_TYPE_AE:
            interface = models.AeInterfaces()
        elif values['iftype'] == constants.INTERFACE_TYPE_VLAN:
            interface = models.VlanInterfaces()
        elif values['iftype'] == constants.INTERFACE_TYPE_VIRTUAL:
            interface = models.VirtualInterfaces()
        elif values['iftype'] == constants.INTERFACE_TYPE_VF:
            interface = models.SriovVFInterfaces()
        else:
            interface = models.EthernetInterfaces()
        return self._interface_create(interface, forihostid, values)

    def iinterface_get_all(self, forihostid=None, expunge=False):
        try:
            with _session_for_read() as session:
                interfaces = self._iinterface_get_all(forihostid,
                                                      session=session)
                if expunge:
                    session.expunge_all()
        except DetachedInstanceError:
            # A rare DetachedInstanceError exception may occur, retry
            LOG.warn("Detached Instance Error,  retry "
                     "iinterface_get_all %s" % forihostid)
            interfaces = self._iinterface_get_all(forihostid)

        return interfaces

    @objects.objectify(objects.interface)
    def _iinterface_get_all(self, forihostid=None, session=None):
        interfaces = with_polymorphic(models.Interfaces, '*')
        query = model_query(interfaces, read_deleted="no", session=session)
        if forihostid:
            query = (query.join(models.ihost,
                                models.ihost.id == models.Interfaces.forihostid))
            query = query.options(contains_eager(interfaces.host))
            query, field = add_filter_by_many_identities(
                            query, models.ihost, [forihostid])
        return query.all()

    def _iinterface_get(self, iinterface_id, ihost=None):
        entity = with_polymorphic(models.Interfaces, '*')
        query = model_query(entity)
        query = add_interface_filter(query, iinterface_id)
        if ihost is not None:
            query = add_interface_filter_by_ihost(query, ihost)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                err="No entry found for interface %s" % iinterface_id)
        except MultipleResultsFound:
            raise exception.InvalidParameterValue(
                err="Multiple entries found for interface %s" % iinterface_id)

        return result

    @objects.objectify(objects.interface)
    def iinterface_get(self, iinterface_id, ihost=None, network=None):
        return self._iinterface_get(iinterface_id, ihost)

    @objects.objectify(objects.interface)
    def iinterface_get_list(self, limit=None, marker=None,
                      sort_key=None, sort_dir=None):

        entity = with_polymorphic(models.Interfaces, '*')
        query = model_query(entity)
        return _paginate_query(models.Interfaces, limit, marker,
                               sort_key, sort_dir, query)

    def iinterface_get_by_ihost(self, ihost, expunge=False,
                                limit=None, marker=None,
                                sort_key=None, sort_dir=None):
        try:
            with _session_for_read() as session:
                interfaces = self._iinterface_get_by_ihost(ihost, session=session,
                                                           limit=limit,
                                                           marker=marker,
                                                           sort_key=sort_key,
                                                           sort_dir=sort_dir)
                if expunge:
                    session.expunge_all()
        except DetachedInstanceError:
            # A rare DetachedInstanceError exception may occur, retry
            LOG.warn("Detached Instance Error,  retry "
                     "iinterface_get_by_ihost %s" % ihost)
            interfaces = self._iinterface_get_by_ihost(ihost, session=None,
                                                       limit=limit,
                                                       marker=marker,
                                                       sort_key=sort_key,
                                                       sort_dir=sort_dir)
        return interfaces

    @objects.objectify(objects.interface)
    def _iinterface_get_by_ihost(self, ihost, session=None,
                                limit=None, marker=None,
                                sort_key=None, sort_dir=None):
        interfaces = with_polymorphic(models.Interfaces, '*')
        query = model_query(interfaces, session=session)
        query = (query.join(models.ihost,
                            models.ihost.id == models.Interfaces.forihostid))
        query = query.options(contains_eager(interfaces.host))
        query, field = add_filter_by_many_identities(
                            query, models.ihost, [ihost])

        return _paginate_query(models.Interfaces, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.interface)
    def iinterface_update(self, iinterface_id, values):
        self._interface_ratelimit_encode(values)
        with _session_for_write() as session:
            query = model_query(models.Interfaces, read_deleted="no",
                                session=session)
            query = add_interface_filter(query, iinterface_id)
            try:
                result = query.one()
            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for interface %s" % iinterface_id)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for interface %s" % iinterface_id)

            if result.iftype == constants.INTERFACE_TYPE_AE:
                return self._interface_update(models.AeInterfaces, iinterface_id, values)
            elif result.iftype == constants.INTERFACE_TYPE_VLAN:
                return self._interface_update(models.VlanInterfaces, iinterface_id, values)
            elif result.iftype == constants.INTERFACE_TYPE_VF:
                return self._interface_update(models.SriovVFInterfaces, iinterface_id, values)
            else:
                return self._interface_update(models.EthernetInterfaces, iinterface_id, values)

    def iinterface_destroy(self, iinterface_id):
        return self._interface_destroy(models.Interfaces, iinterface_id)

    def _interface_ratelimit_encode(self, values):
        # we need to use 'ifcapabilities' dict to save ratelimit info
        if values.get('max_tx_rate') is not None:
            capabilities = {'max_tx_rate': values['max_tx_rate']}
            if values.get('ifcapabilities') is not None:
                values['ifcapabilities'].update(capabilities)
            else:
                values['ifcapabilities'] = capabilities

    def _interface_create(self, obj, forihostid, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        values['forihostid'] = int(forihostid)

        self._interface_ratelimit_encode(values)

        is_profile = values.get('interface_profile', False)
        with _session_for_write() as session:

            # interface = models.Interfaces()
            if hasattr(obj, 'uses') and values.get('uses'):
                for i in list(values['uses']):
                    try:
                        if is_profile:
                            uses_if = self._interface_get(models.Interfaces, i, obj=obj)
                        else:
                            uses_if = self._interface_get(models.Interfaces, i, values['forihostid'], obj=obj)
                        obj.uses.append(uses_if)
                    except NoResultFound:
                        raise exception.InvalidParameterValue(
                            err="No entry found for host %s interface %s" % (values['forihostid'], i))
                    except MultipleResultsFound:
                        raise exception.InvalidParameterValue(
                            err="Multiple entries found for host %s interface %s" % (values['forihostid'], i))
                values.pop('uses')

            if hasattr(obj, 'used_by') and values.get('used_by'):
                for i in list(values['used_by']):
                    try:
                        if is_profile:
                            uses_if = self._interface_get(models.Interfaces, i, obj=obj)
                        else:
                            uses_if = self._interface_get(models.Interfaces, i, values['forihostid'], obj=obj)
                        obj.used_by.append(uses_if)
                    except NoResultFound:
                        raise exception.InvalidParameterValue(
                            err="No entry found for host %s interface %s" % (values['forihostid'], i))
                    except MultipleResultsFound:
                        raise exception.InvalidParameterValue(
                            err="Multiple entries found for host %s interface %s" % (values['forihostid'], i))
                values.pop('used_by')

            # The id is null for ae interfaces with more than one member interface
            temp_id = obj.id
            obj.update(values)
            if obj.id is None:
                obj.id = temp_id

            try:
                session.add(obj)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add interface %s (uuid: %s), an interface "
                          "with name %s already exists on host %s" %
                          (values['ifname'],
                           values['uuid'],
                           values['ifname'],
                           values['forihostid']))

                raise exception.InterfaceNameAlreadyExists(
                    name=values['ifname'])

        return self._interface_get(type(obj), values['uuid'])

    def _interface_get_all(self, cls, forihostid=None):
        query = model_query(cls, read_deleted="no")
        if utils.is_int_like(forihostid):
            query = query.filter_by(forihostid=forihostid)
        return query.all()

    def _interface_get(self, cls, interface_id, ihost=None, obj=None):
        session = None
        if obj:
            session = inspect(obj).session
        query = model_query(cls, session=session)
        if ihost:
            query = add_interface_filter_by_ihost(query, ihost)
        query = add_interface_filter(query, interface_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                err="No entry found for interface %s" % interface_id)
        except MultipleResultsFound:
            raise exception.InvalidParameterValue(
                    err="Multiple entries found for interface %s" % interface_id)

        return result

    def _interface_get_list(self, cls, limit=None, marker=None,
                           sort_key=None, sort_dir=None):
        return _paginate_query(cls, limit, marker, sort_key, sort_dir)

    def _interface_get_by_ihost_port(self, cls, ihost, port,
                                     limit=None, marker=None,
                                     sort_key=None, sort_dir=None):

        query = model_query(cls).join(models.Ports)
        query = add_interface_filter_by_ihost(query, ihost)
        query = add_interface_filter_by_port(query, port)
        return _paginate_query(cls, limit, marker, sort_key, sort_dir, query)

    def _interface_get_by_ihost(self, cls, ihost,
                               limit=None, marker=None,
                               sort_key=None, sort_dir=None):
        query = model_query(cls)
        query = add_interface_filter_by_ihost(query, ihost)
        return _paginate_query(cls, limit, marker, sort_key, sort_dir, query)

    def _interface_update(self, cls, interface_id, values):
        with _session_for_write() as session:
            entity = with_polymorphic(models.Interfaces, '*')
            query = model_query(entity)
            # query = model_query(cls, read_deleted="no")
            try:
                query = add_interface_filter(query, interface_id)
                result = query.one()

                obj = self._interface_get(models.Interfaces, interface_id)

                for k, v in list(values.items()):
                    if k == 'datanetworks' and v == 'none':
                        v = None
                    if k == 'uses':
                        del obj.uses[:]
                        for i in list(values['uses']):
                            try:
                                uses_if = self._interface_get(models.Interfaces, i, obj=obj)
                                obj.uses.append(uses_if)
                            except NoResultFound:
                                raise exception.InvalidParameterValue(
                                    err="No entry found for interface %s" % i)
                            except MultipleResultsFound:
                                raise exception.InvalidParameterValue(
                                    err="Multiple entries found for interface %s" % i)

                        del values['uses']
                        continue
                    if k == 'used_by':
                        del obj.used_by[:]
                        for i in list(values['used_by']):
                            try:
                                used_by = self._interface_get(models.Interfaces, i, obj=obj)
                                obj.used_by.append(used_by)
                            except NoResultFound:
                                raise exception.InvalidParameterValue(
                                    err="No entry found for interface %s" % i)
                            except MultipleResultsFound:
                                raise exception.InvalidParameterValue(
                                    err="Multiple entries found for interface %s" % i)

                        del values['used_by']
                        continue
                    setattr(result, k, v)

            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for interface %s" % interface_id)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for interface %s" % interface_id)

            try:
                session.add(obj)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to update interface")

            return query.one()

    def _interface_destroy(self, cls, interface_id):
        with _session_for_write() as session:
            # Delete interface which should cascade to delete derived interfaces
            if uuidutils.is_uuid_like(interface_id):
                model_query(cls, read_deleted="no",
                            session=session).\
                    filter_by(uuid=interface_id).\
                    delete()
            else:
                model_query(cls, read_deleted="no").\
                    filter_by(id=interface_id).\
                    delete()

    @objects.objectify(objects.ethernet_interface)
    def ethernet_interface_create(self, forihostid, values):
        interface = models.EthernetInterfaces()
        return self._interface_create(interface, forihostid, values)

    @objects.objectify(objects.ethernet_interface)
    def ethernet_interface_get_all(self, forihostid=None):
        return self._interface_get_all(models.EthernetInterfaces, forihostid)

    @objects.objectify(objects.ethernet_interface)
    def ethernet_interface_get(self, interface_id):
        return self._interface_get(models.EthernetInterfaces, interface_id)

    @objects.objectify(objects.ethernet_interface)
    def ethernet_interface_get_list(self, limit=None, marker=None,
                           sort_key=None, sort_dir=None):
        return self._interface_get_list(models.EthernetInterfaces, limit, marker,
                                        sort_key, sort_dir)

    @objects.objectify(objects.ethernet_interface)
    def ethernet_interface_get_by_ihost(self, ihost,
                               limit=None, marker=None,
                               sort_key=None, sort_dir=None):
        return self._interface_get_by_ihost(models.EthernetInterfaces, ihost, limit,
                                            marker, sort_key, sort_dir)

    @objects.objectify(objects.ethernet_interface)
    def ethernet_interface_update(self, interface_id, values):
        return self._interface_update(models.EthernetInterfaces, interface_id,
                                      values)

    def ethernet_interface_destroy(self, interface_id):
        return self._interface_destroy(models.EthernetInterfaces, interface_id)

    @objects.objectify(objects.ae_interface)
    def ae_interface_create(self, forihostid, values):
        interface = models.AeInterfaces()
        return self._interface_create(interface, forihostid, values)

    @objects.objectify(objects.ae_interface)
    def ae_interface_get_all(self, forihostid=None):
        return self._interface_get_all(models.AeInterfaces, forihostid)

    @objects.objectify(objects.ae_interface)
    def ae_interface_get(self, interface_id):
        return self._interface_get(models.AeInterfaces, interface_id)

    @objects.objectify(objects.ae_interface)
    def ae_interface_get_list(self, limit=None, marker=None,
                           sort_key=None, sort_dir=None):
        return self._interface_get_list(models.AeInterfaces, limit, marker,
                                        sort_key, sort_dir)

    @objects.objectify(objects.ae_interface)
    def ae_interface_get_by_ihost(self, ihost,
                               limit=None, marker=None,
                               sort_key=None, sort_dir=None):
        return self._interface_get_by_ihost(models.AeInterfaces, ihost, limit,
                                            marker, sort_key, sort_dir)

    @objects.objectify(objects.ae_interface)
    def ae_interface_update(self, interface_id, values):
        return self._interface_update(models.AeInterfaces, interface_id, values)

    def ae_interface_destroy(self, interface_id):
        return self._interface_destroy(models.AeInterfaces, interface_id)

    @objects.objectify(objects.vlan_interface)
    def vlan_interface_create(self, forihostid, values):
        interface = models.VlanInterfaces()
        return self._interface_create(interface, forihostid, values)

    @objects.objectify(objects.vlan_interface)
    def vlan_interface_get_all(self, forihostid=None):
        return self._interface_get_all(models.VlanInterfaces, forihostid)

    @objects.objectify(objects.vlan_interface)
    def vlan_interface_get(self, interface_id):
        return self._interface_get(models.VlanInterfaces, interface_id)

    @objects.objectify(objects.vlan_interface)
    def vlan_interface_get_list(self, limit=None, marker=None,
                           sort_key=None, sort_dir=None):
        return self._interface_get_list(models.VlanInterfaces, limit, marker,
                                        sort_key, sort_dir)

    @objects.objectify(objects.vlan_interface)
    def vlan_interface_get_by_ihost(self, ihost,
                               limit=None, marker=None,
                               sort_key=None, sort_dir=None):
        return self._interface_get_by_ihost(models.VlanInterfaces, ihost, limit,
                                            marker, sort_key, sort_dir)

    @objects.objectify(objects.vlan_interface)
    def vlan_interface_update(self, interface_id, values):
        return self._interface_update(models.VlanInterfaces, interface_id, values)

    def vlan_interface_destroy(self, interface_id):
        return self._interface_destroy(models.VlanInterfaces, interface_id)

    @objects.objectify(objects.virtual_interface)
    def virtual_interface_create(self, forihostid, values):
        interface = models.VirtualInterfaces()
        return self._interface_create(interface, forihostid, values)

    @objects.objectify(objects.virtual_interface)
    def virtual_interface_get_all(self, forihostid=None):
        return self._interface_get_all(models.EthernetInterfaces, forihostid)

    @objects.objectify(objects.virtual_interface)
    def virtual_interface_get(self, interface_id):
        return self._interface_get(models.VirtualInterfaces, interface_id)

    @objects.objectify(objects.virtual_interface)
    def virtual_interface_get_list(self, limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        return self._interface_get_list(models.VirtualInterfaces, limit,
                                        marker, sort_key, sort_dir)

    @objects.objectify(objects.virtual_interface)
    def virtual_interface_get_by_ihost(self, ihost,
                                       limit=None, marker=None,
                                       sort_key=None, sort_dir=None):
        return self._interface_get_by_ihost(models.VirtualInterfaces, ihost,
                                            limit, marker, sort_key, sort_dir)

    @objects.objectify(objects.virtual_interface)
    def virtual_interface_update(self, interface_id, values):
        return self._interface_update(models.VirtualInterfaces, interface_id,
                                      values)

    def virtual_interface_destroy(self, interface_id):
        return self._interface_destroy(models.VirtualInterfaces, interface_id)

    @objects.objectify(objects.sriov_vf_interface)
    def sriov_vf_interface_create(self, forihostid, values):
        interface = models.SriovVFInterfaces()
        return self._interface_create(interface, forihostid, values)

    @objects.objectify(objects.sriov_vf_interface)
    def sriov_vf_interface_get_all(self, forihostid=None):
        return self._interface_get_all(models.SriovVFInterfaces, forihostid)

    @objects.objectify(objects.sriov_vf_interface)
    def sriov_vf_interface_get(self, interface_id):
        return self._interface_get(models.SriovVFInterfaces, interface_id)

    @objects.objectify(objects.sriov_vf_interface)
    def sriov_vf_interface_get_list(self, limit=None, marker=None,
                                    sort_key=None, sort_dir=None):
        return self._interface_get_list(models.SriovVFInterfaces, limit, marker,
                                        sort_key, sort_dir)

    @objects.objectify(objects.sriov_vf_interface)
    def sriov_vf_interface_get_by_ihost(self, ihost,
                                        limit=None, marker=None,
                                        sort_key=None, sort_dir=None):
        return self._interface_get_by_ihost(models.SriovVFInterfaces, ihost, limit,
                                            marker, sort_key, sort_dir)

    @objects.objectify(objects.sriov_vf_interface)
    def sriov_vf_interface_update(self, interface_id, values):
        return self._interface_update(models.SriovVFInterfaces, interface_id, values)

    def sriov_vf_interface_destroy(self, interface_id):
        return self._interface_destroy(models.SriovVFInterfaces, interface_id)

    def _disk_get(self, disk_id, forihostid=None):
        query = model_query(models.idisk)

        if forihostid:
            query = query.filter_by(forihostid=forihostid)

        query = add_identity_filter(query, disk_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.DiskNotFound(disk_id=disk_id)

        return result

    @objects.objectify(objects.disk)
    def idisk_create(self, forihostid, values):

        if utils.is_int_like(forihostid):
            values['forihostid'] = int(forihostid)
        else:
            # this is not necessary if already integer following not work
            ihost = self.ihost_get(forihostid.strip())
            values['forihostid'] = ihost['id']

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        disk = models.idisk()
        disk.update(values)

        with _session_for_write() as session:
            try:
                session.add(disk)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.DiskAlreadyExists(uuid=values['uuid'])

            return self._disk_get(values['uuid'])

    @objects.objectify(objects.disk)
    def idisk_get_all(self, forihostid=None, foristorid=None, foripvid=None):
        query = model_query(models.idisk, read_deleted="no")
        if forihostid:
            query = query.filter_by(forihostid=forihostid)
        if foristorid:
            query = query.filter_by(foristorid=foristorid)
        if foripvid:
            query = query.filter_by(foripvid=foripvid)
        return query.all()

    @objects.objectify(objects.disk)
    def idisk_get(self, disk_id, forihostid=None):
        return self._disk_get(disk_id, forihostid)

    @objects.objectify(objects.disk)
    def idisk_get_list(self, limit=None, marker=None,
                      sort_key=None, sort_dir=None):
        return _paginate_query(models.idisk, limit, marker,
                               sort_key, sort_dir)

    @objects.objectify(objects.disk)
    def idisk_get_by_ihost(self, ihost,
                          limit=None, marker=None,
                          sort_key=None, sort_dir=None):

        query = model_query(models.idisk)
        query = add_idisk_filter_by_ihost(query, ihost)
        return _paginate_query(models.idisk, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.disk)
    def idisk_get_by_istor(self, istor_uuid,
                           limit=None, marker=None,
                           sort_key=None, sort_dir=None):

        query = model_query(models.idisk)
        query = add_idisk_filter_by_istor(query, istor_uuid)
        return _paginate_query(models.idisk, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.disk)
    def idisk_get_by_ihost_istor(self, ihost, istor,
                                 limit=None, marker=None,
                                 sort_key=None, sort_dir=None):

        query = model_query(models.idisk)
        query = add_idisk_filter_by_ihost_istor(query, ihost, istor)
        return _paginate_query(models.idisk, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.disk)
    def idisk_get_by_ipv(self, ipv,
                         limit=None, marker=None,
                         sort_key=None, sort_dir=None):

        query = model_query(models.idisk)
        query = add_idisk_filter_by_ipv(query, ipv)
        return _paginate_query(models.idisk, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.disk)
    def idisk_get_by_device_id(self, device_id,
                               limit=None, marker=None,
                               sort_key=None, sort_dir=None):

        query = model_query(models.idisk)
        query = add_idisk_filter_by_device_id(query, device_id)
        return _paginate_query(models.idisk, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.disk)
    def idisk_get_by_device_path(self, device_path,
                                 limit=None, marker=None,
                                 sort_key=None, sort_dir=None):

        query = model_query(models.idisk)
        query = add_idisk_filter_by_device_path(query, device_path)
        return _paginate_query(models.idisk, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.disk)
    def idisk_get_by_device_wwn(self, device_wwn,
                               limit=None, marker=None,
                               sort_key=None, sort_dir=None):

        query = model_query(models.idisk)
        query = add_idisk_filter_by_device_wwn(query, device_wwn)
        return _paginate_query(models.idisk, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.disk)
    def idisk_get_by_ihost_ipv(self, ihost, ipv,
                               limit=None, marker=None,
                               sort_key=None, sort_dir=None):

        query = model_query(models.idisk)
        query = add_idisk_filter_by_ihost_ipv(query, ihost, ipv)
        return _paginate_query(models.idisk, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.disk)
    def idisk_update(self, disk_id, values, forihostid=None):
        with _session_for_write() as session:
            # May need to reserve in multi controller system; ref sysinv
            query = model_query(models.idisk, read_deleted="no",
                                session=session)
            if forihostid:
                query = query.filter_by(forihostid=forihostid)

            query = add_identity_filter(query, disk_id)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.DiskNotFound(disk_id=disk_id)
            return query.one()

    def idisk_destroy(self, disk_id):
        with _session_for_write() as session:
            # Delete physically since it has unique columns
            if uuidutils.is_uuid_like(disk_id):
                model_query(models.idisk, read_deleted="no",
                            session=session).\
                            filter_by(uuid=disk_id).\
                            delete()
            else:
                model_query(models.idisk, read_deleted="no",
                            session=session).\
                            filter_by(id=disk_id).\
                            delete()

    def _partition_get(self, partition_id, forihostid=None):
        query = model_query(models.partition)

        if forihostid:
            query = query.filter_by(forihostid=forihostid)

        query = add_identity_filter(query, partition_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.DiskPartitionNotFound(partition_id=partition_id)

        return result

    @objects.objectify(objects.partition)
    def partition_get_all(self, forihostid=None, foripvid=None):
        query = model_query(models.partition, read_deleted="no")
        if forihostid:
            query = query.filter_by(forihostid=forihostid)
        if foripvid:
            query = query.filter_by(foripvid=foripvid)
        return query.all()

    @objects.objectify(objects.partition)
    def partition_get(self, partition_id, forihostid=None):
        return self._partition_get(partition_id, forihostid)

    @objects.objectify(objects.partition)
    def partition_get_by_ihost(self, ihost,
                           limit=None, marker=None,
                           sort_key=None, sort_dir=None):

        query = model_query(models.partition)
        query = add_partition_filter_by_ihost(query, ihost)
        return _paginate_query(models.partition, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.partition)
    def partition_get_by_idisk(self, idisk,
                               limit=None, marker=None,
                               sort_key=None, sort_dir=None):

        query = model_query(models.partition)
        query = add_partition_filter_by_idisk(query, idisk)
        return _paginate_query(models.partition, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.partition)
    def partition_get_by_ipv(self, ipv,
                             limit=None, marker=None,
                             sort_key=None, sort_dir=None):

        query = model_query(models.partition)
        query = add_partition_filter_by_ipv(query, ipv)
        return _paginate_query(models.partition, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.partition)
    def partition_create(self, forihostid, values):

        if utils.is_int_like(forihostid):
            values['forihostid'] = int(forihostid)
        else:
            # this is not necessary if already integer following not work
            ihost = self.ihost_get(forihostid.strip())
            values['forihostid'] = ihost['id']

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        partition = models.partition()
        partition.update(values)

        with _session_for_write() as session:
            try:
                session.add(partition)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.PartitionAlreadyExists(device_path=values['device_path'])

            return self._partition_get(values['uuid'])

    @objects.objectify(objects.partition)
    def partition_update(self, partition_id, values, forihostid=None):
        with _session_for_write():
            query = model_query(models.partition, read_deleted="no")
            if forihostid:
                query = query.filter_by(forihostid=forihostid)

            query = add_identity_filter(query, partition_id)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.DiskPartitionNotFound(partition_id=partition_id)
            return query.one()

    def partition_destroy(self, partition_id):
        with _session_for_write():
            # Delete physically since it has unique columns
            if uuidutils.is_uuid_like(partition_id):
                model_query(models.partition, read_deleted="no"). \
                    filter_by(uuid=partition_id). \
                    delete()
            else:
                model_query(models.partition, read_deleted="no"). \
                    filter_by(id=partition_id). \
                    delete()

    @objects.objectify(objects.journal)
    def journal_create(self, foristorid, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        values['foristorid'] = int(foristorid)

        journal = models.journal()
        journal.update(values)

        with _session_for_write() as session:
            try:
                session.add(journal)
                session.flush()
            except Exception:
                raise

            return journal

    @objects.objectify(objects.journal)
    def journal_update(self, journal_id, values):
        with _session_for_write() as session:
            # May need to reserve in multi controller system; ref sysinv
            query = model_query(models.journal, read_deleted="no",
                                session=session)
            query = add_identity_filter(query, journal_id)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.ServerNotFound(server=journal_id)
            return query.one()

    def journal_update_path(self, disk):
        forihostid = disk.forihostid
        istors = self.istor_get_by_ihost(forihostid)

        if not istors:
            return

        for stor in istors:
            if stor.idisk_uuid == disk.uuid:
                # Update the journal device path.
                journals = self.journal_get_all(stor.uuid)
                for journal in journals:
                    partition_number = re.match('.*?([0-9]+)$',
                                                journal.device_path).group(1)
                    device_path = "{}{}{}".format(disk['device_path'],
                                                  "-part",
                                                  partition_number)
                    updates = {'device_path': device_path}
                    self.journal_update(journal['uuid'], updates)

    def journal_update_dev_nodes(self, journal_stor_uuid):
        """ Update the journal nodes, in order with the correct device node """

        # Get journal data
        journals = self.journal_get_all(journal_stor_uuid)
        journals = sorted(journals, key=lambda journal: journal["foristorid"])
        journal_stor = self.istor_get(journal_stor_uuid)
        journal_disk = self.idisk_get_by_istor(journal_stor_uuid)[0]

        if journal_stor.function != constants.STOR_FUNCTION_JOURNAL:
            # This exception should not occur as it will break the setup!
            raise exception.NotFound((
                "Storage device with uuid %s is not a journal"
                % journal_stor.function))

        # Update the device nodes
        partition_index = 1
        for journal in journals:
            # Update DB
            journal_path = journal_disk.device_path
            updates = {'device_path': journal_path + "-part" +
                                      str(partition_index)}
            self.journal_update(journal.id, updates)
            partition_index += 1
            # Update output

    @objects.objectify(objects.journal)
    def journal_get_all(self, onistor_uuid=None):
        query = model_query(models.journal, read_deleted="no")
        if onistor_uuid:
            query = query.filter_by(onistor_uuid=onistor_uuid)
        return query.all()

    @objects.objectify(objects.journal)
    def journal_get(self, journal_id):
        query = model_query(models.journal)
        query = add_identity_filter(query, journal_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=journal_id)

        return result

    @objects.objectify(objects.journal)
    def journal_get_by_istor_id(self, istor_id,
                                limit=None, marker=None,
                                sort_key=None, sort_dir=None):
        query = model_query(models.journal)
        query = add_journal_filter_by_foristor(query, istor_id)
        return _paginate_query(models.journal, limit, marker,
                               sort_key, sort_dir, query)

    def istor_disable_journal(self, istor_id):
        """Move all journals from external journal drive to OSD."""

        # Get all the journals that are on our istor.
        journal_stor = self.istor_get(istor_id)
        query = model_query(models.journal)
        query = query.filter_by(onistor_uuid=journal_stor.uuid)
        journals = _paginate_query(models.journal, query=query)

        # Update device nodes.
        for journal in journals:
            stor = self.istor_get(journal.foristorid)
            disk = self.idisk_get_by_istor(stor.uuid)[0]
            journal_vals = {'onistor_uuid': stor.uuid,
                            'device_path': disk.device_path + "-part" + "2",
                            'size_mib': CONF.journal.journal_default_size}
            self.journal_update(journal.id, journal_vals)

    def _stor_get(self, istor_id):
        query = model_query(models.istor)
        query = add_identity_filter(query, istor_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=istor_id)

        return result

    @objects.objectify(objects.storage)
    def istor_create(self, forihostid, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        values['forihostid'] = int(forihostid)
        stor = models.istor()
        stor.update(values)

        with _session_for_write() as session:
            try:
                session.add(stor)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.StorAlreadyExists(uuid=values['uuid'])

            return self._stor_get(values['uuid'])

    @objects.objectify(objects.storage)
    def istor_get_all(self, forihostid=None):
        query = model_query(models.istor, read_deleted="no")
        if forihostid:
            query = query.filter_by(forihostid=forihostid)
        return query.all()

    @objects.objectify(objects.storage)
    def istor_get(self, istor_id):
        return self._stor_get(istor_id)

    @objects.objectify(objects.storage)
    def istor_get_list(self, limit=None, marker=None,
                       sort_key=None, sort_dir=None):
        return _paginate_query(models.istor, limit, marker,
                               sort_key, sort_dir)

    @objects.objectify(objects.storage)
    def istor_get_by_ihost(self, ihost,
                           limit=None, marker=None,
                           sort_key=None, sort_dir=None):

        query = model_query(models.istor)
        query = add_istor_filter_by_ihost(query, ihost)
        return _paginate_query(models.istor, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.storage)
    def istor_get_by_tier(self, tier,
                          limit=None, marker=None,
                          sort_key=None, sort_dir=None):

        query = model_query(models.istor)
        query = add_istor_filter_by_tier(query, tier)
        return _paginate_query(models.istor, limit, marker,
                               sort_key, sort_dir, query)

    def _istor_update_journal(self, istor_obj, values):
        """Update the journal location of an istor."""

        obj = self.journal_get_by_istor_id(istor_obj['id'])
        if not obj:
            # This object does not have an associated journal.
            return values
        obj = obj[0]

        journal_vals = {}
        for key, value in list(values.items()):
            if key == 'journal_location':
                # Obtain the new journal location
                new_onistor = self.istor_get(value)
                new_onidisk = self.idisk_get(new_onistor.idisk_uuid)
                journal_vals['onistor_uuid'] = new_onistor.uuid

                # Update device node for journal.
                if value == istor_obj['uuid']:
                    # If the journal becomes collocated, assign second
                    # partition.
                    journal_vals['device_path'] = new_onidisk.device_path + \
                                                  "-part" + "2"

                del values[key]

            if key == 'journal_size_mib':
                journal_vals['size_mib'] = value
                del values[key]

        self.journal_update(obj.id, journal_vals)
        return values

    @objects.objectify(objects.storage)
    def istor_get_by_ihost_function(self, ihost, function,
                           limit=None, marker=None,
                           sort_key=None, sort_dir=None):

        query = model_query(models.istor)
        query = add_istor_filter_by_ihost(query, ihost)
        query = query.filter_by(function=function)

        return _paginate_query(models.istor, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.storage)
    def istor_update(self, istor_id, values):

        # Obtain all istor object.
        istor_obj = self.istor_get(istor_id)

        with _session_for_write() as session:
            # May need to reserve in multi controller system; ref sysinv
            query = model_query(models.istor, read_deleted="no",
                                session=session)
            query = add_istor_filter(query, istor_id)

            values = self._istor_update_journal(istor_obj, values)
            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.ServerNotFound(server=istor_id)
            return query.one()

    def istor_remove_disk_association(self, stor_uuid):
        """ Remove association from the disk to this stor """

        idisks = self.idisk_get_by_istor(stor_uuid)
        for disk in idisks:
            values = {'foristorid': None}
            self.idisk_update(disk['uuid'], values)

    def istor_destroy(self, istor_id):
        with _session_for_write() as session:
            # Delete physically since it has unique columns
            if uuidutils.is_uuid_like(istor_id):
                model_query(models.istor, read_deleted="no",
                            session=session).\
                    filter_by(uuid=istor_id).\
                    delete()
            else:
                model_query(models.istor, read_deleted="no",
                            session=session).\
                    filter_by(id=istor_id).\
                    delete()

    def _lvg_get(self, ilvg_id):
        query = model_query(models.ilvg)
        query = add_identity_filter(query, ilvg_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.LvmLvgNotFound(lvg_id=ilvg_id)

        return result

    @objects.objectify(objects.lvg)
    def ilvg_create(self, forihostid, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        values['forihostid'] = int(forihostid)
        iLvg = models.ilvg()
        iLvg.update(values)
        with _session_for_write() as session:
            try:
                session.add(iLvg)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.LvmLvgAlreadyExists(
                    name=values['lvm_vg_name'], host=forihostid)

            return self._lvg_get(values['uuid'])

    @objects.objectify(objects.lvg)
    def ilvg_get_all(self, forihostid=None):
        query = model_query(models.ilvg, read_deleted="no")
        if forihostid:
            query = query.filter_by(forihostid=forihostid)
        return query.all()

    @objects.objectify(objects.lvg)
    def ilvg_get(self, ilvg_id):
        return self._lvg_get(ilvg_id)

    @objects.objectify(objects.lvg)
    def ilvg_get_list(self, limit=None, marker=None,
                      sort_key=None, sort_dir=None):
        return _paginate_query(models.ilvg, limit, marker,
                               sort_key, sort_dir)

    @objects.objectify(objects.lvg)
    def ilvg_get_by_ihost(self, ihost,
                          limit=None, marker=None,
                          sort_key=None, sort_dir=None):

        query = model_query(models.ilvg)
        query = add_ilvg_filter_by_ihost(query, ihost)
        return _paginate_query(models.ilvg, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.lvg)
    def ilvg_update(self, ilvg_id, values):
        with _session_for_write() as session:
            query = model_query(models.ilvg, read_deleted="no",
                                session=session)
            query = add_ilvg_filter(query, ilvg_id)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.LvmLvgNotFound(lvg_id=ilvg_id)
            return query.one()

    def ilvg_destroy(self, ilvg_id):
        with _session_for_write() as session:
            # Delete physically since it has unique columns
            if uuidutils.is_uuid_like(ilvg_id):
                model_query(models.ilvg, read_deleted="no",
                            session=session).\
                    filter_by(uuid=ilvg_id).\
                    delete()
            else:
                model_query(models.ilvg, read_deleted="no").\
                    filter_by(id=ilvg_id).\
                    delete()

    def _pv_get(self, ipv_id):
        query = model_query(models.ipv)
        query = add_identity_filter(query, ipv_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.LvmPvNotFound(pv_id=ipv_id)

        return result

    @objects.objectify(objects.pv)
    def ipv_create(self, forihostid, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        values['forihostid'] = int(forihostid)
        pv = models.ipv()
        pv.update(values)
        with _session_for_write() as session:
            try:
                session.add(pv)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.LvmPvAlreadyExists(
                    name=values['idisk_device_node'], host=forihostid)

            return self._pv_get(values['uuid'])

    @objects.objectify(objects.pv)
    def ipv_get_all(self, forihostid=None):
        query = model_query(models.ipv, read_deleted="no")
        if forihostid:
            query = query.filter_by(forihostid=forihostid)
        return query.all()

    @objects.objectify(objects.pv)
    def ipv_get(self, ipv_id):
        return self._pv_get(ipv_id)

    @objects.objectify(objects.pv)
    def ipv_get_list(self, limit=None, marker=None,
                     sort_key=None, sort_dir=None):
        return _paginate_query(models.ipv, limit, marker,
                               sort_key, sort_dir)

    @objects.objectify(objects.pv)
    def ipv_get_by_ihost(self, ihost,
                         limit=None, marker=None,
                         sort_key=None, sort_dir=None):

        query = model_query(models.ipv)
        query = add_ipv_filter_by_ihost(query, ihost)
        return _paginate_query(models.ipv, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.pv)
    def ipv_update(self, ipv_id, values):
        with _session_for_write() as session:
            query = model_query(models.ipv, read_deleted="no",
                                session=session)
            query = add_ipv_filter(query, ipv_id)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.LvmPvNotFound(pv_id=ipv_id)
            return query.one()

    def ipv_destroy(self, ipv_id):
        with _session_for_write() as session:
            # Delete physically since it has unique columns
            if uuidutils.is_uuid_like(ipv_id):
                model_query(models.ipv, read_deleted="no",
                            session=session).\
                    filter_by(uuid=ipv_id).\
                    delete()
            else:
                model_query(models.ipv, read_deleted="no",
                            session=session).\
                    filter_by(id=ipv_id).\
                    delete()

    def _user_get(self, server):
        # server may be passed as a string. It may be uuid or Int.
        # server = int(server)
        query = model_query(models.iuser)
        query = add_identity_filter(query, server)

        try:
            return query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=server)

    @objects.objectify(objects.user)
    def iuser_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        user = models.iuser()
        user.update(values)
        with _session_for_write() as session:
            try:
                session.add(user)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.UserAlreadyExists(uuid=values['uuid'])
            return self._user_get(values['uuid'])

    @objects.objectify(objects.user)
    def iuser_get(self, server):
        return self._user_get(server)

    @objects.objectify(objects.user)
    def iuser_get_one(self):
        query = model_query(models.iuser)

        try:
            return query.one()
        except NoResultFound:
            raise exception.NotFound()

    @objects.objectify(objects.user)
    def iuser_get_list(self, limit=None, marker=None,
                       sort_key=None, sort_dir=None):

        query = model_query(models.iuser)

        return _paginate_query(models.iuser, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.user)
    def iuser_get_by_isystem(self, isystem_id, limit=None, marker=None,
                             sort_key=None, sort_dir=None):
        # isystem_get() to raise an exception if the isystem is not found
        isystem_obj = self.isystem_get(isystem_id)
        query = model_query(models.iuser)
        query = query.filter_by(forisystemid=isystem_obj.id)
        return _paginate_query(models.iuser, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.user)
    def iuser_update(self, server, values):
        with _session_for_write() as session:
            query = model_query(models.iuser, session=session)
            query = add_identity_filter(query, server)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.ServerNotFound(server=server)
            return query.one()

    def iuser_destroy(self, server):
        with _session_for_write() as session:
            query = model_query(models.iuser, session=session)
            query = add_identity_filter(query, server)

            try:
                query.one()
            except NoResultFound:
                raise exception.ServerNotFound(server=server)
            # if node_ref['reservation'] is not None:
            #     raise exception.NodeLocked(node=node)

            # Get node ID, if an UUID was supplied. The ID is
            # required for deleting all ports, attached to the node.
            # if uuidutils.is_uuid_like(server):
            #     server_id = node_ref['id']
            # else:
            #     server_id = server

            query.delete()

    def _dns_get(self, server):
        query = model_query(models.idns)
        query = add_identity_filter(query, server)

        try:
            return query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=server)

    @objects.objectify(objects.dns)
    def idns_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        dns = models.idns()
        dns.update(values)
        with _session_for_write() as session:
            try:
                session.add(dns)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.DNSAlreadyExists(uuid=values['uuid'])
            return self._dns_get(values['uuid'])

    @objects.objectify(objects.dns)
    def idns_get(self, server):
        return self._dns_get(server)

    @objects.objectify(objects.dns)
    def idns_get_one(self):
        query = model_query(models.idns)

        try:
            return query.one()
        except NoResultFound:
            raise exception.NotFound()

    @objects.objectify(objects.dns)
    def idns_get_list(self, limit=None, marker=None,
                      sort_key=None, sort_dir=None):

        query = model_query(models.idns)

        return _paginate_query(models.idns, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.dns)
    def idns_get_by_isystem(self, isystem_id, limit=None, marker=None,
                            sort_key=None, sort_dir=None):
        # isystem_get() to raise an exception if the isystem is not found
        isystem_obj = self.isystem_get(isystem_id)
        query = model_query(models.idns)
        query = query.filter_by(forisystemid=isystem_obj.id)
        return _paginate_query(models.idns, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.dns)
    def idns_update(self, server, values):
        with _session_for_write() as session:
            query = model_query(models.idns, session=session)
            query = add_identity_filter(query, server)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.ServerNotFound(server=server)
            return query.one()

    def idns_destroy(self, server):
        with _session_for_write() as session:
            query = model_query(models.idns, session=session)
            query = add_identity_filter(query, server)

            try:
                query.one()
            except NoResultFound:
                raise exception.ServerNotFound(server=server)
            # if node_ref['reservation'] is not None:
            #     raise exception.NodeLocked(node=node)

            # Get node ID, if an UUID was supplied. The ID is
            # required for deleting all ports, attached to the node.
            # if uuidutils.is_uuid_like(server):
            #     server_id = node_ref['id']
            # else:
            #     server_id = server

            query.delete()

    def _ntp_get(self, intp_id):
        query = model_query(models.intp)
        query = add_identity_filter(query, intp_id)

        try:
            return query.one()
        except NoResultFound:
            raise exception.NTPNotFound(intp_id=intp_id)

    @objects.objectify(objects.ntp)
    def intp_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        ntp = models.intp()
        ntp.update(values)
        with _session_for_write() as session:
            try:
                session.add(ntp)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.NTPAlreadyExists(uuid=values['uuid'])
            return self._ntp_get(values['uuid'])

    @objects.objectify(objects.ntp)
    def intp_get(self, server):
        return self._ntp_get(server)

    @objects.objectify(objects.ntp)
    def intp_get_one(self):
        query = model_query(models.intp)

        try:
            return query.one()
        except NoResultFound:
            raise exception.NotFound()

    @objects.objectify(objects.ntp)
    def intp_get_list(self, limit=None, marker=None,
                      sort_key=None, sort_dir=None):

        query = model_query(models.intp)

        return _paginate_query(models.intp, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.ntp)
    def intp_get_by_isystem(self, isystem_id, limit=None, marker=None,
                            sort_key=None, sort_dir=None):
        # isystem_get() to raise an exception if the isystem is not found
        isystem_obj = self.isystem_get(isystem_id)
        query = model_query(models.intp)
        query = query.filter_by(forisystemid=isystem_obj.id)
        return _paginate_query(models.intp, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.ntp)
    def intp_update(self, intp_id, values):
        with _session_for_write() as session:
            query = model_query(models.intp, session=session)
            query = add_identity_filter(query, intp_id)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.NTPNotFound(intp_id=intp_id)
            return query.one()

    def intp_destroy(self, intp_id):
        with _session_for_write() as session:
            query = model_query(models.intp, session=session)
            query = add_identity_filter(query, intp_id)

            try:
                query.one()
            except NoResultFound:
                raise exception.NTPNotFound(intp_id=intp_id)
            # if node_ref['reservation'] is not None:
            #     raise exception.NodeLocked(node=node)

            # Get node ID, if an UUID was supplied. The ID is
            # required for deleting all ports, attached to the node.
            # if uuidutils.is_uuid_like(server):
            #     server_id = node_ref['id']
            # else:
            #     server_id = server

            query.delete()

    def _ptp_get(self, ptp_id):
        query = model_query(models.PTP)
        query = add_identity_filter(query, ptp_id)

        try:
            return query.one()
        except NoResultFound:
            raise exception.PTPNotFound(ptp_id=ptp_id)

    @objects.objectify(objects.ptp)
    def ptp_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        ptp = models.PTP()
        ptp.update(values)
        with _session_for_write() as session:
            try:
                session.add(ptp)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.PTPAlreadyExists(uuid=values['uuid'])
            return self._ptp_get(values['uuid'])

    @objects.objectify(objects.ptp)
    def ptp_get(self, ptp_id):
        return self._ptp_get(ptp_id)

    @objects.objectify(objects.ptp)
    def ptp_get_one(self):
        query = model_query(models.PTP)

        try:
            return query.one()
        except NoResultFound:
            raise exception.NotFound()

    @objects.objectify(objects.ptp)
    def ptp_get_list(self, limit=None, marker=None,
                     sort_key=None, sort_dir=None):

        query = model_query(models.PTP)

        return _paginate_query(models.PTP, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.ptp)
    def ptp_get_by_isystem(self, isystem_id, limit=None, marker=None,
                           sort_key=None, sort_dir=None):
        # isystem_get() to raise an exception if the isystem is not found
        isystem_obj = self.isystem_get(isystem_id)
        query = model_query(models.PTP)
        query = query.filter_by(system_id=isystem_obj.id)
        return _paginate_query(models.PTP, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.ptp)
    def ptp_update(self, ptp_id, values):
        with _session_for_write() as session:
            query = model_query(models.PTP, session=session)
            query = add_identity_filter(query, ptp_id)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.PTPNotFound(ptp_id=ptp_id)
            return query.one()

    def ptp_destroy(self, ptp_id):
        with _session_for_write() as session:
            query = model_query(models.PTP, session=session)
            query = add_identity_filter(query, ptp_id)

            try:
                query.one()
            except NoResultFound:
                raise exception.PTPNotFound(ptp_id=ptp_id)

            query.delete()

    def ptp_fill_empty_system_id(self, system_id):
        values = {'system_id': system_id}
        with _session_for_write() as session:
            query = model_query(models.PTP,
                                session=session)
            query = query.filter_by(system_id=None)
            query.update(values, synchronize_session='fetch')

    # NOTE: method is deprecated and provided for API compatibility.
    # object class will convert Network entity to an iextoam object
    @objects.objectify(objects.oam_network)
    def iextoam_get_one(self):
        return self._network_get_by_type(constants.NETWORK_TYPE_OAM)

    # NOTE: method is deprecated and provided for API compatibility.
    # object class will convert Network entity to an iextoam object
    @objects.objectify(objects.oam_network)
    def iextoam_get_list(self, limit=None, marker=None,
                         sort_key=None, sort_dir=None):
        return self._networks_get_by_type(constants.NETWORK_TYPE_OAM,
                                          limit, marker, sort_key, sort_dir)

    def _controller_fs_get(self, controller_fs_id):
        query = model_query(models.ControllerFs)
        query = add_identity_filter(query, controller_fs_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=controller_fs_id)

        return result

    @objects.objectify(objects.controller_fs)
    def controller_fs_create(self, values):
        if values.get('isystem_uuid'):
            system = self.isystem_get(values.get('isystem_uuid'))
            values['forisystemid'] = system.id
        else:
            system = self.isystem_get_one()
            values['forisystemid'] = system.id

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        controller_fs = models.ControllerFs()
        controller_fs.update(values)

        with _session_for_write() as session:
            try:
                session.add(controller_fs)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.ControllerFSAlreadyExists(uuid=values['uuid'])
            return self._controller_fs_get(values['uuid'])

    @objects.objectify(objects.controller_fs)
    def controller_fs_get(self, controller_fs_id):
        return self._controller_fs_get(controller_fs_id)

    @objects.objectify(objects.controller_fs)
    def controller_fs_get_one(self):
        query = model_query(models.ControllerFs)

        try:
            return query.one()
        except NoResultFound:
            raise exception.NotFound()

    @objects.objectify(objects.controller_fs)
    def controller_fs_get_list(self, limit=None, marker=None,
                               sort_key=None, sort_dir=None):

        query = model_query(models.ControllerFs)

        return _paginate_query(models.ControllerFs, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.controller_fs)
    def controller_fs_get_by_isystem(self, isystem_id, limit=None, marker=None,
                                     sort_key=None, sort_dir=None):
        # isystem_get() to raise an exception if the isystem is not found
        isystem_obj = self.isystem_get(isystem_id)
        query = model_query(models.ControllerFs)
        query = query.filter_by(forisystemid=isystem_obj.id)
        return _paginate_query(models.ControllerFs, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.controller_fs)
    def controller_fs_update(self, controller_fs_id, values):
        with _session_for_write() as session:
            query = model_query(models.ControllerFs, read_deleted="no",
                                session=session)

            try:
                query = add_identity_filter(query, controller_fs_id)
                result = query.one()
                for k, v in values.items():
                    setattr(result, k, v)
            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for controller fs %s" %
                        controller_fs_id)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for controller fs %s" %
                        controller_fs_id)

            return query.one()

    def controller_fs_destroy(self, controller_fs_id):
        with _session_for_write() as session:
            query = model_query(models.ControllerFs, session=session)
            query = add_identity_filter(query, controller_fs_id)

            try:
                query.one()
            except NoResultFound:
                raise exception.ServerNotFound(server=controller_fs_id)
            query.delete()

    def _ceph_mon_get(self, ceph_mon_id):
        query = model_query(models.CephMon)
        query = add_identity_filter(query, ceph_mon_id)

        try:
            return query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=ceph_mon_id)

    @objects.objectify(objects.ceph_mon)
    def ceph_mon_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        ceph_mon = models.CephMon()
        ceph_mon.update(values)
        with _session_for_write() as session:
            try:
                session.add(ceph_mon)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.CephMonAlreadyExists(uuid=values['uuid'])
            return self._ceph_mon_get(values['uuid'])

    @objects.objectify(objects.ceph_mon)
    def ceph_mon_get(self, ceph_mon_id):
        return self._ceph_mon_get(ceph_mon_id)

    @objects.objectify(objects.ceph_mon)
    def ceph_mon_get_list(self, limit=None, marker=None,
                          sort_key=None, sort_dir=None):

        query = model_query(models.CephMon)

        return _paginate_query(models.CephMon, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.ceph_mon)
    def ceph_mon_get_by_ihost(self, ihost_id_or_uuid,
                              limit=None, marker=None,
                              sort_key=None, sort_dir=None):

        query = model_query(models.CephMon)
        query = add_ceph_mon_filter_by_ihost(query, ihost_id_or_uuid)
        return _paginate_query(models.CephMon, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.ceph_mon)
    def ceph_mon_update(self, ceph_mon_id, values):
        with _session_for_write() as session:
            query = model_query(models.CephMon, session=session)
            query = add_identity_filter(query, ceph_mon_id)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.ServerNotFound(server=ceph_mon_id)
            return query.one()

    def ceph_mon_destroy(self, ceph_mon_id):
        with _session_for_write() as session:
            query = model_query(models.CephMon, session=session)
            query = add_identity_filter(query, ceph_mon_id)

            try:
                query.one()
            except NoResultFound:
                raise exception.ServerNotFound(server=ceph_mon_id)
            query.delete()

    # Storage Tiers
    def _storage_tier_get(self, uuid, session=None):
        query = model_query(models.StorageTier, session=session)
        query = add_identity_filter(query, uuid, use_name=True)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.StorageTierNotFound(storage_tier_uuid=uuid)
        return result

    @objects.objectify(objects.storage_tier)
    def storage_tier_get(self, storage_tier_uuid):
        return self._storage_tier_get(storage_tier_uuid)

    @objects.objectify(objects.storage_tier)
    def storage_tier_get_by_cluster(self, cluster,
                                    limit=None, marker=None,
                                    sort_key=None, sort_dir=None):

        query = model_query(models.StorageTier)
        query = add_storage_tier_filter_by_cluster(query, cluster)
        return _paginate_query(models.StorageTier, limit, marker,
                               sort_key, sort_dir, query)

    def _storage_tier_query(self, values, session=None):
        query = model_query(models.StorageTier, session=session)
        query = (query.
                 filter(models.StorageTier.name == values['name']))
        try:
            result = query.one()
        except NoResultFound:
            raise exception.StorageTierNotFoundByName(name=values['name'])
        return result

    @objects.objectify(objects.storage_tier)
    def storage_tier_query(self, values):
        return self._storage_tier_query(values)

    @objects.objectify(objects.storage_tier)
    def storage_tier_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        storage_tier = models.StorageTier()
        storage_tier.update(values)

        with _session_for_write() as session:
            try:
                session.add(storage_tier)
                session.flush()
            except db_exc.DBDuplicateEntry:
                exception.StorageTierAlreadyExists(uuid=values['uuid'])
            return self._storage_tier_get(values['uuid'])

    @objects.objectify(objects.storage_tier)
    def storage_tier_update(self, storage_tier_uuid, values):
        with _session_for_write() as session:
            storage_tier = self._storage_tier_get(storage_tier_uuid,
                                                  session=session)
            storage_tier.update(values)
            session.add(storage_tier)
            session.flush()
            return storage_tier

    @objects.objectify(objects.storage_tier)
    def storage_tier_get_list(self, limit=None, marker=None,
                          sort_key=None, sort_dir=None):
        query = model_query(models.StorageTier)
        return _paginate_query(models.StorageTier, limit, marker,
                               sort_key, sort_dir, query)

    def storage_tier_get_all(self, uuid=None, name=None, type=None):
        query = model_query(models.StorageTier, read_deleted="no")
        if uuid is not None:
            query = query.filter_by(uuid=uuid)
        if name is not None:
            query = query.filter_by(name=name)
        if type is not None:
            query = query.filter_by(type=type)
        storage_tier_list = []
        try:
            storage_tier_list = query.all()
        except UnicodeDecodeError:
            LOG.error("UnicodeDecodeError occurred, "
                      "return an empty storage_tier list.")
        return storage_tier_list

    def storage_tier_destroy(self, storage_tier_uuid):
        query = model_query(models.StorageTier)
        query = add_identity_filter(query, storage_tier_uuid)
        try:
            query.one()
        except NoResultFound:
            raise exception.StorageTierNotFound(
                storage_tier_uuid=storage_tier_uuid)
        query.delete()

    @objects.objectify(objects.storage_backend)
    def storage_backend_create(self, values):
        if values['backend'] == constants.SB_TYPE_CEPH:
            backend = models.StorageCeph()
        elif values['backend'] == constants.SB_TYPE_CEPH_EXTERNAL:
            backend = models.StorageCephExternal()
        elif values['backend'] == constants.SB_TYPE_FILE:
            backend = models.StorageFile()
        elif values['backend'] == constants.SB_TYPE_LVM:
            backend = models.StorageLvm()
        elif values['backend'] == constants.SB_TYPE_EXTERNAL:
            backend = models.StorageExternal()
        elif values['backend'] == constants.SB_TYPE_CEPH_ROOK:
            backend = models.StorageCephRook()
        else:
            raise exception.InvalidParameterValue(
                err="Invalid backend setting: %s" % values['backend'])
        return self._storage_backend_create(backend, values)

    def _storage_backend_create(self, obj, values):

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        obj.update(values)
        with _session_for_write() as session:
            try:
                session.add(obj)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.StorageBackendAlreadyExists(uuid=values['uuid'])

        return self._storage_backend_get_by_cls(type(obj), values['uuid'])

    @objects.objectify(objects.storage_backend)
    def storage_backend_get(self, storage_backend_id):
        return self._storage_backend_get(storage_backend_id)

    def _storage_backend_get(self, storage_backend_id):
        entity = with_polymorphic(models.StorageBackend, '*')
        query = model_query(entity)
        query = add_storage_backend_filter(query, storage_backend_id)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                err="No entry found for storage backend %s" % storage_backend_id)
        except MultipleResultsFound:
            raise exception.InvalidParameterValue(
                err="Multiple entries found for storage backend %s" % storage_backend_id)

        return result

    def _storage_backend_get_by_cls(self, cls, storage_backend_id, obj=None):
        session = None
        if obj:
            session = inspect(obj).session
        query = model_query(cls, session=session)
        query = add_storage_backend_filter(query, storage_backend_id)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                err="No entry found for storage backend %s" % storage_backend_id)
        except MultipleResultsFound:
            raise exception.InvalidParameterValue(
                err="Multiple entries found for storage backend %s" % storage_backend_id)

        return result

    def storage_backend_get_by_name(self, name):

        entity = with_polymorphic(models.StorageBackend, '*')
        query = model_query(entity)
        query = add_storage_backend_name_filter(query, name)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.StorageBackendNotFoundByName(name=name)

        if result['backend'] == constants.SB_TYPE_CEPH:
            return objects.storage_ceph.from_db_object(result)
        elif result['backend'] == constants.SB_TYPE_CEPH_EXTERNAL:
            return objects.storage_ceph_external.from_db_object(result)
        elif result['backend'] == constants.SB_TYPE_FILE:
            return objects.storage_file.from_db_object(result)
        elif result['backend'] == constants.SB_TYPE_LVM:
            return objects.storage_lvm.from_db_object(result)
        elif result['backend'] == constants.SB_TYPE_EXTERNAL:
            return objects.storage_external.from_db_object(result)
        elif result['backend'] == constants.SB_TYPE_CEPH_ROOK:
            return objects.storage_ceph_rook.from_db_object(result)
        else:
            return objects.storage_backend.from_db_object(result)

    @objects.objectify(objects.storage_backend)
    def storage_backend_get_list(self, limit=None, marker=None,
                                 sort_key=None, sort_dir=None):

        entity = with_polymorphic(models.StorageBackend, '*')
        query = model_query(entity)
        try:
            result = _paginate_query(models.StorageBackend, limit, marker,
                                     sort_key, sort_dir, query)
        except (db_exc.InvalidSortKey, ValueError):
            result = []

        return result

    @objects.objectify(objects.storage_backend)
    def storage_backend_get_list_by_type(self, backend_type=None, limit=None,
                                         marker=None, sort_key=None,
                                         sort_dir=None):

        if backend_type == constants.SB_TYPE_CEPH:
            return self._storage_backend_get_list(models.StorageCeph, limit,
                                                  marker, sort_key, sort_dir)
        elif backend_type == constants.SB_TYPE_CEPH_EXTERNAL:
            return self._storage_backend_get_list(models.StorageCephExternal, limit,
                                                  marker, sort_key, sort_dir)
        elif backend_type == constants.SB_TYPE_FILE:
            return self._storage_backend_get_list(models.StorageFile, limit,
                                                  marker, sort_key, sort_dir)
        elif backend_type == constants.SB_TYPE_LVM:
            return self._storage_backend_get_list(models.StorageLvm, limit,
                                                  marker, sort_key, sort_dir)
        elif backend_type == constants.SB_TYPE_EXTERNAL:
            return self._storage_backend_get_list(models.StorageExternal, limit,
                                                  marker, sort_key, sort_dir)
        elif backend_type == constants.SB_TYPE_CEPH_ROOK:
            return self._storage_backend_get_list(models.StorageCephRook, limit,
                                                  marker, sort_key, sort_dir)
        else:
            entity = with_polymorphic(models.StorageBackend, '*')
            query = model_query(entity)
            try:
                result = _paginate_query(models.StorageBackend, limit, marker,
                                     sort_key, sort_dir, query)
            except exception.SysinvException:
                result = []

            return result

    def _storage_backend_get_list(self, cls, limit=None, marker=None,
                                  sort_key=None, sort_dir=None):
        return _paginate_query(cls, limit, marker, sort_key, sort_dir)

    @objects.objectify(objects.storage_backend)
    def storage_backend_get_by_isystem(self, isystem_id, limit=None,
                                       marker=None, sort_key=None,
                                       sort_dir=None):
        isystem_obj = self.isystem_get(isystem_id)
        entity = with_polymorphic(models.StorageBackend, '*')
        query = model_query(entity)
        query = query.filter_by(forisystemid=isystem_obj.id)
        return _paginate_query(models.StorageBackend, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.storage_backend)
    def storage_backend_update(self, storage_backend_id, values):
        with _session_for_write():
            query = model_query(models.StorageBackend, read_deleted="no")
            query = add_storage_backend_filter(query, storage_backend_id)
            try:
                result = query.one()
            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for storage backend %s" % storage_backend_id)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for storage backend %s" % storage_backend_id)

            if result.backend == constants.SB_TYPE_CEPH:
                return self._storage_backend_update(models.StorageCeph, storage_backend_id, values)
            elif result.backend == constants.SB_TYPE_CEPH_EXTERNAL:
                return self._storage_backend_update(models.StorageCephExternal, storage_backend_id, values)
            elif result.backend == constants.SB_TYPE_FILE:
                return self._storage_backend_update(models.StorageFile, storage_backend_id, values)
            elif result.backend == constants.SB_TYPE_LVM:
                return self._storage_backend_update(models.StorageLvm, storage_backend_id, values)
            elif result.backend == constants.SB_TYPE_EXTERNAL:
                return self._storage_backend_update(models.StorageExternal, storage_backend_id, values)
            elif result.backend == constants.SB_TYPE_CEPH_ROOK:
                return self._storage_backend_update(models.StorageCephRook, storage_backend_id, values)
            else:
                return self._storage_backend_update(models.StorageBackend, storage_backend_id, values)

    def _storage_backend_update(self, cls, storage_backend_id, values):
        with _session_for_write() as session:
            entity = with_polymorphic(models.StorageBackend, '*')
            query = model_query(entity)
            # query = model_query(cls, read_deleted="no")
            try:
                query = add_storage_backend_filter(query, storage_backend_id)
                result = query.one()

                obj = self._storage_backend_get_by_cls(models.StorageBackend, storage_backend_id)

                for k, v in values.items():
                    setattr(result, k, v)

            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for storage backend %s" % storage_backend_id)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for storage backend %s" % storage_backend_id)

            try:
                session.add(obj)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to update storage backend")

            return query.one()

    def storage_backend_destroy(self, storage_backend_id):
        return self._storage_backend_destroy(models.StorageBackend, storage_backend_id)

    def _storage_backend_destroy(self, cls, storage_backend_id):
        with _session_for_write():
            # Delete storage_backend which should cascade to delete derived backends
            if uuidutils.is_uuid_like(storage_backend_id):
                model_query(cls, read_deleted="no").\
                    filter_by(uuid=storage_backend_id).\
                    delete()
            else:
                model_query(cls, read_deleted="no").\
                    filter_by(id=storage_backend_id).\
                    delete()

    @objects.objectify(objects.storage_ceph)
    def storage_ceph_create(self, values):
        backend = models.StorageCeph()
        return self._storage_backend_create(backend, values)

    @objects.objectify(objects.storage_ceph)
    def storage_ceph_get(self, storage_ceph_id):
        return self._storage_backend_get_by_cls(models.StorageCeph, storage_ceph_id)

    @objects.objectify(objects.storage_ceph)
    def storage_ceph_get_list(self, limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        return self._storage_backend_get_list(models.StorageCeph, limit, marker,
                                              sort_key, sort_dir)

    @objects.objectify(objects.storage_ceph)
    def storage_ceph_update(self, storage_ceph_id, values):
        return self._storage_backend_update(models.StorageCeph, storage_ceph_id,
                                            values)

    @objects.objectify(objects.storage_ceph)
    def storage_ceph_destroy(self, storage_ceph_id):
        return self._storage_backend_destroy(models.StorageCeph, storage_ceph_id)

    @objects.objectify(objects.storage_external)
    def storage_external_create(self, values):
        backend = models.StorageExternal()
        return self._storage_backend_create(backend, values)

    @objects.objectify(objects.storage_external)
    def storage_external_get(self, storage_external_id):
        return self._storage_backend_get_by_cls(models.StorageExternal, storage_external_id)

    @objects.objectify(objects.storage_external)
    def storage_external_get_list(self, limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        return self._storage_backend_get_list(models.StorageExternal, limit, marker,
                                              sort_key, sort_dir)

    @objects.objectify(objects.storage_external)
    def storage_external_update(self, storage_external_id, values):
        return self._storage_backend_update(models.StorageExternal, storage_external_id,
                                            values)

    @objects.objectify(objects.storage_external)
    def storage_external_destroy(self, storage_external_id):
        return self._storage_backend_destroy(models.StorageExternal, storage_external_id)

    @objects.objectify(objects.storage_file)
    def storage_file_create(self, values):
        backend = models.StorageFile()
        return self._storage_backend_create(backend, values)

    @objects.objectify(objects.storage_file)
    def storage_file_get(self, storage_file_id):
        return self._storage_backend_get_by_cls(models.StorageFile, storage_file_id)

    @objects.objectify(objects.storage_file)
    def storage_file_get_list(self, limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        return self._storage_backend_get_list(models.StorageFile, limit, marker,
                                              sort_key, sort_dir)

    @objects.objectify(objects.storage_file)
    def storage_file_update(self, storage_file_id, values):
        return self._storage_backend_update(models.StorageFile, storage_file_id,
                                            values)

    @objects.objectify(objects.storage_file)
    def storage_file_destroy(self, storage_file_id):
        return self._storage_backend_destroy(models.StorageFile, storage_file_id)

    @objects.objectify(objects.storage_lvm)
    def storage_lvm_create(self, values):
        backend = models.StorageLvm()
        return self._storage_backend_create(backend, values)

    @objects.objectify(objects.storage_lvm)
    def storage_lvm_get(self, storage_lvm_id):
        return self._storage_backend_get_by_cls(models.StorageLvm, storage_lvm_id)

    @objects.objectify(objects.storage_lvm)
    def storage_lvm_get_list(self, limit=None, marker=None,
                             sort_key=None, sort_dir=None):
        return self._storage_backend_get_list(models.StorageLvm, limit, marker,
                                              sort_key, sort_dir)

    @objects.objectify(objects.storage_lvm)
    def storage_lvm_update(self, storage_lvm_id, values):
        return self._storage_backend_update(models.StorageLvm, storage_lvm_id,
                                            values)

    @objects.objectify(objects.storage_lvm)
    def storage_lvm_destroy(self, storage_lvm_id):
        return self._storage_backend_destroy(models.StorageLvm, storage_lvm_id)

    @objects.objectify(objects.storage_ceph_external)
    def storage_ceph_external_create(self, values):
        backend = models.StorageCephExternal()
        return self._storage_backend_create(backend, values)

    @objects.objectify(objects.storage_ceph_external)
    def storage_ceph_external_get(self, storage_ceph_external_id):
        return self._storage_backend_get_by_cls(models.StorageCephExternal,
                                                storage_ceph_external_id)

    @objects.objectify(objects.storage_ceph_external)
    def storage_ceph_external_get_list(self, limit=None, marker=None,
                                       sort_key=None, sort_dir=None):
        return self._storage_backend_get_list(models.StorageCephExternal, limit,
                                              marker,
                                              sort_key, sort_dir)

    @objects.objectify(objects.storage_ceph_external)
    def storage_ceph_external_update(self, storage_ceph_external_id, values):
        return self._storage_backend_update(models.StorageCephExternal,
                                            storage_ceph_external_id,
                                            values)

    @objects.objectify(objects.storage_ceph_external)
    def storage_ceph_external_destroy(self, storage_ceph_external_id):
        return self._storage_backend_destroy(models.StorageCephExternal,
                                             storage_ceph_external_id)

    @objects.objectify(objects.storage_ceph_rook)
    def storage_ceph_rook_create(self, values):
        backend = models.StorageCephRook()
        return self._storage_backend_create(backend, values)

    @objects.objectify(objects.storage_ceph_rook)
    def storage_ceph_rook_get(self, storage_ceph_rook_id):
        return self._storage_backend_get_by_cls(models.StorageCephRook,
                                                storage_ceph_rook_id)

    @objects.objectify(objects.storage_ceph_rook)
    def storage_ceph_rook_get_list(self, limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        return self._storage_backend_get_list(models.StorageCephRook, limit,
                                              marker,
                                              sort_key, sort_dir)

    @objects.objectify(objects.storage_ceph_rook)
    def storage_ceph_rook_update(self, storage_ceph_rook_id, values):
        return self._storage_backend_update(models.StorageCephRook,
                                            storage_ceph_rook_id,
                                            values)

    @objects.objectify(objects.storage_ceph_rook)
    def storage_ceph_rook_destroy(self, storage_ceph_rook_id):
        return self._storage_backend_destroy(models.StorageCephRook,
                                             storage_ceph_rook_id)

    def _drbdconfig_get(self, server):
        query = model_query(models.drbdconfig)
        query = add_identity_filter(query, server)

        try:
            return query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=server)

    @objects.objectify(objects.drbdconfig)
    def drbdconfig_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        drbd = models.drbdconfig()
        drbd.update(values)
        with _session_for_write() as session:
            try:
                session.add(drbd)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.DRBDAlreadyExists(uuid=values['uuid'])
            return self._drbdconfig_get(values['uuid'])

    @objects.objectify(objects.drbdconfig)
    def drbdconfig_get(self, server):
        return self._drbdconfig_get(server)

    @objects.objectify(objects.drbdconfig)
    def drbdconfig_get_one(self):
        query = model_query(models.drbdconfig)

        try:
            return query.one()
        except NoResultFound:
            raise exception.NotFound()

    @objects.objectify(objects.drbdconfig)
    def drbdconfig_get_list(self, limit=None, marker=None,
                            sort_key=None, sort_dir=None):

        query = model_query(models.drbdconfig)

        return _paginate_query(models.drbdconfig, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.drbdconfig)
    def drbdconfig_get_by_isystem(self, isystem_id, limit=None, marker=None,
                                  sort_key=None, sort_dir=None):
        # isystem_get() to raise an exception if the isystem is not found
        isystem_obj = self.isystem_get(isystem_id)
        query = model_query(models.drbdconfig)
        query = query.filter_by(forisystemid=isystem_obj.id)
        return _paginate_query(models.drbdconfig, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.drbdconfig)
    def drbdconfig_update(self, server, values):
        with _session_for_write() as session:
            query = model_query(models.drbdconfig, session=session)
            query = add_identity_filter(query, server)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.ServerNotFound(server=server)
            return query.one()

    def drbdconfig_destroy(self, server):
        with _session_for_write() as session:
            query = model_query(models.drbdconfig, session=session)
            query = add_identity_filter(query, server)

            try:
                query.one()
            except NoResultFound:
                raise exception.ServerNotFound(server=server)
            # if node_ref['reservation'] is not None:
            #     raise exception.NodeLocked(node=node)

            # Get node ID, if an UUID was supplied. The ID is
            # required for deleting all ports, attached to the node.
            # if uuidutils.is_uuid_like(server):
            #     server_id = node_ref['id']
            # else:
            #     server_id = server

            query.delete()

    def _remotelogging_get(self, server):
        query = model_query(models.remotelogging)
        query = add_identity_filter(query, server)

        try:
            return query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=server)

    @objects.objectify(objects.remotelogging)
    def remotelogging_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        remotelogging = models.remotelogging()
        remotelogging.update(values)
        with _session_for_write() as session:
            try:
                session.add(remotelogging)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.RemoteLoggingAlreadyExists(uuid=values['uuid'])
            return self._remotelogging_get(values['uuid'])

    @objects.objectify(objects.remotelogging)
    def remotelogging_get(self, server):
        return self._remotelogging_get(server)

    @objects.objectify(objects.remotelogging)
    def remotelogging_get_one(self):
        query = model_query(models.remotelogging)

        try:
            return query.one()
        except NoResultFound:
            raise exception.NotFound()

    @objects.objectify(objects.remotelogging)
    def remotelogging_get_list(self, limit=None, marker=None,
                               sort_key=None, sort_dir=None):

        query = model_query(models.remotelogging)

        return _paginate_query(models.remotelogging, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.remotelogging)
    def remotelogging_get_by_isystem(self, isystem_id, limit=None, marker=None,
                                     sort_key=None, sort_dir=None):
        # isystem_get() to raise an exception if the isystem is not found
        isystem_obj = self.isystem_get(isystem_id)
        query = model_query(models.remotelogging)
        query = query.filter_by(system_id=isystem_obj.id)
        return _paginate_query(models.remotelogging, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.remotelogging)
    def remotelogging_update(self, server, values):
        with _session_for_write() as session:
            query = model_query(models.remotelogging, session=session)
            query = add_identity_filter(query, server)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.ServerNotFound(server=server)
            return query.one()

    def remotelogging_destroy(self, server):
        with _session_for_write() as session:
            query = model_query(models.remotelogging, session=session)
            query = add_identity_filter(query, server)

            try:
                query.one()
            except NoResultFound:
                raise exception.ServerNotFound(server=server)

            query.delete()

    def remotelogging_fill_empty_system_id(self, system_id):
        values = {'system_id': system_id}
        with _session_for_write() as session:
            query = model_query(models.remotelogging,
                                session=session)
            query = query.filter_by(system_id=None)
            query.update(values, synchronize_session='fetch')

    def _service_get(self, name):
        query = model_query(models.Services)
        query = query.filter_by(name=name)

        try:
            return query.one()
        except NoResultFound:
            raise exception.ServiceNotFound(service=name)

    @objects.objectify(objects.service)
    def service_create(self, values):
        service = models.Services()
        service.update(values)
        with _session_for_write() as session:
            try:
                session.add(service)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.ServiceAlreadyExists(uuid=values['uuid'])
            return self._service_get(values['name'])

    @objects.objectify(objects.service)
    def service_get(self, name):
        return self._service_get(name)

    @objects.objectify(objects.service)
    def service_get_one(self):
        query = model_query(models.Services)

        try:
            return query.one()
        except NoResultFound:
            raise exception.NotFound()

    @objects.objectify(objects.service)
    def service_get_list(self, limit=None, marker=None,
                      sort_key=None, sort_dir=None):

        query = model_query(models.Services)

        return _paginate_query(models.Services, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.service)
    def service_get_all(self):
        query = model_query(models.Services, read_deleted="no")
        return query.all()

    @objects.objectify(objects.service)
    def service_update(self, name, values):
        with _session_for_write() as session:
            query = model_query(models.Services, session=session)
            query = query.filter_by(name=name)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.ServiceNotFound(service=name)
            return query.one()

    def service_destroy(self, service):
        with _session_for_write() as session:
            query = model_query(models.Services, session=session)
            query = query.filter_by(name=service)
            try:
                query.one()
            except NoResultFound:
                raise exception.ServiceNotFound(service=service)
            query.delete()

    def _network_get(self, network_uuid):
        query = model_query(models.Networks)
        query = add_identity_filter(query, network_uuid)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.NetworkNotFound(network_uuid=network_uuid)
        return result

    def _network_get_by_id(self, network_id):
        query = model_query(models.Networks)
        query = query.filter_by(id=network_id)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.NetworkIDNotFound(id=network_id)
        return result

    def _network_get_by_type(self, networktype):
        query = model_query(models.Networks)
        query = query.filter_by(type=networktype)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.NetworkTypeNotFound(type=networktype)
        return result

    def _network_get_by_name(self, networkname):
        query = model_query(models.Networks)
        query = query.filter_by(name=networkname)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.NetworkNameNotFound(name=networkname)
        return result

    def _networks_get_by_type(self, networktype, limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        query = model_query(models.Networks)
        query = query.filter_by(type=networktype)
        return _paginate_query(models.Networks, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.network)
    def network_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        network = models.Networks(**values)
        with _session_for_write() as session:
            try:
                session.add(network)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.NetworkAlreadyExists(uuid=values['uuid'])
            return self._network_get(values['uuid'])

    @objects.objectify(objects.network)
    def network_get(self, network_uuid):
        return self._network_get(network_uuid)

    @objects.objectify(objects.network)
    def network_get_by_id(self, network_id):
        return self._network_get_by_id(network_id)

    @objects.objectify(objects.network)
    def network_get_by_type(self, networktype):
        return self._network_get_by_type(networktype)

    @objects.objectify(objects.network)
    def networks_get_all(self, limit=None, marker=None,
                         sort_key=None, sort_dir=None):
        query = model_query(models.Networks)
        return _paginate_query(models.Networks, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.network)
    def networks_get_by_type(self, networktype, limit=None, marker=None,
                             sort_key=None, sort_dir=None):
        return self._networks_get_by_type(networktype, limit, marker,
                                          sort_key, sort_dir)

    @objects.objectify(objects.network)
    def network_get_by_name(self, networkname):
        return self._network_get_by_name(networkname)

    @objects.objectify(objects.network)
    def networks_get_by_pool(self, pool_id, limit=None, marker=None,
                             sort_key=None, sort_dir=None):
        query = model_query(models.Networks)
        query = query.filter_by(address_pool_id=pool_id)
        return _paginate_query(models.Networks, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.network)
    def network_update(self, network_uuid, values):
        with _session_for_write() as session:
            query = model_query(models.Networks, session=session)
            query = add_identity_filter(query, network_uuid)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.NetworkNotFound(network_uuid=network_uuid)
            return query.one()

    def network_destroy(self, network_uuid):
        query = model_query(models.Networks)
        query = add_identity_filter(query, network_uuid)
        try:
            query.one()
        except NoResultFound:
            raise exception.NetworkNotFound(network_uuid=network_uuid)
        query.delete()

    def _interface_network_get(self, uuid):
        query = model_query(models.InterfaceNetworks)
        query = add_identity_filter(query, uuid)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.InterfaceNetworkNotFound(uuid=uuid)
        return result

    def _interface_network_get_all(
            self, limit=None, marker=None,
            sort_key=None, sort_dir=None):
        query = model_query(models.InterfaceNetworks)
        return _paginate_query(
            models.InterfaceNetworks, limit, marker,
            sort_key, sort_dir, query)

    def _interface_network_get_by_host(
            self, host_uuid, limit=None, marker=None,
            sort_key=None, sort_dir=None):
        query = model_query(models.InterfaceNetworks)
        query = (query.
                 join(models.Interfaces).
                 join(models.ihost,
                      models.ihost.id == models.Interfaces.forihostid))
        query, field = add_filter_by_many_identities(
            query, models.ihost, [host_uuid])
        return _paginate_query(
            models.InterfaceNetworks, limit, marker,
            sort_key, sort_dir, query)

    def _interface_network_get_by_interface(
            self, interface_uuid, limit=None, marker=None,
            sort_key=None, sort_dir=None):
        query = model_query(models.InterfaceNetworks)
        query = (query.join(models.Interfaces))
        query, field = add_filter_by_many_identities(
            query, models.Interfaces, [interface_uuid])
        return _paginate_query(models.InterfaceNetworks, limit, marker,
                               sort_key, sort_dir, query)

    def _interface_network_query(self, values):
        query = model_query(models.InterfaceNetworks)
        query = (query.
                 filter(models.InterfaceNetworks.interface_id == values['interface_id']).
                 filter(models.InterfaceNetworks.network_id == values['network_id']))
        try:
            result = query.one()
        except NoResultFound:
            raise exception.InterfaceNetworkNotFoundByHostInterfaceNetwork(
                interface_id=values['interface_id'],
                network_id=values['network_id'])
        return result

    @objects.objectify(objects.interface_network)
    def interface_network_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        interface_network = models.InterfaceNetworks(**values)
        with _session_for_write() as session:
            try:
                session.add(interface_network)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.InterfaceNetworkAlreadyExists(
                    interface_id=values['interface_id'],
                    network_id=values['network_id'])
            return self._interface_network_get(values['uuid'])

    @objects.objectify(objects.interface_network)
    def interface_network_get(self, uuid):
        return self._interface_network_get(uuid)

    @objects.objectify(objects.interface_network)
    def interface_network_get_all(
            self, limit=None, marker=None,
            sort_key=None, sort_dir=None):
        return self._interface_network_get_all(
            limit, marker, sort_key, sort_dir)

    @objects.objectify(objects.interface_network)
    def interface_network_get_by_host(
            self, host_id, limit=None, marker=None,
            sort_key=None, sort_dir=None):
        return self._interface_network_get_by_host(
            host_id, limit, marker, sort_key, sort_dir)

    @objects.objectify(objects.interface_network)
    def interface_network_get_by_interface(
            self, interface_id, limit=None, marker=None,
            sort_key=None, sort_dir=None):
        return self._interface_network_get_by_interface(
            interface_id, limit, marker, sort_key, sort_dir)

    def interface_network_destroy(self, uuid):
        query = model_query(models.InterfaceNetworks)
        query = add_identity_filter(query, uuid)
        try:
            query.one()
        except NoResultFound:
            raise exception.InterfaceNetworkNotFound(uuid=uuid)
        query.delete()

    @objects.objectify(objects.interface_network)
    def interface_network_query(self, values):
        return self._interface_network_query(values)

    def _address_get(self, address_uuid):
        query = model_query(models.Addresses)
        query = add_identity_filter(query, address_uuid)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.AddressNotFound(address_uuid=address_uuid)
        return result

    def _address_query(self, values):
        query = model_query(models.Addresses)
        query = (query.
                 filter(models.Addresses.address == values['address']))
        try:
            result = query.one()
        except NoResultFound:
            raise exception.AddressNotFoundByAddress(address=values['address'])
        return result

    @objects.objectify(objects.address)
    def address_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        address = models.Addresses(**values)
        with _session_for_write() as session:
            try:
                session.add(address)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.AddressAlreadyExists(address=values['address'],
                                                     prefix=values['prefix'])
            return self._address_get(values['uuid'])

    @objects.objectify(objects.address)
    def address_get(self, address_uuid):
        return self._address_get(address_uuid)

    @objects.objectify(objects.address)
    def address_get_by_name(self, name):
        query = model_query(models.Addresses)
        query = query.filter_by(name=name)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.AddressNotFoundByName(name=name)
        return result

    @objects.objectify(objects.address)
    def address_get_by_address(self, address):
        query = model_query(models.Addresses)
        query = query.filter_by(address=address)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.AddressNotFoundByAddress(address=address)
        return result

    @objects.objectify(objects.address)
    def address_update(self, address_uuid, values):
        with _session_for_write() as session:
            query = model_query(models.Addresses, session=session)
            query = add_identity_filter(query, address_uuid)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.AddressNotFound(address_uuid=address_uuid)
            return query.one()

    @objects.objectify(objects.address)
    def address_query(self, values):
        return self._address_query(values)

    @objects.objectify(objects.address)
    def addresses_get_all(self, limit=None, marker=None,
                          sort_key=None, sort_dir=None):
        query = model_query(models.Addresses)
        return _paginate_query(models.Addresses, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.address)
    def addresses_get_by_interface(self, interface_id, family=None,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        query = model_query(models.Addresses)
        query = (query.
                 join(models.Interfaces))
        if family:
            query = (query.
                     filter(models.Addresses.family == family))
        query, field = add_filter_by_many_identities(
            query, models.Interfaces, [interface_id])
        return _paginate_query(models.Addresses, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.address)
    def addresses_get_by_host(self, host_id, family=None,
                              limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        query = model_query(models.Addresses)
        query = (query.
                 join(models.Interfaces).
                 join(models.ihost,
                      models.ihost.id == models.Interfaces.forihostid))
        if family:
            query = (query.
                     filter(models.Addresses.family == family))
        query, field = add_filter_by_many_identities(
            query, models.ihost, [host_id])
        return _paginate_query(models.Addresses, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.address)
    def addresses_get_by_pool(self, pool_id,
                              limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        query = model_query(models.Addresses)
        query = (query.
                 join(models.AddressPools,
                      models.AddressPools.id == pool_id).
                 filter(models.Addresses.address_pool_id == pool_id))
        return _paginate_query(models.Addresses, limit, marker,
                               sort_key, sort_dir, query)

    def _addresses_get_by_pool_uuid(self, pool_uuid,
                                    limit=None, marker=None,
                                    sort_key=None, sort_dir=None):
        with _session_for_write() as session:
            pool_id = self.address_pool_get(pool_uuid).id
            query = model_query(models.Addresses, session=session)
            query = (query.
                     join(models.AddressPools,
                          models.AddressPools.id == pool_id).
                     filter(models.Addresses.address_pool_id == pool_id))
            result = _paginate_query(models.Addresses, limit, marker,
                                     sort_key, sort_dir, query)
            for address in result:
                if address.interface:
                    LOG.debug(address.interface.imac)
            return result

    @objects.objectify(objects.address)
    def addresses_get_by_pool_uuid(self, pool_uuid,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        return self._addresses_get_by_pool_uuid(pool_uuid,
                                                limit, marker,
                                                sort_key, sort_dir)

    @objects.objectify(objects.address)
    def addresses_get_by_interface_pool(self, interface_uuid, pool_uuid,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        interface_id = self.iinterface_get(interface_uuid).id
        pool_id = self.address_pool_get(pool_uuid).id
        query = model_query(models.Addresses)
        query = (query.
                 join(models.AddressPools,
                      models.AddressPools.id == pool_id).
                 join(models.Interfaces,
                      models.Interfaces.id == interface_id).
                 filter(models.Addresses.interface_id == interface_id).
                 filter(models.Addresses.address_pool_id == pool_id))
        try:
            result = query.one()
        except NoResultFound:
            raise exception.AddressNotFoundByInterfacePool(interface=interface_uuid, pool=pool_uuid)
        return result

    def address_destroy(self, address_uuid):
        query = model_query(models.Addresses)
        query = add_identity_filter(query, address_uuid)
        try:
            query.one()
        except NoResultFound:
            raise exception.AddressNotFound(address_uuid=address_uuid)
        query.delete()

    def address_remove_interface(self, address_uuid):
        query = model_query(models.Addresses)
        query = add_identity_filter(query, address_uuid)
        try:
            query.one()
        except NoResultFound:
            raise exception.AddressNotFound(address_uuid=address_uuid)
        query.update({models.Addresses.interface_id: None},
                     synchronize_session='fetch')

    def addresses_destroy_by_interface(self, interface_id, family=None):
        query = model_query(models.Addresses)
        query = query.filter(models.Addresses.interface_id == interface_id)
        if family:
            query = query.filter(models.Addresses.family == family)
        query.delete()

    def addresses_remove_interface_by_interface(self, interface_id,
                                                family=None):
        query = model_query(models.Addresses)
        query = query.filter(models.Addresses.interface_id == interface_id)
        if family:
            query = query.filter(models.Addresses.family == family)
        query.update({models.Addresses.interface_id: None},
                     synchronize_session='fetch')

    def _route_get(self, route_uuid):
        query = model_query(models.Routes)
        query = add_identity_filter(query, route_uuid)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.RouteNotFound(route_uuid=route_uuid)
        return result

    def _route_query(self, host_id, values):
        query = model_query(models.Routes)
        query = (query.
                 join(models.Interfaces,
                      models.Interfaces.id == models.Routes.interface_id).
                 join(models.ihost,
                      models.ihost.id == models.Interfaces.forihostid).
                 filter(models.Routes.network == values['network']).
                 filter(models.Routes.prefix == values['prefix']).
                 filter(models.Routes.gateway == values['gateway']).
                 filter(models.Routes.metric == values['metric']))
        query, field = add_filter_by_many_identities(
            query, models.ihost, [host_id])
        try:
            result = query.one()
        except NoResultFound:
            raise exception.RouteNotFoundByName(network=values['network'],
                                                prefix=values['prefix'],
                                                gateway=values['gateway'])
        return result

    @objects.objectify(objects.route)
    def route_create(self, interface_id, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        values['interface_id'] = interface_id
        route = models.Routes(**values)
        with _session_for_write() as session:
            try:
                session.add(route)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.RouteAlreadyExists(uuid=values['uuid'])
            return self._route_get(values['uuid'])

    @objects.objectify(objects.route)
    def route_get(self, route_uuid):
        return self._route_get(route_uuid)

    @objects.objectify(objects.route)
    def route_query(self, host_id, values):
        return self._route_query(host_id, values)

    @objects.objectify(objects.route)
    def routes_get_all(self, limit=None, marker=None,
                       sort_key=None, sort_dir=None):
        query = model_query(models.Routes)
        return _paginate_query(models.Routes, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.route)
    def routes_get_by_interface(self, interface_id, limit=None, marker=None,
                                sort_key=None, sort_dir=None):
        query = model_query(models.Routes)
        query = (query.
                 join(models.Interfaces))
        query, field = add_filter_by_many_identities(
            query, models.Interfaces, [interface_id])
        return _paginate_query(models.Routes, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.route)
    def routes_get_by_host(self, host_id, limit=None, marker=None,
                           sort_key=None, sort_dir=None):
        query = model_query(models.Routes)
        query = (query.
                 join(models.Interfaces).
                 join(models.ihost,
                      models.ihost.id == models.Interfaces.forihostid))
        query, field = add_filter_by_many_identities(
            query, models.ihost, [host_id])
        return _paginate_query(models.Routes, limit, marker,
                               sort_key, sort_dir, query)

    def route_destroy(self, route_uuid):
        query = model_query(models.Routes)
        query = add_identity_filter(query, route_uuid)
        try:
            query.one()
        except NoResultFound:
            raise exception.RouteNotFound(route_uuid=route_uuid)
        query.delete()

    def routes_destroy_by_interface(self, interface_id, family=None):
        query = model_query(models.Routes)
        query = query.filter(models.Routes.interface_id == interface_id)
        if family:
            query = query.filter(models.Routes.family == family)
        query.delete()

    def _address_mode_query(self, interface_id, family, session=None):
        query = model_query(models.AddressModes, session=session)
        query = (query.
                 join(models.Interfaces,
                      models.Interfaces.id ==
                      models.AddressModes.interface_id).
                 filter(models.AddressModes.family == family))
        query, field = add_filter_by_many_identities(
            query, models.Interfaces, [interface_id])
        try:
            result = query.one()
        except NoResultFound:
            raise exception.AddressModeNotFoundByFamily(
                family=IP_FAMILIES[family])
        return result

    def _address_mode_get(self, mode_uuid):
        query = model_query(models.AddressModes)
        query = add_identity_filter(query, mode_uuid)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.AddressModeNotFound(mode_uuid=mode_uuid)
        return result

    @objects.objectify(objects.address_mode)
    def address_mode_get(self, mode_uuid):
        return self._address_mode_get(mode_uuid)

    @objects.objectify(objects.address_mode)
    def address_mode_query(self, interface_id, family):
        return self._address_mode_query(interface_id, family)

    @objects.objectify(objects.address_mode)
    def address_mode_update(self, interface_id, values, context=None):
        try:
            # Update it if it exists.
            family = values['family']
            with _session_for_write() as session:
                existing = self._address_mode_query(
                    interface_id, family, session=session)
                existing.update(values)
                session.add(existing)
                session.flush()
                return existing
        except exception.AddressModeNotFoundByFamily:
            with _session_for_write() as session:
                # Otherwise create a new entry
                if not values.get('uuid'):
                    values['uuid'] = uuidutils.generate_uuid()
                values['interface_id'] = interface_id
                new = models.AddressModes(**values)
                try:
                    session.add(new)
                    session.flush()
                except db_exc.DBDuplicateEntry:
                    raise exception.AddressModeAlreadyExists(uuid=values['uuid'])
                return self._address_mode_get(values['uuid'])

    def address_mode_destroy(self, mode_uuid):
        query = model_query(models.AddressModes)
        query = add_identity_filter(query, mode_uuid)
        try:
            query.one()
        except NoResultFound:
            raise exception.AddressModeNotFound(mode_uuid=mode_uuid)
        query.delete()

    def address_modes_destroy_by_interface(self, interface_id, family=None):
        query = model_query(models.AddressModes)
        query = query.filter(models.AddressModes.interface_id == interface_id)
        if family:
            query = query.filter(models.AddressModes.family == family)
        query.delete()

    def _address_pool_get(self, address_pool_uuid, session=None):
        query = model_query(models.AddressPools, session=session)
        query = add_identity_filter(query, address_pool_uuid, use_name=True)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.AddressPoolNotFound(
                address_pool_uuid=address_pool_uuid)
        return result

    def _address_pool_query(self, values, session=None):
        query = model_query(models.AddressPools, session=session)
        query = (query.
                 filter(models.AddressPools.name == values['name']))
        try:
            result = query.one()
        except NoResultFound:
            raise exception.AddressPoolNotFoundByName(name=values['name'])
        return result

    @objects.objectify(objects.address_pool)
    def address_pool_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        ranges = values.pop('ranges')
        address_pool = models.AddressPools(**values)
        for start, end in ranges:
            range_values = {'start': start,
                            'end': end,
                            'uuid': uuidutils.generate_uuid()}
            new_range = models.AddressPoolRanges(**range_values)
            address_pool.ranges.append(new_range)
        with _session_for_write() as session:
            try:
                session.add(address_pool)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.AddressPoolAlreadyExists(uuid=values['uuid'])
            return self._address_pool_get(values['uuid'])

    def _address_pool_range_update(self, session, address_pool, ranges):
        # reset the list of stored ranges and then re-add then
        address_pool.ranges = []
        for start, end in ranges:
            range_values = {'start': start,
                            'end': end,
                            'uuid': uuidutils.generate_uuid()}
            new_range = models.AddressPoolRanges(**range_values)
            address_pool.ranges.append(new_range)

    @objects.objectify(objects.address_pool)
    def address_pool_update(self, address_pool_uuid, values):
        with _session_for_write() as session:
            address_pool = self._address_pool_get(address_pool_uuid,
                                                  session=session)
            ranges = values.pop('ranges', [])
            address_pool.update(values)
            if ranges:
                self._address_pool_range_update(session, address_pool, ranges)

            session.add(address_pool)
            session.flush()

            return address_pool

    @objects.objectify(objects.address_pool)
    def address_pool_get(self, address_pool_uuid):
        return self._address_pool_get(address_pool_uuid)

    @objects.objectify(objects.address_pool)
    def address_pool_query(self, values):
        return self._address_pool_query(values)

    @objects.objectify(objects.address_pool)
    def address_pools_get_all(self, limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        query = model_query(models.AddressPools)
        return _paginate_query(models.AddressPools, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.address_pool)
    def address_pools_get_by_interface(self, interface_id,
                                       limit=None, marker=None,
                                       sort_key=None, sort_dir=None):
        query = model_query(models.AddressPools)
        query = (query.
                 join(models.AddressModes,
                      (models.AddressModes.address_pool_id ==
                       models.AddressPools.id)).
                 join(models.Interfaces,
                      (models.Interfaces.id ==
                       models.AddressModes.interface_id)).
                 filter(models.Interfaces.id == interface_id))
        return _paginate_query(models.AddressPools, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.address_pool)
    def address_pools_get_by_id(self, address_pool_id):
        query = model_query(models.AddressPools)
        query = query.filter(models.AddressPools.id == address_pool_id)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.AddressPoolNotFoundByID(
                address_pool_id=address_pool_id
            )
        return result

    def address_pool_destroy(self, address_pool_uuid):
        query = model_query(models.AddressPools)
        query = add_identity_filter(query, address_pool_uuid)
        try:
            query.one()
        except NoResultFound:
            raise exception.AddressPoolNotFound(
                address_pool_uuid=address_pool_uuid)
        query.delete()

    # SENSORS
    def _sensor_analog_create(self, hostid, values):
        if utils.is_int_like(hostid):
            host = self.ihost_get(int(hostid))
        elif utils.is_uuid_like(hostid):
            host = self.ihost_get(hostid.strip())
        elif isinstance(hostid, models.ihost):
            host = hostid
        else:
            raise exception.NodeNotFound(node=hostid)

        values['host_id'] = host['id']

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        sensor_analog = models.SensorsAnalog()
        sensor_analog.update(values)

        with _session_for_write() as session:
            try:
                session.add(sensor_analog)
                session.flush()
            except db_exc.DBDuplicateEntry:
                exception.SensorAlreadyExists(uuid=values['uuid'])
            return self._sensor_analog_get(values['uuid'])

    def _sensor_analog_get(self, sensorid, hostid=None):
        query = model_query(models.SensorsAnalog)

        if hostid:
            query = query.filter_by(host_id=hostid)

        query = add_sensor_analog_filter(query, sensorid)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=sensorid)

        return result

    def _sensor_analog_get_list(self, limit=None, marker=None,
                                sort_key=None, sort_dir=None):
        return _paginate_query(models.SensorsAnalog, limit, marker,
                               sort_key, sort_dir)

    def _sensor_analog_get_all(self, hostid=None, sensorgroupid=None):
        query = model_query(models.SensorsAnalog, read_deleted="no")
        if hostid:
            query = query.filter_by(host_id=hostid)
        if sensorgroupid:
            query = query.filter_by(sensorgroup_id=hostid)
        return query.all()

    def _sensor_analog_get_by_host(self, host,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        query = model_query(models.SensorsAnalog)
        query = add_port_filter_by_host(query, host)
        return _paginate_query(models.SensorsAnalog, limit, marker,
                               sort_key, sort_dir, query)

    def _sensor_analog_get_by_isensorgroup(self, sensorgroup,
                                           limit=None, marker=None,
                                           sort_key=None, sort_dir=None):

        query = model_query(models.SensorsAnalog)
        query = add_sensor_filter_by_sensorgroup(query, sensorgroup)
        return _paginate_query(models.SensorsAnalog, limit, marker,
                               sort_key, sort_dir, query)

    def _sensor_analog_get_by_host_isensorgroup(self, host, sensorgroup,
                                                limit=None, marker=None,
                                                sort_key=None, sort_dir=None):
        query = model_query(models.SensorsAnalog)
        query = add_sensor_filter_by_ihost_sensorgroup(query,
                                                       host,
                                                       sensorgroup)
        return _paginate_query(models.SensorsAnalog, limit, marker,
                               sort_key, sort_dir, query)

    def _sensor_analog_update(self, sensorid, values, hostid=None):
        with _session_for_write():
            # May need to reserve in multi controller system; ref sysinv
            query = model_query(models.SensorsAnalog, read_deleted="no")

            if hostid:
                query = query.filter_by(host_id=hostid)

            try:
                query = add_sensor_analog_filter(query, sensorid)
                result = query.one()
                for k, v in values.items():
                    setattr(result, k, v)
            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for port %s" % sensorid)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for port %s" % sensorid)

            return query.one()

    def _sensor_analog_destroy(self, sensorid):
        with _session_for_write():
            # Delete port which should cascade to delete SensorsAnalog
            if uuidutils.is_uuid_like(sensorid):
                model_query(models.Sensors, read_deleted="no").\
                            filter_by(uuid=sensorid).\
                            delete()
            else:
                model_query(models.Sensors, read_deleted="no").\
                            filter_by(id=sensorid).\
                            delete()

    @objects.objectify(objects.sensor_analog)
    def isensor_analog_create(self, hostid, values):
        return self._sensor_analog_create(hostid, values)

    @objects.objectify(objects.sensor_analog)
    def isensor_analog_get(self, sensorid, hostid=None):
        return self._sensor_analog_get(sensorid, hostid)

    @objects.objectify(objects.sensor_analog)
    def isensor_analog_get_list(self, limit=None, marker=None,
                                sort_key=None, sort_dir=None):
        return self._sensor_analog_get_list(limit, marker, sort_key, sort_dir)

    @objects.objectify(objects.sensor_analog)
    def isensor_analog_get_all(self, hostid=None, sensorgroupid=None):
        return self._sensor_analog_get_all(hostid, sensorgroupid)

    @objects.objectify(objects.sensor_analog)
    def isensor_analog_get_by_host(self, host,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        return self._sensor_analog_get_by_host(host, limit, marker,
                                               sort_key, sort_dir)

    @objects.objectify(objects.sensor_analog)
    def isensor_analog_get_by_isensorgroup(self, sensorgroup,
                                           limit=None, marker=None,
                                           sort_key=None, sort_dir=None):
        return self._sensor_analog_get_by_isensorgroup(sensorgroup, limit, marker,
                                                       sort_key, sort_dir)

    @objects.objectify(objects.sensor_analog)
    def isensor_analog_get_by_host_isensorgroup(self, host, sensorgroup,
                                                limit=None, marker=None,
                                                sort_key=None, sort_dir=None):
        return self._sensor_analog_get_by_host_isensorgroup(host, sensorgroup,
                                                            limit, marker,
                                                            sort_key, sort_dir)

    @objects.objectify(objects.sensor_analog)
    def isensor_analog_update(self, sensorid, values, hostid=None):
        return self._sensor_analog_update(sensorid, values, hostid)

    def isensor_analog_destroy(self, sensorid):
        return self._sensor_analog_destroy(sensorid)

    def _sensor_discrete_create(self, hostid, values):
        if utils.is_int_like(hostid):
            host = self.ihost_get(int(hostid))
        elif utils.is_uuid_like(hostid):
            host = self.ihost_get(hostid.strip())
        elif isinstance(hostid, models.ihost):
            host = hostid
        else:
            raise exception.NodeNotFound(node=hostid)

        values['host_id'] = host['id']

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        sensor_discrete = models.SensorsDiscrete()
        sensor_discrete.update(values)
        with _session_for_write() as session:
            try:
                session.add(sensor_discrete)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.SensorAlreadyExists(uuid=values['uuid'])
            return self._sensor_discrete_get(values['uuid'])

    def _sensor_discrete_get(self, sensorid, hostid=None):
        query = model_query(models.SensorsDiscrete)

        if hostid:
            query = query.filter_by(host_id=hostid)

        query = add_sensor_discrete_filter(query, sensorid)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=sensorid)

        return result

    def _sensor_discrete_get_list(self, limit=None, marker=None,
                                  sort_key=None, sort_dir=None):
        return _paginate_query(models.SensorsDiscrete, limit, marker,
                               sort_key, sort_dir)

    def _sensor_discrete_get_all(self, hostid=None, sensorgroupid=None):
        query = model_query(models.SensorsDiscrete, read_deleted="no")
        if hostid:
            query = query.filter_by(host_id=hostid)
        if sensorgroupid:
            query = query.filter_by(sensorgroup_id=hostid)
        return query.all()

    def _sensor_discrete_get_by_host(self, host,
                                     limit=None, marker=None,
                                     sort_key=None, sort_dir=None):
        query = model_query(models.SensorsDiscrete)
        query = add_port_filter_by_host(query, host)
        return _paginate_query(models.SensorsDiscrete, limit, marker,
                               sort_key, sort_dir, query)

    def _sensor_discrete_get_by_isensorgroup(self, sensorgroup,
                                             limit=None, marker=None,
                                             sort_key=None, sort_dir=None):

        query = model_query(models.SensorsDiscrete)
        query = add_sensor_filter_by_sensorgroup(query, sensorgroup)
        return _paginate_query(models.SensorsDiscrete, limit, marker,
                               sort_key, sort_dir, query)

    def _sensor_discrete_get_by_host_isensorgroup(self, host, sensorgroup,
                                                  limit=None, marker=None,
                                                  sort_key=None, sort_dir=None):
        query = model_query(models.SensorsDiscrete)
        query = add_sensor_filter_by_ihost_sensorgroup(query,
                                                       host,
                                                       sensorgroup)
        return _paginate_query(models.SensorsDiscrete, limit, marker,
                               sort_key, sort_dir, query)

    def _sensor_discrete_update(self, sensorid, values, hostid=None):
        with _session_for_write():
            # May need to reserve in multi controller system; ref sysinv
            query = model_query(models.SensorsDiscrete, read_deleted="no")

            if hostid:
                query = query.filter_by(host_id=hostid)

            try:
                query = add_sensor_discrete_filter(query, sensorid)
                result = query.one()
                for k, v in values.items():
                    setattr(result, k, v)
            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for port %s" % sensorid)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for port %s" % sensorid)

            return query.one()

    def _sensor_discrete_destroy(self, sensorid):
        with _session_for_write():
            # Delete port which should cascade to delete SensorsDiscrete
            if uuidutils.is_uuid_like(sensorid):
                model_query(models.Sensors, read_deleted="no").\
                            filter_by(uuid=sensorid).\
                            delete()
            else:
                model_query(models.Sensors, read_deleted="no").\
                            filter_by(id=sensorid).\
                            delete()

    @objects.objectify(objects.sensor_discrete)
    def isensor_discrete_create(self, hostid, values):
        return self._sensor_discrete_create(hostid, values)

    @objects.objectify(objects.sensor_discrete)
    def isensor_discrete_get(self, sensorid, hostid=None):
        return self._sensor_discrete_get(sensorid, hostid)

    @objects.objectify(objects.sensor_discrete)
    def isensor_discrete_get_list(self, limit=None, marker=None,
                                  sort_key=None, sort_dir=None):
        return self._sensor_discrete_get_list(limit, marker, sort_key, sort_dir)

    @objects.objectify(objects.sensor_discrete)
    def isensor_discrete_get_all(self, hostid=None, sensorgroupid=None):
        return self._sensor_discrete_get_all(hostid, sensorgroupid)

    @objects.objectify(objects.sensor_discrete)
    def isensor_discrete_get_by_host(self, host,
                                     limit=None, marker=None,
                                     sort_key=None, sort_dir=None):
        return self._sensor_discrete_get_by_host(host, limit, marker,
                                                 sort_key, sort_dir)

    @objects.objectify(objects.sensor_discrete)
    def isensor_discrete_get_by_isensorgroup(self, sensorgroup,
                                             limit=None, marker=None,
                                             sort_key=None, sort_dir=None):
        return self._sensor_discrete_get_by_isensorgroup(sensorgroup, limit, marker,
                                                         sort_key, sort_dir)

    @objects.objectify(objects.sensor_discrete)
    def isensor_discrete_get_by_host_isensorgroup(self, host, sensorgroup,
                                                  limit=None, marker=None,
                                                  sort_key=None, sort_dir=None):
        return self._sensor_discrete_get_by_host_isensorgroup(host, sensorgroup,
                                                              limit, marker,
                                                              sort_key, sort_dir)

    @objects.objectify(objects.sensor_discrete)
    def isensor_discrete_update(self, sensorid, values, hostid=None):
        return self._sensor_discrete_update(sensorid, values, hostid)

    def isensor_discrete_destroy(self, sensorid):
        return self._sensor_discrete_destroy(sensorid)

    def _isensor_get(self, cls, sensor_id, ihost=None, obj=None):
        session = None
        if obj:
            session = inspect(obj).session
        query = model_query(cls, session=session)
        query = add_sensor_filter(query, sensor_id)
        if ihost:
            query = add_sensor_filter_by_ihost(query, ihost)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                err="No entry found for interface %s" % sensor_id)
        except MultipleResultsFound:
            raise exception.InvalidParameterValue(
                    err="Multiple entries found for interface %s" % sensor_id)

        return result

    def _isensor_create(self, obj, host_id, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        values['host_id'] = int(host_id)

        if 'sensor_profile' in values:
            values.pop('sensor_profile')

        # The id is null for ae sensors with more than one member
        # sensor
        temp_id = obj.id
        obj.update(values)
        if obj.id is None:
            obj.id = temp_id

        with _session_for_write() as session:
            try:
                session.add(obj)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add sensor %s (uuid: %s), an sensor "
                          "with name %s already exists on host %s" %
                          (values['sensorname'],
                           values['uuid'],
                           values['sensorname'],
                           values['host_id']))
                raise exception.SensorAlreadyExists(uuid=values['uuid'])
            return self._isensor_get(type(obj), values['uuid'])

    @objects.objectify(objects.sensor)
    def isensor_create(self, hostid, values):
        if values['datatype'] == 'discrete':
            sensor = models.SensorsDiscrete()
        elif values['datatype'] == 'analog':
            sensor = models.SensorsAnalog()
        else:
            sensor = models.SensorsAnalog()
            LOG.error("default SensorsAnalog due to datatype=%s" %
                      values['datatype'])

        return self._isensor_create(sensor, hostid, values)

    @objects.objectify(objects.sensor)
    def isensor_get(self, sensorid, hostid=None):
        return self._isensor_get(models.Sensors, sensorid, hostid)

    @objects.objectify(objects.sensor)
    def isensor_get_list(self, limit=None, marker=None,
                         sort_key=None, sort_dir=None):
        model_query(models.Sensors)
        return _paginate_query(models.Sensors, limit, marker,
                               sort_key, sort_dir)

    @objects.objectify(objects.sensor)
    def isensor_get_all(self, host_id=None, sensorgroupid=None):
        query = model_query(models.Sensors, read_deleted="no")

        if host_id:
            query = query.filter_by(host_id=host_id)
        if sensorgroupid:
            query = query.filter_by(sensorgroup_id=sensorgroupid)
        return query.all()

    @objects.objectify(objects.sensor)
    def isensor_get_by_ihost(self, ihost,
                             limit=None, marker=None,
                             sort_key=None, sort_dir=None):
        query = model_query(models.Sensors)
        query = add_sensor_filter_by_ihost(query, ihost)
        return _paginate_query(models.Sensors, limit, marker,
                               sort_key, sort_dir, query)

    def _isensor_get_by_sensorgroup(self, cls, sensorgroup,
                                    limit=None, marker=None,
                                    sort_key=None, sort_dir=None):
        query = model_query(cls)
        query = add_sensor_filter_by_sensorgroup(query, sensorgroup)
        return _paginate_query(cls, limit, marker, sort_key, sort_dir, query)

    @objects.objectify(objects.sensor)
    def isensor_get_by_sensorgroup(self, sensorgroup,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        query = model_query(models.Sensors)
        query = add_sensor_filter_by_sensorgroup(query, sensorgroup)
        return _paginate_query(models.Sensors, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.sensor)
    def isensor_get_by_ihost_sensorgroup(self, ihost, sensorgroup,
                                         limit=None, marker=None,
                                         sort_key=None, sort_dir=None):
        query = model_query(models.Sensors)
        query = add_sensor_filter_by_ihost(query, ihost)
        query = add_sensor_filter_by_sensorgroup(query, sensorgroup)
        return _paginate_query(models.Sensors, limit, marker,
                               sort_key, sort_dir, query)

    def _isensor_update(self, cls, sensor_id, values):
        with _session_for_write():
            query = model_query(models.Sensors)
            query = add_sensor_filter(query, sensor_id)
            try:
                result = query.one()
                # obj = self._isensor_get(models.Sensors, sensor_id)
                for k, v in values.items():
                    if v == 'none':
                        v = None
                    setattr(result, k, v)
            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for sensor %s" % sensor_id)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for sensor %s" % sensor_id)

            return query.one()

    @objects.objectify(objects.sensor)
    def isensor_update(self, isensor_id, values):
        with _session_for_write():
            query = model_query(models.Sensors, read_deleted="no")
            query = add_sensor_filter(query, isensor_id)
            try:
                result = query.one()
            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for sensor %s" % isensor_id)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for sensor %s" % isensor_id)

            if result.datatype == 'discrete':
                return self._isensor_update(models.SensorsDiscrete,
                                            isensor_id, values)
            elif result.datatype == 'analog':
                return self._isensor_update(models.SensorsAnalog,
                                            isensor_id, values)
            else:
                return self._isensor_update(models.SensorsAnalog,
                                            isensor_id, values)

    def _isensor_destroy(self, cls, sensor_id):
        with _session_for_write():
            # Delete sensor which should cascade to delete derived sensors
            if uuidutils.is_uuid_like(sensor_id):
                model_query(cls, read_deleted="no").\
                    filter_by(uuid=sensor_id).\
                    delete()
            else:
                model_query(cls, read_deleted="no").\
                    filter_by(id=sensor_id).\
                    delete()

    def isensor_destroy(self, sensor_id):
        return self._isensor_destroy(models.Sensors, sensor_id)

    # SENSOR GROUPS
    @objects.objectify(objects.sensorgroup)
    def isensorgroup_create(self, host_id, values):
        if values['datatype'] == 'discrete':
            sensorgroup = models.SensorGroupsDiscrete()
        elif values['datatype'] == 'analog':
            sensorgroup = models.SensorGroupsAnalog()
        else:
            LOG.error("default SensorsAnalog due to datatype=%s" %
                      values['datatype'])

            sensorgroup = models.SensorGroupsAnalog
        return self._isensorgroup_create(sensorgroup, host_id, values)

    def _isensorgroup_get(self, cls, sensorgroup_id, ihost=None, obj=None):
        query = model_query(cls)
        query = add_sensorgroup_filter(query, sensorgroup_id)
        if ihost:
            query = add_sensorgroup_filter_by_ihost(query, ihost)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                err="No entry found for sensorgroup %s" % sensorgroup_id)
        except MultipleResultsFound:
            raise exception.InvalidParameterValue(
                    err="Multiple entries found for sensorgroup %s" %
                        sensorgroup_id)

        return result

    @objects.objectify(objects.sensorgroup)
    def isensorgroup_get(self, isensorgroup_id, ihost=None):
        return self._isensorgroup_get(models.SensorGroups,
                                      isensorgroup_id,
                                      ihost)

    @objects.objectify(objects.sensorgroup)
    def isensorgroup_get_list(self, limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        query = model_query(models.SensorGroups)
        return _paginate_query(models.SensorGroupsAnalog, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.sensorgroup)
    def isensorgroup_get_by_ihost_sensor(self, ihost, sensor,
                                         limit=None, marker=None,
                                         sort_key=None, sort_dir=None):
        query = model_query(models.SensorGroups)
        query = add_sensorgroup_filter_by_ihost(query, ihost)
        query = add_sensorgroup_filter_by_sensor(query, sensor)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                err="No entry found for host %s port %s" % (ihost, sensor))
        except MultipleResultsFound:
            raise exception.InvalidParameterValue(
                err="Multiple entries found for host %s port %s" %
                    (ihost, sensor))

        return result

    @objects.objectify(objects.sensorgroup)
    def isensorgroup_get_by_ihost(self, ihost,
                                  limit=None, marker=None,
                                  sort_key=None, sort_dir=None):
        query = model_query(models.SensorGroups)
        query = add_sensorgroup_filter_by_ihost(query, ihost)
        return _paginate_query(models.SensorGroups, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.sensorgroup)
    def isensorgroup_update(self, isensorgroup_id, values):
        with _session_for_write():
            query = model_query(models.SensorGroups, read_deleted="no")
            query = add_sensorgroup_filter(query, isensorgroup_id)
            try:
                result = query.one()
            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for sensorgroup %s" % isensorgroup_id)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for sensorgroup %s" %
                        isensorgroup_id)

            if result.datatype == 'discrete':
                return self._isensorgroup_update(models.SensorGroupsDiscrete,
                                                 isensorgroup_id,
                                                 values)
            elif result.datatype == 'analog':
                return self._isensorgroup_update(models.SensorGroupsAnalog,
                                                 isensorgroup_id,
                                                 values)
            else:
                return self._isensorgroup_update(models.SensorGroupsAnalog,
                                                 isensorgroup_id,
                                                 values)

    def isensorgroup_propagate(self, sensorgroup_id, values):
        query = model_query(models.SensorGroups, read_deleted="no")
        query = add_sensorgroup_filter(query, sensorgroup_id)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                err="No entry found for sensorgroup %s" % sensorgroup_id)
        except MultipleResultsFound:
            raise exception.InvalidParameterValue(
                err="Multiple entries found for sensorgroup %s" %
                    sensorgroup_id)

        sensors = self._isensor_get_by_sensorgroup(models.Sensors,
                                                   result.uuid)
        for sensor in sensors:
            LOG.info("sensorgroup update propagate sensor=%s val=%s" %
                     (sensor.sensorname, values))
            self._isensor_update(models.Sensors, sensor.uuid, values)

    def _isensorgroup_create(self, obj, host_id, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        values['host_id'] = int(host_id)

        if 'sensorgroup_profile' in values:
            values.pop('sensorgroup_profile')

        temp_id = obj.id
        obj.update(values)
        if obj.id is None:
            obj.id = temp_id
        with _session_for_write() as session:
            try:
                session.add(obj)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add sensorgroup %s (uuid: %s), an sensorgroup "
                          "with name %s already exists on host %s" %
                          (values['sensorgroupname'],
                           values['uuid'],
                           values['sensorgroupname'],
                           values['host_id']))
                raise exception.SensorGroupAlreadyExists(uuid=values['uuid'])
            return self._isensorgroup_get(type(obj), values['uuid'])

    def _isensorgroup_get_all(self, cls, host_id=None):
        query = model_query(cls, read_deleted="no")
        if utils.is_int_like(host_id):
            query = query.filter_by(host_id=host_id)
        return query.all()

    def _isensorgroup_get_list(self, cls, limit=None, marker=None,
                               sort_key=None, sort_dir=None):
        return _paginate_query(cls, limit, marker, sort_key, sort_dir)

    def _isensorgroup_get_by_ihost_sensor(self, cls, ihost, sensor,
                                          limit=None, marker=None,
                                          sort_key=None, sort_dir=None):

        query = model_query(cls).join(models.Sensors)
        query = add_sensorgroup_filter_by_ihost(query, ihost)
        query = add_sensorgroup_filter_by_sensor(query, sensor)
        return _paginate_query(cls, limit, marker, sort_key, sort_dir, query)

    def _isensorgroup_get_by_ihost(self, cls, ihost,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):

        query = model_query(cls)
        query = add_sensorgroup_filter_by_ihost(query, ihost)
        return _paginate_query(cls, limit, marker, sort_key, sort_dir, query)

    def _isensorgroup_update(self, cls, sensorgroup_id, values):
        with _session_for_write() as session:
            # query = model_query(models.SensorGroups, read_deleted="no")
            query = model_query(cls, read_deleted="no")
            try:
                query = add_sensorgroup_filter(query, sensorgroup_id)
                result = query.one()

                # obj = self._isensorgroup_get(models.SensorGroups,
                obj = self._isensorgroup_get(cls, sensorgroup_id)

                for k, v in values.items():
                    if k == 'algorithm' and v == 'none':
                        v = None
                    if k == 'actions_critical_choices' and v == 'none':
                        v = None
                    if k == 'actions_major_choices' and v == 'none':
                        v = None
                    if k == 'actions_minor_choices' and v == 'none':
                        v = None
                    setattr(result, k, v)

            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for sensorgroup %s" % sensorgroup_id)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for sensorgroup %s" % sensorgroup_id)
            try:
                session.add(obj)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.SensorGroupAlreadyExists(uuid=values['uuid'])
            return query.one()

    def _isensorgroup_destroy(self, cls, sensorgroup_id):
        with _session_for_write():
            # Delete sensorgroup which should cascade to
            # delete derived sensorgroups
            if uuidutils.is_uuid_like(sensorgroup_id):
                model_query(cls, read_deleted="no").\
                    filter_by(uuid=sensorgroup_id).\
                    delete()
            else:
                model_query(cls, read_deleted="no").\
                    filter_by(id=sensorgroup_id).\
                    delete()

    def isensorgroup_destroy(self, sensorgroup_id):
        return self._isensorgroup_destroy(models.SensorGroups, sensorgroup_id)

    @objects.objectify(objects.sensorgroup_analog)
    def isensorgroup_analog_create(self, host_id, values):
        sensorgroup = models.SensorGroupsAnalog()
        return self._isensorgroup_create(sensorgroup, host_id, values)

    @objects.objectify(objects.sensorgroup_analog)
    def isensorgroup_analog_get_all(self, host_id=None):
        return self._isensorgroup_get_all(models.SensorGroupsAnalog, host_id)

    @objects.objectify(objects.sensorgroup_analog)
    def isensorgroup_analog_get(self, sensorgroup_id):
        return self._isensorgroup_get(models.SensorGroupsAnalog,
                                      sensorgroup_id)

    @objects.objectify(objects.sensorgroup_analog)
    def isensorgroup_analog_get_list(self, limit=None, marker=None,
                                     sort_key=None, sort_dir=None):
        return self._isensorgroup_get_list(models.SensorGroupsAnalog,
                                           limit, marker,
                                           sort_key, sort_dir)

    @objects.objectify(objects.sensorgroup_analog)
    def isensorgroup_analog_get_by_ihost(self, ihost,
                                         limit=None, marker=None,
                                         sort_key=None, sort_dir=None):
        return self._isensorgroup_get_by_ihost(models.SensorGroupsAnalog, ihost,
                                               limit, marker,
                                               sort_key, sort_dir)

    @objects.objectify(objects.sensorgroup_analog)
    def isensorgroup_analog_update(self, sensorgroup_id, values):
        return self._isensorgroup_update(models.SensorGroupsAnalog,
                                         sensorgroup_id,
                                         values)

    def isensorgroup_analog_destroy(self, sensorgroup_id):
        return self._isensorgroup_destroy(models.SensorGroupsAnalog,
                                          sensorgroup_id)

    @objects.objectify(objects.sensorgroup_discrete)
    def isensorgroup_discrete_create(self, host_id, values):
        sensorgroup = models.SensorGroupsDiscrete()
        return self._isensorgroup_create(sensorgroup, host_id, values)

    @objects.objectify(objects.sensorgroup_discrete)
    def isensorgroup_discrete_get_all(self, host_id=None):
        return self._isensorgroup_get_all(models.SensorGroupsDiscrete, host_id)

    @objects.objectify(objects.sensorgroup_discrete)
    def isensorgroup_discrete_get(self, sensorgroup_id):
        return self._isensorgroup_get(models.SensorGroupsDiscrete, sensorgroup_id)

    @objects.objectify(objects.sensorgroup_discrete)
    def isensorgroup_discrete_get_list(self, limit=None, marker=None,
                                       sort_key=None, sort_dir=None):
        return self._isensorgroup_get_list(models.SensorGroupsDiscrete,
                                           limit, marker,
                                           sort_key, sort_dir)

    @objects.objectify(objects.sensorgroup_discrete)
    def isensorgroup_discrete_get_by_ihost(self, ihost,
                                           limit=None, marker=None,
                                           sort_key=None, sort_dir=None):
        return self._isensorgroup_get_by_ihost(models.SensorGroupsDiscrete, ihost,
                                               limit, marker, sort_key, sort_dir)

    @objects.objectify(objects.sensorgroup_discrete)
    def isensorgroup_discrete_update(self, sensorgroup_id, values):
        return self._isensorgroup_update(models.SensorGroupsDiscrete,
                                         sensorgroup_id, values)

    def isensorgroup_discrete_destroy(self, sensorgroup_id):
        return self._isensorgroup_destroy(models.SensorGroupsDiscrete, sensorgroup_id)

    @objects.objectify(objects.load)
    def load_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        load = models.Load()
        load.update(values)
        with _session_for_write() as session:
            try:
                session.add(load)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.LoadAlreadyExists(uuid=values['uuid'])
        return load

    @objects.objectify(objects.load)
    def load_get(self, load):
        # load may be passed as a string. It may be uuid or Int.
        query = model_query(models.Load)
        query = add_identity_filter(query, load)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.LoadNotFound(load=load)

        return result

    @objects.objectify(objects.load)
    def load_get_by_version(self, version):
        query = model_query(models.Load)
        query = query.filter_by(software_version=version)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.LoadNotFound(load=version)

        return result

    @objects.objectify(objects.load)
    def load_get_list(self, limit=None, marker=None, sort_key=None,
                      sort_dir=None):

        query = model_query(models.Load)

        return _paginate_query(models.Load, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.load)
    def load_update(self, load, values):
        with _session_for_write() as session:
            query = model_query(models.Load, session=session)
            query = add_identity_filter(query, load)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.LoadNotFound(load=load)
            return query.one()

    def load_destroy(self, load):
        with _session_for_write() as session:
            query = model_query(models.Load, session=session)
            query = add_identity_filter(query, load)

            try:
                query.one()
            except NoResultFound:
                raise exception.LoadNotFound(load=load)

            query.delete()

    def set_upgrade_loads_state(self, upgrade, to_state, from_state):
        with _session_for_write():
            self.load_update(upgrade.from_load, {'state': from_state})
            self.load_update(upgrade.to_load, {'state': to_state})

    def _software_upgrade_get(self, id):
        query = model_query(models.SoftwareUpgrade)
        if utils.is_uuid_like(id):
            query = query.filter_by(uuid=id)
        else:
            query = query.filter_by(id=id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                    err="No software upgrade entry found for %s" % id)

        return result

    @objects.objectify(objects.software_upgrade)
    def software_upgrade_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        upgrade = models.SoftwareUpgrade()
        upgrade.update(values)
        with _session_for_write() as session:
            try:
                session.add(upgrade)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.UpgradeAlreadyExists(uuid=values['uuid'])

            return self._software_upgrade_get(values['uuid'])

    @objects.objectify(objects.software_upgrade)
    def software_upgrade_get(self, id):
        return self._software_upgrade_get(id)

    @objects.objectify(objects.software_upgrade)
    def software_upgrade_get_list(self, limit=None, marker=None,
                                  sort_key=None, sort_dir=None):

        query = model_query(models.SoftwareUpgrade)

        return _paginate_query(models.SoftwareUpgrade, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.software_upgrade)
    def software_upgrade_get_one(self):
        query = model_query(models.SoftwareUpgrade)

        try:
            return query.one()
        except NoResultFound:
            raise exception.NotFound()

    @objects.objectify(objects.software_upgrade)
    def software_upgrade_update(self, uuid, values):
        with _session_for_write() as session:
            query = model_query(models.SoftwareUpgrade, session=session)
            query = query.filter_by(uuid=uuid)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.NotFound(id)
            return query.one()

    def software_upgrade_destroy(self, id):
        with _session_for_write() as session:
            query = model_query(models.SoftwareUpgrade, session=session)
            query = query.filter_by(uuid=id)

            try:
                query.one()
            except NoResultFound:
                raise exception.NotFound(id)

            query.delete()

    def _host_upgrade_create(self, host_id, version, values=None):
        if values is None:
            values = dict()
            if not version:
                systems = self.isystem_get_list()
                if systems is not None:
                    version = systems[0].software_version
                    LOG.info("_host_upgrade_create system version=%s" % version)
            if version:
                # get the load_id from the loads table
                query = model_query(models.Load)
                query = query.filter_by(software_version=version)
                try:
                    result = query.one()
                except NoResultFound:
                    LOG.info("Fail to get load id from load table %s" %
                             version)
                    return None
                values['software_load'] = result.id
                values['target_load'] = result.id
            values['forihostid'] = host_id
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        upgrade = models.HostUpgrade()
        upgrade.update(values)
        with _session_for_write() as session:
            try:
                session.add(upgrade)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.UpgradeAlreadyExists(uuid=values['uuid'])
            return upgrade

    @objects.objectify(objects.host_upgrade)
    def host_upgrade_create(self, host_id, version, values):
        return self._host_upgrade_create(host_id, version, values)

    @objects.objectify(objects.host_upgrade)
    def host_upgrade_get(self, id):
        query = model_query(models.HostUpgrade)

        if utils.is_uuid_like(id):
            query = query.filter_by(uuid=id)
        else:
            query = query.filter_by(id=id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                    err="No host upgrade entry found for %s" % id)

        return result

    @objects.objectify(objects.host_upgrade)
    def host_upgrade_get_by_host(self, host_id):
        query = model_query(models.HostUpgrade)
        query = query.filter_by(forihostid=host_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.NotFound(host_id)

        return result

    @objects.objectify(objects.host_upgrade)
    def host_upgrade_get_list(self, limit=None, marker=None, sort_key=None,
                              sort_dir=None):
        query = model_query(models.HostUpgrade)

        return _paginate_query(models.HostUpgrade, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.host_upgrade)
    def host_upgrade_update(self, object_id, values):
        with _session_for_write() as session:
            query = model_query(models.HostUpgrade, session=session)
            query = query.filter_by(id=object_id)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.NotFound(id)
            session.flush()
            return query.one()

    @objects.objectify(objects.service_parameter)
    def service_parameter_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        parameter = models.ServiceParameter()
        parameter.update(values)
        with _session_for_write() as session:
            try:
                session.add(parameter)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.ServiceParameterAlreadyExists(
                    name=values['name'],
                    service=values['service'],
                    section=values['section'],
                    personality=values.get('personality'),
                    resource=values.get('resource'))
            return parameter

    @objects.objectify(objects.service_parameter)
    def service_parameter_get(self, id):
        query = model_query(models.ServiceParameter)
        if utils.is_uuid_like(id):
            query = query.filter_by(uuid=id)
        else:
            query = query.filter_by(id=id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                err="No service parameter entry found for %s" % id)

        return result

    @objects.objectify(objects.service_parameter)
    def service_parameter_get_one(self, service=None, section=None, name=None,
                                  personality=None, resource=None):
        query = model_query(models.ServiceParameter)
        if service is not None:
            query = query.filter_by(service=service)
        if section is not None:
            query = query.filter_by(section=section)
        if name is not None:
            query = query.filter_by(name=name)
        if personality is not None:
            query = query.filter_by(personality=personality)
        if resource is not None:
            query = query.filter_by(resource=resource)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.NotFound()
        except MultipleResultsFound:
            raise exception.MultipleResults()

        return result

    @objects.objectify(objects.service_parameter)
    def service_parameter_get_list(self, limit=None, marker=None,
                                   sort_key=None, sort_dir=None):

        query = model_query(models.ServiceParameter)

        return _paginate_query(models.ServiceParameter, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.service_parameter)
    def service_parameter_get_all(self, uuid=None, service=None,
                                  section=None, name=None, limit=None,
                                  sort_key=None, sort_dir=None):
        query = model_query(models.ServiceParameter, read_deleted="no")
        if uuid is not None:
            query = query.filter_by(uuid=uuid)
        if service is not None:
            query = query.filter_by(service=service)
        if section is not None:
            query = query.filter_by(section=section)
        if name is not None:
            query = query.filter_by(name=name)
        return _paginate_query(models.ServiceParameter, limit, None,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.service_parameter)
    def service_parameter_update(self, uuid, values):
        with _session_for_write() as session:
            query = model_query(models.ServiceParameter, session=session)
            query = query.filter_by(uuid=uuid)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.NotFound(id)
            session.flush()
            return query.one()

    def service_parameter_destroy_uuid(self, id):
        with _session_for_write() as session:
            query = model_query(models.ServiceParameter, session=session)
            query = query.filter_by(uuid=id)

            try:
                query.one()
            except NoResultFound:
                raise exception.NotFound(id)

            query.delete()

    def service_parameter_destroy(self, name, service, section):
        if not name or not service or not section:
            raise exception.NotFound()

        with _session_for_write() as session:
            query = model_query(models.ServiceParameter, session=session)
            query = query.filter_by(name=name,
                                    service=service,
                                    section=section)
            try:
                query.one()
            except NoResultFound:
                raise exception.NotFound()

            query.delete()

    # Cluster and Peer DB API
    def _cluster_get(self, uuid, session=None):
        query = model_query(models.Clusters, session=session)
        query = add_identity_filter(query, uuid, use_name=True)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.ClusterNotFound(cluster_uuid=uuid)
        return result

    def _cluster_query(self, values, session=None):
        query = model_query(models.Clusters, session=session)
        query = (query.
                 filter(models.Clusters.name == values['name']))
        try:
            result = query.one()
        except NoResultFound:
            raise exception.ClusterNotFoundByName(name=values['name'])
        return result

    @objects.objectify(objects.cluster)
    def cluster_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        cluster = models.Clusters(**values)
        with _session_for_write() as session:
            try:
                session.add(cluster)
                session.flush()
            except db_exc.DBDuplicateEntry:
                exception.ClusterAlreadyExists(uuid=values['uuid'])
            return self._cluster_get(values['uuid'])

    @objects.objectify(objects.cluster)
    def cluster_update(self, cluster_uuid, values):
        with _session_for_write() as session:
            cluster = self._cluster_get(cluster_uuid,
                                        session=session)
            values.pop('peers', [])
            cluster.update(values)
            # if peers:
            #     self._peer_update(session, cluster, peers)
            session.add(cluster)
            session.flush()
            return cluster

    @objects.objectify(objects.cluster)
    def cluster_get(self, cluster_uuid):
        return self._cluster_get(cluster_uuid)

    @objects.objectify(objects.cluster)
    def cluster_query(self, values):
        return self._cluster_query(values)

    @objects.objectify(objects.cluster)
    def clusters_get_list(self, limit=None, marker=None,
                          sort_key=None, sort_dir=None):
        query = model_query(models.Clusters)
        return _paginate_query(models.Clusters, limit, marker,
                               sort_key, sort_dir, query)

    def clusters_get_all(self, uuid=None, name=None, type=None):
        query = model_query(models.Clusters, read_deleted="no")
        if uuid is not None:
            query = query.filter_by(uuid=uuid)
        if name is not None:
            query = query.filter_by(name=name)
        if type is not None:
            query = query.filter_by(type=type)
        cluster_list = []
        try:
            cluster_list = query.all()
        except UnicodeDecodeError:
            LOG.error("UnicodeDecodeError occurred, "
                      "return an empty cluster list.")
        return cluster_list

    def cluster_destroy(self, cluster_uuid):
        query = model_query(models.Clusters)
        query = add_identity_filter(query, cluster_uuid)
        try:
            query.one()
        except NoResultFound:
            raise exception.ClusterNotFound(
                cluster_uuid=cluster_uuid)
        query.delete()

    def _peer_get(self, peer_uuid, session=None):
        query = model_query(models.Peers, session=session)
        query = add_identity_filter(query, peer_uuid, use_name=True)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.PeerNotFound(
                peer_uuid=peer_uuid)
        return result

    @objects.objectify(objects.peer)
    def peer_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        peer = models.Peers(**values)
        with _session_for_write() as session:
            try:
                session.add(peer)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.PeerAlreadyExists(uuid=values['uuid'])
            return self._peer_get(values['uuid'])

    @objects.objectify(objects.peer)
    def peers_get_all_by_cluster(self, cluster_id, name=None):
        # cluster_get() to raise an exception if the isystem is not found
        query = model_query(models.Peers)
        cluster_obj = self.cluster_get(cluster_id)
        query = query.filter_by(cluster_id=cluster_obj.id)
        if name is not None:
            query = query.filter_by(name=name)
        peer_list = []
        try:
            peer_list = query.all()
        except UnicodeDecodeError:
            LOG.error("UnicodeDecodeError occurred, "
                      "return an empty peer list.")
        return peer_list

    @objects.objectify(objects.peer)
    def peer_get(self, peer_uuid):
        return self._peer_get(peer_uuid)

    def _peer_update(self, session, cluster, peers):
        # reset the list of stored peers and then re-add then
        cluster.peers = []
        for name, status in peers:
            peer_values = {'name': name,
                           'status': status,
                           'uuid': uuidutils.generate_uuid()}
            new_peer = models.Peers(**peer_values)
            cluster.peers.append(new_peer)

    def _lldp_agent_get(self, agentid, hostid=None):
        query = model_query(models.LldpAgents)

        if hostid:
            query = query.filter_by(host_id=hostid)

        query = add_lldp_filter_by_agent(query, agentid)

        try:
            return query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=agentid)

    @objects.objectify(objects.lldp_agent)
    def lldp_agent_create(self, portid, hostid, values):
        host = self.ihost_get(hostid)
        port = self.port_get(portid)

        values['host_id'] = host['id']
        values['port_id'] = port['id']

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        lldp_agent = models.LldpAgents()
        lldp_agent.update(values)
        with _session_for_write() as session:
            try:
                session.add(lldp_agent)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add lldp agent %s, on host %s:"
                          "already exists" %
                          (values['uuid'],
                           values['host_id']))
                raise exception.LLDPAgentExists(uuid=values['uuid'],
                                                host=values['host_id'])
            return self._lldp_agent_get(values['uuid'])

    @objects.objectify(objects.lldp_agent)
    def lldp_agent_get(self, agentid, hostid=None):
        return self._lldp_agent_get(agentid, hostid)

    @objects.objectify(objects.lldp_agent)
    def lldp_agent_get_list(self, limit=None, marker=None,
                            sort_key=None, sort_dir=None):
        return _paginate_query(models.LldpAgents, limit, marker,
                               sort_key, sort_dir)

    @objects.objectify(objects.lldp_agent)
    def lldp_agent_get_all(self, hostid=None, portid=None):
        query = model_query(models.LldpAgents, read_deleted="no")
        if hostid:
            query = query.filter_by(host_id=hostid)
        if portid:
            query = query.filter_by(port_id=portid)
        return query.all()

    @objects.objectify(objects.lldp_agent)
    def lldp_agent_get_by_host(self, host,
                               limit=None, marker=None,
                               sort_key=None, sort_dir=None):
        query = model_query(models.LldpAgents)
        query = add_lldp_filter_by_host(query, host)
        return _paginate_query(models.LldpAgents, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.lldp_agent)
    def lldp_agent_get_by_port(self, port):
        query = model_query(models.LldpAgents)
        query = add_lldp_filter_by_port(query, port)
        try:
            return query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                    err="No entry found for agent on port %s" % port)
        except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for agent on port %s" % port)

    @objects.objectify(objects.lldp_agent)
    def lldp_agent_update(self, uuid, values):
        with _session_for_write():
            query = model_query(models.LldpAgents, read_deleted="no")

            try:
                query = add_lldp_filter_by_agent(query, uuid)
                result = query.one()
                for k, v in values.items():
                    setattr(result, k, v)
                return result
            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for agent %s" % uuid)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for agent %s" % uuid)

    def lldp_agent_destroy(self, agentid):

        with _session_for_write():
            query = model_query(models.LldpAgents, read_deleted="no")
            query = add_lldp_filter_by_agent(query, agentid)

            try:
                query.delete()
            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for agent %s" % agentid)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for agent %s" % agentid)

    def _lldp_neighbour_get(self, neighbourid, hostid=None):
        query = model_query(models.LldpNeighbours)

        if hostid:
            query = query.filter_by(host_id=hostid)

        query = add_lldp_filter_by_neighbour(query, neighbourid)

        try:
            return query.one()
        except NoResultFound:
            raise exception.ServerNotFound(server=neighbourid)

    @objects.objectify(objects.lldp_neighbour)
    def lldp_neighbour_create(self, portid, hostid, values):
        if utils.is_int_like(hostid):
            host = self.ihost_get(int(hostid))
        elif utils.is_uuid_like(hostid):
            host = self.ihost_get(hostid.strip())
        elif isinstance(hostid, models.ihost):
            host = hostid
        else:
            raise exception.NodeNotFound(node=hostid)
        if utils.is_int_like(portid):
            port = self.port_get(int(portid))
        elif utils.is_uuid_like(portid):
            port = self.port_get(portid.strip())
        elif isinstance(portid, models.Ports):
            port = portid
        else:
            raise exception.PortNotFound(port=portid)

        values['host_id'] = host['id']
        values['port_id'] = port['id']

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        lldp_neighbour = models.LldpNeighbours()
        lldp_neighbour.update(values)
        with _session_for_write() as session:
            try:
                session.add(lldp_neighbour)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add lldp neighbour %s, on port %s:. "
                          "Already exists with msap %s" %
                          (values['uuid'],
                           values['port_id'],
                           values['msap']))
                raise exception.LLDPNeighbourExists(uuid=values['uuid'])

            return self._lldp_neighbour_get(values['uuid'])

    @objects.objectify(objects.lldp_neighbour)
    def lldp_neighbour_get(self, neighbourid, hostid=None):
        return self._lldp_neighbour_get(neighbourid, hostid)

    @objects.objectify(objects.lldp_neighbour)
    def lldp_neighbour_get_list(self, limit=None, marker=None,
                                sort_key=None, sort_dir=None):
        return _paginate_query(models.LldpNeighbours, limit, marker,
                               sort_key, sort_dir)

    @objects.objectify(objects.lldp_neighbour)
    def lldp_neighbour_get_all(self, hostid=None, interfaceid=None):
        query = model_query(models.LldpNeighbours, read_deleted="no")
        if hostid:
            query = query.filter_by(host_id=hostid)
        if interfaceid:
            query = query.filter_by(interface_id=interfaceid)
        return query.all()

    @objects.objectify(objects.lldp_neighbour)
    def lldp_neighbour_get_by_host(self, host,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        query = model_query(models.LldpNeighbours)
        query = add_port_filter_by_host(query, host)
        return _paginate_query(models.LldpNeighbours, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.lldp_neighbour)
    def lldp_neighbour_get_by_port(self, port,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        query = model_query(models.LldpNeighbours)
        query = add_lldp_filter_by_port(query, port)
        return _paginate_query(models.LldpNeighbours, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.lldp_neighbour)
    def lldp_neighbour_get_by_msap(self, msap,
                                   portid=None,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        query = model_query(models.LldpNeighbours)
        if portid:
            query = query.filter_by(port_id=portid)
        query = query.filter_by(msap=msap)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.LldpNeighbourNotFoundForMsap(msap=msap)

        return result

    @objects.objectify(objects.lldp_neighbour)
    def lldp_neighbour_update(self, uuid, values):
        with _session_for_write():
            query = model_query(models.LldpNeighbours, read_deleted="no")

            try:
                query = add_lldp_filter_by_neighbour(query, uuid)
                result = query.one()
                for k, v in values.items():
                    setattr(result, k, v)
                return result
            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for uuid %s" % uuid)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for uuid %s" % uuid)

    def lldp_neighbour_destroy(self, neighbourid):
        with _session_for_write():
            query = model_query(models.LldpNeighbours, read_deleted="no")
            query = add_lldp_filter_by_neighbour(query, neighbourid)
            try:
                query.delete()
            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for neighbour %s" % neighbourid)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for neighbour %s" % neighbourid)

    def _lldp_tlv_get(self, type, agentid=None, neighbourid=None,
                      session=None):
        if not agentid and not neighbourid:
            raise exception.InvalidParameterValue(
                err="agent id and neighbour id not specified")

        query = model_query(models.LldpTlvs, session=session)

        if agentid:
            query = query.filter_by(agent_id=agentid)

        if neighbourid:
            query = query.filter_by(neighbour_id=neighbourid)

        query = query.filter_by(type=type)

        try:
            return query.one()
        except NoResultFound:
            raise exception.LldpTlvNotFound(type=type)
        except MultipleResultsFound:
            raise exception.InvalidParameterValue(
                err="Multiple entries found")

    @objects.objectify(objects.lldp_tlv)
    def lldp_tlv_create(self, values, agentid=None, neighbourid=None):
        if not agentid and not neighbourid:
            raise exception.InvalidParameterValue(
                err="agent id and neighbour id not specified")

        if agentid:
            if utils.is_int_like(agentid):
                agent = self.lldp_agent_get(int(agentid))
            elif utils.is_uuid_like(agentid):
                agent = self.lldp_agent_get(agentid.strip())
            elif isinstance(agentid, models.LldpAgents):
                agent = agentid
            else:
                raise exception.LldpAgentNotFound(agent=agentid)

        if neighbourid:
            if utils.is_int_like(neighbourid):
                neighbour = self.lldp_neighbour_get(int(neighbourid))
            elif utils.is_uuid_like(neighbourid):
                neighbour = self.lldp_neighbour_get(neighbourid.strip())
            elif isinstance(neighbourid, models.LldpNeighbours):
                neighbour = neighbourid
            else:
                raise exception.LldpNeighbourNotFound(neighbour=neighbourid)

        if agentid:
            values['agent_id'] = agent['id']

        if neighbourid:
            values['neighbour_id'] = neighbour['id']

        lldp_tlv = models.LldpTlvs()
        lldp_tlv.update(values)
        with _session_for_write() as session:
            try:
                session.add(lldp_tlv)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add lldp tlv %s"
                          "already exists" % (values['type']))
                raise exception.LLDPTlvExists(uuid=values['id'])
            return self._lldp_tlv_get(values['type'],
                                      agentid=values.get('agent_id'),
                                      neighbourid=values.get('neighbour_id'))

    @objects.objectify(objects.lldp_tlv)
    def lldp_tlv_create_bulk(self, values, agentid=None, neighbourid=None):
        if not agentid and not neighbourid:
            raise exception.InvalidParameterValue(
                err="agent id and neighbour id not specified")

        if agentid:
            if utils.is_int_like(agentid):
                agent = self.lldp_agent_get(int(agentid))
            elif utils.is_uuid_like(agentid):
                agent = self.lldp_agent_get(agentid.strip())
            elif isinstance(agentid, models.LldpAgents):
                agent = agentid
            else:
                raise exception.LldpAgentNotFound(agent=agentid)

        if neighbourid:
            if utils.is_int_like(neighbourid):
                neighbour = self.lldp_neighbour_get(int(neighbourid))
            elif utils.is_uuid_like(neighbourid):
                neighbour = self.lldp_neighbour_get(neighbourid.strip())
            elif isinstance(neighbourid, models.LldpNeighbours):
                neighbour = neighbourid
            else:
                raise exception.LldpNeighbourNotFound(neighbour=neighbourid)

        tlvs = []
        with _session_for_write() as session:
            for entry in values:
                lldp_tlv = models.LldpTlvs()
                if agentid:
                    entry['agent_id'] = agent['id']

                if neighbourid:
                    entry['neighbour_id'] = neighbour['id']

                lldp_tlv.update(entry)
                session.add(lldp_tlv)

                lldp_tlv = self._lldp_tlv_get(
                    entry['type'],
                    agentid=entry.get('agent_id'),
                    neighbourid=entry.get('neighbour_id'),
                    session=session)

                tlvs.append(lldp_tlv)

        return tlvs

    @objects.objectify(objects.lldp_tlv)
    def lldp_tlv_get(self, type, agentid=None, neighbourid=None):
        return self._lldp_tlv_get(type, agentid, neighbourid)

    @objects.objectify(objects.lldp_tlv)
    def lldp_tlv_get_by_id(self, id, agentid=None, neighbourid=None):
        query = model_query(models.LldpTlvs)

        query = query.filter_by(id=id)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.LldpTlvNotFound(id=id)
        except MultipleResultsFound:
            raise exception.InvalidParameterValue(
                err="Multiple entries found")

        return result

    @objects.objectify(objects.lldp_tlv)
    def lldp_tlv_get_list(self, limit=None, marker=None,
                          sort_key=None, sort_dir=None):
        return _paginate_query(models.LldpTlvs, limit, marker,
                               sort_key, sort_dir)

    @objects.objectify(objects.lldp_tlv)
    def lldp_tlv_get_all(self, agentid=None, neighbourid=None):
        query = model_query(models.LldpTlvs, read_deleted="no")
        if agentid:
            query = query.filter_by(agent_id=agentid)
        if neighbourid:
            query = query.filter_by(neighbour_id=neighbourid)
        return query.all()

    @objects.objectify(objects.lldp_tlv)
    def lldp_tlv_get_by_agent(self, agent,
                              limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        query = model_query(models.LldpTlvs)
        query = add_lldp_tlv_filter_by_agent(query, agent)
        return _paginate_query(models.LldpTlvs, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.lldp_tlv)
    def lldp_tlv_get_by_neighbour(self, neighbour,
                                  limit=None, marker=None,
                                  sort_key=None, sort_dir=None):

        query = model_query(models.LldpTlvs)
        query = add_lldp_tlv_filter_by_neighbour(query, neighbour)
        return _paginate_query(models.LldpTlvs, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.lldp_tlv)
    def lldp_tlv_update(self, values, agentid=None, neighbourid=None):
        if not agentid and not neighbourid:
                raise exception.InvalidParameterValue(
                    err="agent id and neighbour id not specified")

        with _session_for_write():
            query = model_query(models.LldpTlvs, read_deleted="no")

            if agentid:
                query = add_lldp_tlv_filter_by_agent(query, agentid)

            if neighbourid:
                query = add_lldp_tlv_filter_by_neighbour(query,
                                                         neighbourid)

            query = query.filter_by(type=values['type'])

            try:
                result = query.one()
                for k, v in values.items():
                    setattr(result, k, v)
                return result
            except NoResultFound:
                raise exception.InvalidParameterValue(
                    err="No entry found for tlv")
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found")

    @objects.objectify(objects.lldp_tlv)
    def lldp_tlv_update_bulk(self, values, agentid=None, neighbourid=None):
        results = []

        if not agentid and not neighbourid:
            raise exception.InvalidParameterValue(
                err="agent id and neighbour id not specified")

        with _session_for_write() as session:
            for entry in values:
                query = model_query(models.LldpTlvs, read_deleted="no")

                if agentid:
                    query = query.filter_by(agent_id=agentid)

                if neighbourid:
                    query = query.filter_by(neighbour_id=neighbourid)

                query = query.filter_by(type=entry['type'])

                try:
                    result = query.one()
                    result.update(entry)
                    session.merge(result)
                except NoResultFound:
                    raise exception.InvalidParameterValue(
                        err="No entry found for tlv")
                except MultipleResultsFound:
                    raise exception.InvalidParameterValue(
                        err="Multiple entries found")

                results.append(result)
        return results

    def lldp_tlv_destroy(self, id):
        with _session_for_write():
            model_query(models.LldpTlvs, read_deleted="no").\
                filter_by(id=id).\
                delete()

    @objects.objectify(objects.sdn_controller)
    def sdn_controller_create(self, values):

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        sdn_controller = models.sdn_controller()
        sdn_controller.update(values)
        with _session_for_write() as session:
            try:
                session.add(sdn_controller)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add SDN controller %s. "
                          "Already exists with this uuid" %
                          (values['uuid']))
                raise exception.SDNControllerAlreadyExists(uuid=values['uuid'])
            return sdn_controller

    @objects.objectify(objects.sdn_controller)
    def sdn_controller_get(self, uuid):
        query = model_query(models.sdn_controller)
        query = query.filter_by(uuid=uuid)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                err="No SDN controller entry found for %s" % uuid)
        return result

    @objects.objectify(objects.sdn_controller)
    def sdn_controller_get_list(self, limit=None, marker=None,
                                sort_key=None, sort_dir=None):
        query = model_query(models.sdn_controller)

        return _paginate_query(models.sdn_controller, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.sdn_controller)
    def sdn_controller_update(self, uuid, values):
        with _session_for_write() as session:
            query = model_query(models.sdn_controller, session=session)
            query = query.filter_by(uuid=uuid)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.SDNControllerNotFound(uuid)
            return query.one()

    def sdn_controller_destroy(self, uuid):
        with _session_for_write() as session:
            query = model_query(models.sdn_controller, session=session)
            query = query.filter_by(uuid=uuid)

            try:
                query.one()
            except NoResultFound:
                raise exception.SDNControllerNotFound(uuid)
            query.delete()

    @objects.objectify(objects.tpmconfig)
    def tpmconfig_create(self, values):

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        tpmconfig = models.tpmconfig()
        tpmconfig.update(values)
        with _session_for_write() as session:
            try:
                session.add(tpmconfig)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add TPM configuration %s. "
                          "Already exists with this uuid" %
                          (values['uuid']))
                raise exception.TPMConfigAlreadyExists(uuid=values['uuid'])
            return tpmconfig

    @objects.objectify(objects.tpmconfig)
    def tpmconfig_get(self, uuid):
        query = model_query(models.tpmconfig)
        query = query.filter_by(uuid=uuid)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                err="No TPM configuration entry found for %s" % uuid)
        return result

    @objects.objectify(objects.tpmconfig)
    def tpmconfig_get_one(self):
        query = model_query(models.tpmconfig)
        try:
            return query.one()
        except NoResultFound:
            raise exception.NotFound()

    @objects.objectify(objects.tpmconfig)
    def tpmconfig_get_list(self, limit=None, marker=None,
                           sort_key=None, sort_dir=None):
        query = model_query(models.tpmconfig)

        return _paginate_query(models.tpmconfig, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.tpmconfig)
    def tpmconfig_update(self, uuid, values):
        with _session_for_write() as session:
            query = model_query(models.tpmconfig, session=session)
            query = query.filter_by(uuid=uuid)

            count = query.update(values, synchronize_session='fetch')
            if count == 0:
                raise exception.TPMConfigNotFound(uuid)
            return query.one()

    def tpmconfig_destroy(self, uuid):
        with _session_for_write() as session:
            query = model_query(models.tpmconfig, session=session)
            query = query.filter_by(uuid=uuid)

            try:
                query.one()
            except NoResultFound:
                raise exception.TPMConfigNotFound(uuid)
            query.delete()

    def _tpmdevice_get(self, tpmdevice_id):
        query = model_query(models.tpmdevice)
        query = add_identity_filter(query, tpmdevice_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.TPMDeviceNotFound(uuid=tpmdevice_id)
        return result

    @objects.objectify(objects.tpmdevice)
    def tpmdevice_create(self, host_id, values):

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        values['host_id'] = int(host_id)

        tpmdevice = models.tpmdevice()
        tpmdevice.update(values)
        with _session_for_write() as session:
            try:
                session.add(tpmdevice)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add TPM device configuration %s. "
                          "Already exists with this uuid" %
                          (values['uuid']))
                raise exception.TPMDeviceAlreadyExists(uuid=values['uuid'])
            return self._tpmdevice_get(values['uuid'])

    @objects.objectify(objects.tpmdevice)
    def tpmdevice_get(self, uuid):
        query = model_query(models.tpmdevice)
        query = query.filter_by(uuid=uuid)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                err="No TPM device entry found for %s" % uuid)
        return result

    @objects.objectify(objects.tpmdevice)
    def tpmdevice_get_list(self, limit=None, marker=None,
                           sort_key=None, sort_dir=None):
        query = model_query(models.tpmdevice)
        return _paginate_query(models.tpmdevice, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.tpmdevice)
    def tpmdevice_get_by_host(self, host_id,
                              limit=None, marker=None,
                              sort_key=None, sort_dir=None):

        query = model_query(models.tpmdevice)

        if utils.is_int_like(host_id):
            query = query.filter_by(host_id=host_id)
        else:
            query = query.join(models.ihost,
                               models.tpmdevice.host_id == models.ihost.id)
            query = query.filter(models.ihost.uuid == host_id)

        return _paginate_query(models.tpmdevice, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.tpmdevice)
    def tpmdevice_update(self, uuid, values):
        with _session_for_write() as session:
            query = model_query(models.tpmdevice, session=session)
            query = query.filter_by(uuid=uuid)

            count = query.update(values, synchronize_session='fetch')
            if count == 0:
                raise exception.TPMDeviceNotFound(uuid)
            return query.one()

    def tpmdevice_destroy(self, uuid):
        with _session_for_write() as session:
            query = model_query(models.tpmdevice, session=session)
            query = query.filter_by(uuid=uuid)

            try:
                query.one()
            except NoResultFound:
                raise exception.TPMDeviceNotFound(uuid)
            query.delete()

    @objects.objectify(objects.certificate)
    def certificate_create(self, values):

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        certificate = models.certificate()
        certificate.update(values)
        with _session_for_write() as session:
            try:
                session.add(certificate)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add Certificate %s. "
                          "Already exists with this uuid" %
                          (values['uuid']))
                raise exception.CertificateAlreadyExists(uuid=values['uuid'])
            return certificate

    @objects.objectify(objects.certificate)
    def certificate_get(self, uuid):
        query = model_query(models.certificate)
        query = query.filter_by(uuid=uuid)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                err="No Certificate entry found for %s" % uuid)
        return result

    @objects.objectify(objects.certificate)
    def certificate_get_one(self):
        query = model_query(models.certificate)
        try:
            return query.one()
        except NoResultFound:
            raise exception.NotFound()

    @objects.objectify(objects.certificate)
    def certificate_get_by_certtype(self, certtype):
        query = model_query(models.certificate)
        query = query.filter_by(certtype=certtype)

        try:
            return query.one()
        except NoResultFound:
            raise exception.CertificateTypeNotFound(certtype=certtype)

    @objects.objectify(objects.certificate)
    def certificate_get_list(self, limit=None, marker=None,
                           sort_key=None, sort_dir=None):
        query = model_query(models.certificate)

        return _paginate_query(models.certificate, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.certificate)
    def certificate_update(self, uuid, values):
        with _session_for_write() as session:
            query = model_query(models.certificate, session=session)
            query = query.filter_by(uuid=uuid)

            count = query.update(values, synchronize_session='fetch')
            if count == 0:
                raise exception.CertificateNotFound(uuid)
            return query.one()

    def certificate_destroy(self, uuid):
        with _session_for_write() as session:
            query = model_query(models.certificate, session=session)
            query = query.filter_by(uuid=uuid)

            try:
                query.one()
            except NoResultFound:
                raise exception.CertificateNotFound(uuid)
            query.delete()

    def _helm_override_get(self, app_id, name, namespace):
        query = model_query(models.HelmOverrides)
        query = query.filter_by(
            app_id=app_id, name=name, namespace=namespace)
        try:
            return query.one()
        except NoResultFound:
            raise exception.HelmOverrideNotFound(name=name,
                                                 namespace=namespace)

    @objects.objectify(objects.helm_overrides)
    def helm_override_create(self, values):

        overrides = models.HelmOverrides()
        overrides.update(values)
        with _session_for_write() as session:
            try:
                session.add(overrides)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add HelmOverrides %s. "
                          "Already exists with this name" %
                          (values['name']))
                raise exception.HelmOverrideAlreadyExists(
                    name=values['name'], namespace=values['namespace'])
            return self._helm_override_get(values['app_id'],
                                           values['name'],
                                           values['namespace'])

    @objects.objectify(objects.helm_overrides)
    def helm_override_get(self, app_id, name, namespace):
        return self._helm_override_get(app_id, name, namespace)

    @objects.objectify(objects.helm_overrides)
    def helm_override_get_all(self, app_id):
        query = model_query(models.HelmOverrides, read_deleted="no")
        query = query.filter_by(app_id=app_id)
        return query.all()

    @objects.objectify(objects.helm_overrides)
    def helm_override_update(self, app_id, name, namespace, values):
        with _session_for_write() as session:
            query = model_query(models.HelmOverrides, session=session)
            query = query.filter_by(
                app_id=app_id, name=name, namespace=namespace)

            count = query.update(values, synchronize_session='fetch')
            if count == 0:
                raise exception.HelmOverrideNotFound(name=name,
                                                     namespace=namespace)
            return query.one()

    def helm_override_destroy(self, app_id, name, namespace):
        with _session_for_write() as session:
            query = model_query(models.HelmOverrides, session=session)
            query = query.filter_by(
                app_id=app_id, name=name, namespace=namespace)

            try:
                query.one()
            except NoResultFound:
                raise exception.HelmOverrideNotFound(name=name,
                                                     namespace=namespace)
            query.delete()

    def _label_get(self, label_id):
        query = model_query(models.Label)
        query = add_identity_filter(query, label_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.HostLabelNotFound(uuid=label_id)
        return result

    @objects.objectify(objects.label)
    def label_create(self, host_uuid, values):

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        values['host_uuid'] = host_uuid

        host_label = models.Label()
        host_label.update(values)
        with _session_for_write() as session:
            try:
                session.add(host_label)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add host label %s. "
                          "Already exists with this uuid" %
                          (values['label_key']))
                raise exception.HostLabelAlreadyExists(
                    label=values['label_key'], host=values['host_uuid'])
            return self._label_get(values['uuid'])

    @objects.objectify(objects.label)
    def label_get(self, uuid):
        query = model_query(models.Label)
        query = query.filter_by(uuid=uuid)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                err="No label entry found for %s" % uuid)
        return result

    @objects.objectify(objects.label)
    def label_get_all(self, hostid=None):
        query = model_query(models.Label, read_deleted="no")
        if hostid:
            query = query.filter_by(host_id=hostid)
        return query.all()

    @objects.objectify(objects.label)
    def label_update(self, uuid, values):
        with _session_for_write() as session:
            query = model_query(models.Label, session=session)
            query = query.filter_by(uuid=uuid)

            count = query.update(values, synchronize_session='fetch')
            if count == 0:
                raise exception.HostLabelNotFound(uuid)
            return query.one()

    def label_destroy(self, uuid):
        with _session_for_write() as session:
            query = model_query(models.Label, session=session)
            query = query.filter_by(uuid=uuid)
            try:
                query.one()
            except NoResultFound:
                raise exception.HostLabelNotFound(uuid)
            query.delete()

    @objects.objectify(objects.label)
    def label_get_by_host(self, host,
                          limit=None, marker=None,
                          sort_key=None, sort_dir=None):
        query = model_query(models.Label)
        query = add_label_filter_by_host(query, host)
        return _paginate_query(models.Label, limit, marker,
                               sort_key, sort_dir, query)

    def _label_query(self, host_id, label_key, session=None):
        query = model_query(models.Label, session=session)
        query = query.filter(models.Label.host_id == host_id)
        query = query.filter(models.Label.label_key == label_key)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.HostLabelNotFoundByKey(label=label_key)
        return result

    @objects.objectify(objects.label)
    def label_query(self, host_id, label_key):
        return self._label_query(host_id, label_key)

    def count_hosts_by_label(self, label):
        query = model_query(models.Label, read_deleted="no")
        query = query.filter(models.Label.label_key == label)
        return query.count()

    def _kube_app_get(self, name):
        query = model_query(models.KubeApp)
        query = query.filter(
            models.KubeApp.name == name,
            models.KubeApp.status != constants.APP_INACTIVE_STATE)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.KubeAppNotFound(name=name)
        return result

    @objects.objectify(objects.kube_app)
    def kube_app_get_inactive(self, name, limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        query = model_query(models.KubeApp)
        query = query.filter(
            models.KubeApp.name == name,
            models.KubeApp.status == constants.APP_INACTIVE_STATE)
        return _paginate_query(models.KubeApp, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.kube_app)
    def kube_app_get_inactive_by_name_version(self, name, version):
        query = model_query(models.KubeApp)
        query = query.filter(
            models.KubeApp.name == name,
            models.KubeApp.app_version == version,
            models.KubeApp.status == constants.APP_INACTIVE_STATE)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.KubeAppInactiveNotFound(name=name,
                                                    version=version)
        return result

    @objects.objectify(objects.kube_app)
    def kube_app_create(self, values):
        app = models.KubeApp()
        app.update(values)
        with _session_for_write() as session:
            try:
                session.add(app)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add application %s. "
                          "Already exists with this name"
                          "and version" % (values['name']))
                raise exception.KubeAppAlreadyExists(
                    name=values['name'],
                    version=values['app_version'])
            return self.kube_app_get(values['name'])

    @objects.objectify(objects.kube_app)
    def kube_app_get_all(self):
        query = model_query(models.KubeApp)
        query = query.filter(
            models.KubeApp.status != constants.APP_INACTIVE_STATE)
        return query.all()

    @objects.objectify(objects.kube_app)
    def kube_app_get(self, name):
        return self._kube_app_get(name)

    @objects.objectify(objects.kube_app)
    def kube_app_update(self, app_id, values):
        with _session_for_write() as session:
            query = model_query(models.KubeApp, session=session)
            query = query.filter_by(id=app_id)

            count = query.update(values, synchronize_session='fetch')
            if count == 0:
                raise exception.KubeAppNotFound(name=values.get('name'))
            return query.one()

    def kube_app_destroy(self, name, version=None, inactive=False):
        with _session_for_write() as session:
            query = model_query(models.KubeApp, session=session)
            query = query.filter_by(name=name)
            if version:
                query = query.filter_by(app_version=version)
            if inactive:
                query = query.filter_by(
                    status=constants.APP_INACTIVE_STATE)

            if query.all():
                query.delete()

    @objects.objectify(objects.kube_app_releases)
    def kube_app_chart_release_get(self, app_id, release, namespace):
        query = model_query(models.KubeAppReleases)
        query = query.filter(models.KubeAppReleases.app_id == app_id,
                             models.KubeAppReleases.release == release,
                             models.KubeAppReleases.namespace == namespace)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.KubeAppChartReleaseNotFound(
                name=release,
                namespace=namespace,
                app_id=app_id)
        return result

    @objects.objectify(objects.kube_app_releases)
    def kube_app_chart_release_update(self, app_id, release, namespace, values):
        with _session_for_write() as session:
            query = model_query(models.KubeAppReleases, session=session)
            query = query.filter(models.KubeAppReleases.app_id == app_id,
                                 models.KubeAppReleases.release == release,
                                 models.KubeAppReleases.namespace == namespace)

            count = query.update(values, synchronize_session='fetch')
            if count == 0:
                raise exception.KubeAppChartReleaseNotFound(
                    name=release,
                    namespace=namespace,
                    app_id=app_id)
            return query.one()

    @objects.objectify(objects.kube_app_releases)
    def kube_app_chart_release_create(self, values):
        app_release = models.KubeAppReleases()
        app_release.update(values)
        with _session_for_write() as session:
            try:
                session.add(app_release)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add chart release %s for application %s. "
                          "Already exists with this name %s and namespace %s" %
                          (values['release'], values['app_id'],
                           values['release'], values['namespace']))
                raise exception.KubeAppChartReleaseAlreadyExists(
                    name=values['release'], namespace=values['namespace'],
                    app_id=values['app_id'])

            return self.kube_app_chart_release_get(
                values['app_id'], values['release'], values['namespace'])

    @objects.objectify(objects.kube_app_releases)
    def kube_app_chart_release_get_all(self, app_id, limit=None, marker=None,
                                       sort_key=None, sort_dir=None):
        query = model_query(models.KubeAppReleases)
        query = query.filter(
            models.KubeAppReleases.app_id == app_id)
        return _paginate_query(models.KubeAppReleases, limit, marker,
                               sort_key, sort_dir, query)

    def _datanetwork_get(self, model_class, datanetwork_id, obj=None):
        session = None
        if obj:
            session = inspect(obj).session
        query = model_query(model_class, session=session)

        query = add_datanetwork_filter(query, datanetwork_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.DataNetworkNotFound(
                datanetwork_uuid=datanetwork_id)
        except MultipleResultsFound:
            raise exception.InvalidParameterValue(
                    err="Multiple entries found for datanetwork %s" % datanetwork_id)
        return result

    def _datanetwork_get_one(self, datanetwork_id, datanetwork=None):
        entity = with_polymorphic(models.DataNetworks, '*')
        query = model_query(entity)
        query = add_datanetwork_filter(query, datanetwork_id)
        if datanetwork is not None:
            query = query.filter_by(network_type=datanetwork)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.DataNetworkNotFound(
                datanetwork_uuid=datanetwork_id)
        except MultipleResultsFound:
            raise exception.InvalidParameterValue(
                err="Multiple entries found for datanetwork %s" % datanetwork_id)

        return result

    def _datanetwork_create(self, obj, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        with _session_for_write() as session:
            # The id is null for ae interfaces with more than one member interface
            temp_id = obj.id
            obj.update(values)
            if obj.id is None:
                obj.id = temp_id

            try:
                session.add(obj)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add datanetwork (uuid: %s), "
                          "name %s already exists." %
                          (values['uuid'], values.get('name')))

                raise exception.DataNetworkAlreadyExists(
                    name=values.get('name'))

        return self._datanetwork_get(type(obj), values['uuid'])

    @objects.objectify(objects.datanetwork)
    def datanetwork_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        network_type = values.get('network_type')
        if network_type == constants.DATANETWORK_TYPE_FLAT:
            datanetwork = models.DataNetworksFlat()
        elif network_type == constants.DATANETWORK_TYPE_VLAN:
            datanetwork = models.DataNetworksVlan()
        elif network_type == constants.DATANETWORK_TYPE_VXLAN:
            datanetwork = models.DataNetworksVXlan()
        else:
            raise exception.DataNetworkTypeUnsupported(
                network_type=network_type)
        return self._datanetwork_create(datanetwork, values)

    @objects.objectify(objects.datanetwork)
    def datanetwork_get(self, datanetwork_id):
        return self._datanetwork_get_one(datanetwork_id)

    def _add_datanetworks_filters(self, query, filters):
        if filters is None:
            filters = dict()
        supported_filters = {'network_type',
                             'name',
                             }
        unsupported_filters = set(filters).difference(supported_filters)
        if unsupported_filters:
            msg = _("SqlAlchemy API does not support "
                    "filtering by %s") % ', '.join(unsupported_filters)
            raise ValueError(msg)

        for field in supported_filters:
            if field in filters:
                query = query.filter_by(**{field: filters[field]})

        return query

    @objects.objectify(objects.datanetwork)
    def datanetworks_get_all(self, filters=None, limit=None, marker=None,
                             sort_key=None, sort_dir=None):

        with _session_for_read() as session:
            datanetworks = with_polymorphic(models.DataNetworks, '*')
            query = model_query(datanetworks, session=session)
            query = self._add_datanetworks_filters(query, filters)

        return _paginate_query(models.DataNetworks, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.datanetwork)
    def datanetwork_update(self, datanetwork_uuid, values):
        with _session_for_write() as session:
            query = model_query(models.DataNetworks, session=session)
            query = add_identity_filter(query, datanetwork_uuid)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.DataNetworkNotFound(
                    datanetwork_uuid=datanetwork_uuid)
            return query.one()

    def datanetwork_destroy(self, datanetwork_uuid):
        query = model_query(models.DataNetworks)
        query = add_identity_filter(query, datanetwork_uuid)
        try:
            query.one()
        except NoResultFound:
            raise exception.DataNetworkNotFound(
                datanetwork_uuid=datanetwork_uuid)
        query.delete()

    def _interface_datanetwork_get(self, uuid, session=None):
        query = model_query(models.InterfaceDataNetworks, session=session)
        query = add_identity_filter(query, uuid)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.InterfaceDataNetworkNotFound(uuid=uuid)
        return result

    def _interface_datanetwork_get_all(
            self, limit=None, marker=None,
            sort_key=None, sort_dir=None):
        query = model_query(models.InterfaceDataNetworks)
        return _paginate_query(
            models.InterfaceDataNetworks, limit, marker,
            sort_key, sort_dir, query)

    def _interface_datanetwork_get_by_host(
            self, host_uuid, limit=None, marker=None,
            sort_key=None, sort_dir=None):

        query = model_query(models.InterfaceDataNetworks)
        query = (query.
                 join(models.Interfaces).
                 join(models.ihost,
                      models.ihost.id == models.Interfaces.forihostid))
        query, field = add_filter_by_many_identities(
            query, models.ihost, [host_uuid])
        return _paginate_query(
            models.InterfaceDataNetworks, limit, marker,
            sort_key, sort_dir, query)

    def _interface_datanetwork_get_by_interface(
            self, interface_uuid, limit=None, marker=None,
            sort_key=None, sort_dir=None):
        query = model_query(models.InterfaceDataNetworks)
        query = (query.join(models.Interfaces))
        query, field = add_filter_by_many_identities(
            query, models.Interfaces, [interface_uuid])
        return _paginate_query(models.InterfaceDataNetworks,
                               limit, marker, sort_key, sort_dir, query)

    def _interface_datanetwork_get_by_datanetwork(
            self, datanetwork_uuid, limit=None, marker=None,
            sort_key=None, sort_dir=None):
        query = model_query(models.InterfaceDataNetworks)
        query = (query.join(models.DataNetworks))
        query, field = add_filter_by_many_identities(
            query, models.DataNetworks, [datanetwork_uuid])
        return _paginate_query(models.InterfaceDataNetworks,
                               limit, marker, sort_key, sort_dir, query)

    def _interface_datanetwork_query(self, values):
        query = model_query(models.InterfaceDataNetworks)
        query = (query.
                 filter(models.InterfaceDataNetworks.interface_id ==
                        values['interface_id']).
                 filter(models.InterfaceDataNetworks.datanetwork_id ==
                        values['datanetwork_id']))
        try:
            result = query.one()
        except NoResultFound:
            raise exception.InterfaceDataNetworkNotFoundByKeys(
                interface_id=values['interface_id'],
                datanetwork_id=values['datanetwork_id'])
        return result

    @objects.objectify(objects.interface_datanetwork)
    def interface_datanetwork_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        interface_datanetwork = models.InterfaceDataNetworks(**values)
        with _session_for_write() as session:
            try:
                session.add(interface_datanetwork)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.InterfaceDataNetworkAlreadyExists(
                    interface_id=values['interface_id'],
                    datanetwork_id=values['datanetwork_id'])
            return self._interface_datanetwork_get(values['uuid'], session)

    @objects.objectify(objects.interface_datanetwork)
    def interface_datanetwork_get(self, uuid):
        return self._interface_datanetwork_get(uuid)

    @objects.objectify(objects.interface_datanetwork)
    def interface_datanetwork_get_all(
            self, limit=None, marker=None,
            sort_key=None, sort_dir=None):
        return self._interface_datanetwork_get_all(
            limit, marker, sort_key, sort_dir)

    @objects.objectify(objects.interface_datanetwork)
    def interface_datanetwork_get_by_host(
            self, host_id, limit=None, marker=None,
            sort_key=None, sort_dir=None):
        return self._interface_datanetwork_get_by_host(
            host_id, limit, marker, sort_key, sort_dir)

    @objects.objectify(objects.interface_datanetwork)
    def interface_datanetwork_get_by_interface(
            self, interface_id, limit=None, marker=None,
            sort_key=None, sort_dir=None):
        return self._interface_datanetwork_get_by_interface(
            interface_id, limit, marker, sort_key, sort_dir)

    @objects.objectify(objects.interface_datanetwork)
    def interface_datanetwork_get_by_datanetwork(
            self, datanetwork_id, limit=None, marker=None,
            sort_key=None, sort_dir=None):
        return self._interface_datanetwork_get_by_datanetwork(
            datanetwork_id, limit, marker, sort_key, sort_dir)

    def interface_datanetwork_destroy(self, uuid):
        query = model_query(models.InterfaceDataNetworks)
        query = add_identity_filter(query, uuid)
        try:
            query.one()
        except NoResultFound:
            raise exception.InterfaceDataNetworkNotFound(uuid=uuid)
        query.delete()

    @objects.objectify(objects.interface_datanetwork)
    def interface_datanetwork_query(self, values):
        return self._interface_datanetwork_query(values)

    def _host_fs_get(self, fs_id):
        query = model_query(models.HostFs)
        query = add_identity_filter(query, fs_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.FilesystemNotFound(fs_id=fs_id)

        return result

    @objects.objectify(objects.host_fs)
    def host_fs_create(self, forihostid, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        values['forihostid'] = int(forihostid)
        fs = models.HostFs()
        fs.update(values)
        with _session_for_write() as session:
            try:
                session.add(fs)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.FilesystemAlreadyExists(
                    name=values['name'], host=forihostid)

            return self._host_fs_get(values['uuid'])

    @objects.objectify(objects.host_fs)
    def host_fs_get_all(self, forihostid=None):
        query = model_query(models.HostFs, read_deleted="no")
        if forihostid:
            query = query.filter_by(forihostid=forihostid)
        return query.all()

    @objects.objectify(objects.host_fs)
    def host_fs_get(self, fs_id):
        return self._host_fs_get(fs_id)

    @objects.objectify(objects.host_fs)
    def host_fs_get_list(self, limit=None, marker=None,
                         sort_key=None, sort_dir=None):
        return _paginate_query(models.HostFs, limit, marker,
                               sort_key, sort_dir)

    @objects.objectify(objects.host_fs)
    def host_fs_get_by_ihost(self, ihost, limit=None, marker=None,
                             sort_key=None, sort_dir=None):

        query = model_query(models.HostFs)
        query = add_host_fs_filter_by_ihost(query, ihost)
        return _paginate_query(models.HostFs, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.host_fs)
    def host_fs_update(self, fs_id, values):
        with _session_for_write() as session:
            query = model_query(models.HostFs, read_deleted="no",
                                session=session)
            query = add_host_fs_filter(query, fs_id)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.FilesystemNotFound(fs_id=fs_id)
            return query.one()

    def host_fs_destroy(self, fs_id):
        with _session_for_write() as session:
            # Delete physically since it has unique columns
            if uuidutils.is_uuid_like(fs_id):
                model_query(models.HostFs, read_deleted="no",
                            session=session).\
                    filter_by(uuid=fs_id).\
                    delete()
            else:
                model_query(models.HostFs, read_deleted="no").\
                    filter_by(id=fs_id).\
                    delete()

    def _kube_host_upgrade_get(self, host_upgrade_id):
        query = model_query(models.KubeHostUpgrade)
        query = add_identity_filter(query, host_upgrade_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.KubeHostUpgradeNotFound(
                host_upgrade_id=host_upgrade_id)

        return result

    def _kube_host_upgrade_create(self, host_id, values=None):
        if values is None:
            values = dict()
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        values['host_id'] = int(host_id)
        upgrade = models.KubeHostUpgrade()
        upgrade.update(values)
        with _session_for_write() as session:
            try:
                session.add(upgrade)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.KubeHostUpgradeAlreadyExists(
                    uuid=values['uuid'], host=host_id)
            return self._kube_host_upgrade_get(values['uuid'])

    @objects.objectify(objects.kube_host_upgrade)
    def kube_host_upgrade_create(self, host_id, values):
        return self._kube_host_upgrade_create(host_id, values)

    @objects.objectify(objects.kube_host_upgrade)
    def kube_host_upgrade_get(self, host_upgrade_id):
        return self._kube_host_upgrade_get(host_upgrade_id)

    @objects.objectify(objects.kube_host_upgrade)
    def kube_host_upgrade_get_list(self, limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        query = model_query(models.KubeHostUpgrade)
        # Only retrieve host upgrade records associated with actual hosts
        # (not host profiles).
        query = query.join(models.ihost,
                           models.KubeHostUpgrade.host_id == models.ihost.id)
        query = query.filter(models.ihost.recordtype == "standard")

        return _paginate_query(models.KubeHostUpgrade, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.kube_host_upgrade)
    def kube_host_upgrade_get_by_host(self, host_id):
        query = model_query(models.KubeHostUpgrade)
        query = add_kube_host_upgrade_filter_by_host(query, host_id)
        return query.one()

    @objects.objectify(objects.kube_host_upgrade)
    def kube_host_upgrade_update(self, host_upgrade_id, values):
        with _session_for_write() as session:
            query = model_query(models.KubeHostUpgrade, read_deleted="no",
                                session=session)
            query = add_kube_host_upgrade_filter(query, host_upgrade_id)

            count = query.update(values, synchronize_session='fetch')

            if count != 1:
                raise exception.KubeHostUpgradeNotFound(
                    host_upgrade_id=host_upgrade_id)
            return query.one()

    def kube_host_upgrade_destroy(self, host_upgrade_id):
        with _session_for_write() as session:
            # Delete physically since it has unique columns
            if uuidutils.is_uuid_like(host_upgrade_id):
                model_query(models.KubeHostUpgrade,
                            read_deleted="no", session=session).filter_by(
                    uuid=host_upgrade_id).delete()
            else:
                model_query(models.KubeHostUpgrade, read_deleted="no").\
                    filter_by(id=host_upgrade_id).delete()

    def _kube_upgrade_get(self, upgrade_id):
        query = model_query(models.KubeUpgrade)
        query = add_identity_filter(query, upgrade_id)

        try:
            return query.one()
        except NoResultFound:
            raise exception.KubeUpgradeNotFound(upgrade_id=upgrade_id)

    @objects.objectify(objects.kube_upgrade)
    def kube_upgrade_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        kube_upgrade = models.KubeUpgrade()
        kube_upgrade.update(values)
        with _session_for_write() as session:
            try:
                session.add(kube_upgrade)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.KubeUpgradeAlreadyExists(uuid=values['uuid'])
            return self._kube_upgrade_get(values['uuid'])

    @objects.objectify(objects.kube_upgrade)
    def kube_upgrade_get(self, upgrade_id):
        return self._kube_upgrade_get(upgrade_id)

    @objects.objectify(objects.kube_upgrade)
    def kube_upgrade_get_one(self):
        query = model_query(models.KubeUpgrade)

        try:
            return query.one()
        except NoResultFound:
            raise exception.NotFound()

    @objects.objectify(objects.kube_upgrade)
    def kube_upgrade_get_list(self, limit=None, marker=None,
                              sort_key=None, sort_dir=None):

        query = model_query(models.KubeUpgrade)

        return _paginate_query(models.KubeUpgrade, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.kube_upgrade)
    def kube_upgrade_update(self, upgrade_id, values):
        with _session_for_write() as session:
            query = model_query(models.KubeUpgrade, session=session)
            query = add_identity_filter(query, upgrade_id)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.KubeUpgradeNotFound(upgrade_id=upgrade_id)
            return query.one()

    def kube_upgrade_destroy(self, upgrade_id):
        with _session_for_write() as session:
            query = model_query(models.KubeUpgrade, session=session)
            query = add_identity_filter(query, upgrade_id)

            try:
                query.one()
            except NoResultFound:
                raise exception.KubeUpgradeNotFound(upgrade_id=upgrade_id)
            query.delete()

    def _deviceimage_get(self, model_class, deviceimage_id, obj=None):
        session = None
        if obj:
            session = inspect(obj).session
        query = model_query(model_class, session=session)

        query = add_deviceimage_filter(query, deviceimage_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.DeviceImageNotFound(
                deviceimage_uuid=deviceimage_id)
        except MultipleResultsFound:
            raise exception.InvalidParameterValue(
                    err="Multiple entries found for deviceimage %s" % deviceimage_id)
        return result

    def _deviceimage_get_one(self, deviceimage_id, deviceimage=None):
        entity = with_polymorphic(models.DeviceImage, '*')
        query = model_query(entity)
        query = add_deviceimage_filter(query, deviceimage_id)
        if deviceimage is not None:
            query = query.filter_by(network_type=deviceimage)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.DeviceImageNotFound(
                deviceimage_uuid=deviceimage_id)
        except MultipleResultsFound:
            raise exception.InvalidParameterValue(
                err="Multiple entries found for deviceimage %s" % deviceimage_id)

        return result

    def _deviceimage_create(self, obj, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        with _session_for_write() as session:
            # The id is null for ae interfaces with more than one member interface
            temp_id = obj.id
            obj.update(values)
            if obj.id is None:
                obj.id = temp_id

            try:
                session.add(obj)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add deviceimage (uuid: %s), "
                          "name %s already exists." %
                          (values['uuid'], values.get('name')))

                raise exception.DeviceImageAlreadyExists(
                    name=values.get('name'))

        return self._deviceimage_get(type(obj), values['uuid'])

    @objects.objectify(objects.device_image)
    def deviceimage_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        bitstream_type = values.get('bitstream_type')
        if bitstream_type == dconstants.BITSTREAM_TYPE_ROOT_KEY:
            deviceimage = models.DeviceImageRootKey()
        elif bitstream_type == dconstants.BITSTREAM_TYPE_FUNCTIONAL:
            deviceimage = models.DeviceImageFunctional()
        elif bitstream_type == dconstants.BITSTREAM_TYPE_KEY_REVOCATION:
            deviceimage = models.DeviceImageKeyRevocation()
        else:
            raise exception.DeviceImageTypeUnsupported(
                bitstream_type=bitstream_type)
        return self._deviceimage_create(deviceimage, values)

    @objects.objectify(objects.device_image)
    def deviceimage_get(self, deviceimage_id):
        return self._deviceimage_get_one(deviceimage_id)

    def _add_deviceimage_filters(self, query, filters):
        if filters is None:
            filters = dict()
        supported_filters = {'bitstream_type',
                             'name',
                             }
        unsupported_filters = set(filters).difference(supported_filters)
        if unsupported_filters:
            msg = _("SqlAlchemy API does not support "
                    "filtering by %s") % ', '.join(unsupported_filters)
            raise ValueError(msg)

        for field in supported_filters:
            if field in filters:
                query = query.filter_by(**{field: filters[field]})

        return query

    @objects.objectify(objects.device_image)
    def deviceimages_get_all(self, filters=None, limit=None, marker=None,
                             sort_key=None, sort_dir=None):

        with _session_for_read() as session:
            deviceimages = with_polymorphic(models.DeviceImage, '*')
            query = model_query(deviceimages, session=session)
            query = self._add_deviceimage_filters(query, filters)

        return _paginate_query(models.DeviceImage, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.device_image)
    def deviceimage_update(self, deviceimage_uuid, values):
        with _session_for_write() as session:
            query = model_query(models.DeviceImage, session=session)
            query = add_identity_filter(query, deviceimage_uuid)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.DeviceImageNotFound(
                    deviceimage_uuid=deviceimage_uuid)
            return query.one()

    def deviceimage_destroy(self, deviceimage_uuid):
        query = model_query(models.DeviceImage)
        query = add_identity_filter(query, deviceimage_uuid)
        try:
            query.one()
        except NoResultFound:
            raise exception.DeviceImageNotFound(
                deviceimage_uuid=deviceimage_uuid)
        query.delete()

    def _device_label_get(self, device_label_id):
        query = model_query(models.DeviceLabel)
        query = add_identity_filter(query, device_label_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.DeviceLabelNotFound(uuid=device_label_id)
        return result

    @objects.objectify(objects.device_label)
    def device_label_create(self, device_uuid, values):

        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        values['device_uuid'] = device_uuid

        host_device_label = models.DeviceLabel()
        host_device_label.update(values)
        with _session_for_write() as session:
            try:
                session.add(host_device_label)
                session.flush()
            except db_exc.DBDuplicateEntry:
                LOG.error("Failed to add host device label %s. "
                          "Already exists with this uuid" %
                          (values['label_key']))
                raise exception.DeviceLabelAlreadyExists(
                    label=values['label_key'], host=values['host_uuid'])
            return self._device_label_get(values['uuid'])

    @objects.objectify(objects.device_label)
    def device_label_get(self, uuid):
        query = model_query(models.DeviceLabel)
        query = query.filter_by(uuid=uuid)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                err="No device label entry found for %s" % uuid)
        return result

    @objects.objectify(objects.device_label)
    def device_label_get_all(self, deviceid=None):
        query = model_query(models.DeviceLabel, read_deleted="no")
        if deviceid:
            query = query.filter_by(device_id=deviceid)
        return query.all()

    @objects.objectify(objects.device_label)
    def device_label_get_list(self, limit=None, marker=None,
                              sort_key=None, sort_dir=None):
        return _paginate_query(models.DeviceLabel, limit, marker,
                               sort_key, sort_dir)

    @objects.objectify(objects.device_label)
    def device_label_get_by_label(self, label_key, label_value,
                                  limit=None, marker=None,
                                  sort_key=None, sort_dir=None):
        query = model_query(models.DeviceLabel)
        query = query.filter_by(label_key=label_key,
                                label_value=label_value)
        return _paginate_query(models.DeviceLabel, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.device_label)
    def device_label_update(self, uuid, values):
        with _session_for_write() as session:
            query = model_query(models.DeviceLabel, session=session)
            query = query.filter_by(uuid=uuid)

            count = query.update(values, synchronize_session='fetch')
            if count == 0:
                raise exception.DeviceLabelNotFound(uuid)
            return query.one()

    def device_label_destroy(self, uuid):
        with _session_for_write() as session:
            query = model_query(models.DeviceLabel, session=session)
            query = add_identity_filter(query, uuid)
            try:
                query.one()
            except NoResultFound:
                raise exception.DeviceLabelNotFound(uuid)
            query.delete()

    @objects.objectify(objects.device_label)
    def device_label_get_by_device(self, device_uuid,
                          limit=None, marker=None,
                          sort_key=None, sort_dir=None):
        query = model_query(models.DeviceLabel)
        query = query.filter_by(pcidevice_uuid=device_uuid)
        return _paginate_query(models.DeviceLabel, limit, marker,
                               sort_key, sort_dir, query)

    def _device_label_query(self, device_id, label_key, session=None):
        query = model_query(models.DeviceLabel, session=session)
        query = query.filter(models.DeviceLabel.pcidevice_id == device_id)
        query = query.filter(models.DeviceLabel.label_key == label_key)
        return query.all()

    @objects.objectify(objects.device_label)
    def device_label_query(self, device_id, label_key):
        return self._device_label_query(device_id, label_key)

    def count_hosts_by_device_label(self, device_label):
        query = model_query(models.DeviceLabel, read_deleted="no")
        query = query.filter(models.DeviceLabel.label_key == device_label)
        return query.count()

    def _device_image_label_get(self, device_image_label_id):
        query = model_query(models.DeviceImageLabel)
        query = add_identity_filter(query, device_image_label_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.DeviceLabelNotFound(uuid=device_image_label_id)
        return result

    @objects.objectify(objects.device_image_label)
    def device_image_label_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()

        device_image_label = models.DeviceImageLabel()
        device_image_label.update(values)
        with _session_for_write() as session:
            try:
                session.add(device_image_label)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.DeviceImageLabelAlreadyExists(
                    uuid=values['uuid'])
            return self._device_image_label_get(values['uuid'])

    @objects.objectify(objects.device_image_label)
    def device_image_label_get(self, uuid):
        query = model_query(models.DeviceImageLabel)
        query = query.filter_by(uuid=uuid)
        try:
            result = query.one()
        except NoResultFound:
            raise exception.InvalidParameterValue(
                err="No device image label entry found for %s" % uuid)
        return result

    @objects.objectify(objects.device_image_label)
    def device_image_label_update(self, uuid, values):
        with _session_for_write() as session:
            query = model_query(models.DeviceImageLabel, session=session)
            query = query.filter_by(uuid=uuid)

            count = query.update(values, synchronize_session='fetch')
            if count == 0:
                raise exception.DeviceImageLabelNotFound(uuid)
            return query.one()

    @objects.objectify(objects.device_image_label)
    def device_image_label_get_by_image(self, image_id,
                                  limit=None, marker=None,
                                  sort_key=None, sort_dir=None):
        query = model_query(models.DeviceImageLabel)
        query = query.filter_by(image_id=image_id)
        return query.all()

    @objects.objectify(objects.device_image_label)
    def device_image_label_get_by_label(self, label_id,
                                  limit=None, marker=None,
                                  sort_key=None, sort_dir=None):
        query = model_query(models.DeviceImageLabel)
        query = query.filter_by(label_id=label_id)
        return query.all()

    @objects.objectify(objects.device_image_label)
    def device_image_label_get_by_image_label(self, image_id, label_id,
                                  limit=None, marker=None,
                                  sort_key=None, sort_dir=None):
        query = model_query(models.DeviceImageLabel)
        query = query.filter_by(image_id=image_id, label_id=label_id)
        try:
            return query.one()
        except NoResultFound:
            raise exception.DeviceImageLabelNotFoundByKey(
                image_id=image_id, label_id=label_id)

    def device_image_label_destroy(self, id):
        with _session_for_write() as session:
            query = model_query(models.DeviceImageLabel, session=session)
            query = add_identity_filter(query, id)

            try:
                query.one()
            except NoResultFound:
                raise exception.DeviceImageLabelNotFound(uuid=id)
            query.delete()

    def _device_image_state_get(self, id):
        query = model_query(models.DeviceImageState)
        query = add_identity_filter(query, id)

        try:
            return query.one()
        except NoResultFound:
            raise exception.DeviceImageStateNotFound(id=id)

    @objects.objectify(objects.device_image_state)
    def device_image_state_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        device_image_state = models.DeviceImageState()
        device_image_state.update(values)
        with _session_for_write() as session:
            try:
                session.add(device_image_state)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.DeviceImageStateAlreadyExists(uuid=values['uuid'])
            return self._device_image_state_get(values['uuid'])

    @objects.objectify(objects.device_image_state)
    def device_image_state_get(self, id):
        return self._device_image_state_get(id)

    @objects.objectify(objects.device_image_state)
    def device_image_state_get_one(self):
        query = model_query(models.DeviceImageState)

        try:
            return query.one()
        except NoResultFound:
            raise exception.NotFound()

    @objects.objectify(objects.device_image_state)
    def device_image_state_get_list(self, limit=None, marker=None,
                              sort_key=None, sort_dir=None):

        query = model_query(models.DeviceImageState)

        return _paginate_query(models.DeviceImageState, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.device_image_state)
    def device_image_state_update(self, id, values):
        with _session_for_write() as session:
            query = model_query(models.DeviceImageState, session=session)
            query = add_identity_filter(query, id)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.DeviceImageStateNotFound(id=id)
            return query.one()

    def device_image_state_destroy(self, id):
        with _session_for_write() as session:
            query = model_query(models.DeviceImageState, session=session)
            query = add_identity_filter(query, id)

            try:
                query.one()
            except NoResultFound:
                raise exception.DeviceImageStateNotFound(id=id)
            query.delete()

    @objects.objectify(objects.device_image_state)
    def device_image_state_get_by_image_device(self, image_id, pcidevice_id,
                                               limit=None, marker=None,
                                               sort_key=None, sort_dir=None):
        query = model_query(models.DeviceImageState)
        query = query.filter_by(image_id=image_id,
                                pcidevice_id=pcidevice_id)
        try:
            return query.one()
        except NoResultFound:
            raise exception.DeviceImageStateNotFoundByKey(image_id=image_id,
                    device_id=pcidevice_id)

    @objects.objectify(objects.device_image_state)
    def device_image_state_get_all(self, host_id=None, pcidevice_id=None,
                                   image_id=None, status=None,
                                   limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        query = model_query(models.DeviceImageState)
        if host_id:
            query = query.filter_by(host_id=host_id)
        if pcidevice_id:
            query = query.filter_by(pcidevice_id=pcidevice_id)
        if image_id:
            query = query.filter_by(image_id=image_id)
        if status:
            if isinstance(status, list):
                query = query.filter(models.DeviceImageState.status.in_(status))
            else:
                query = query.filter_by(status=status)
        return query.all()

    def _restore_get(self, id):
        query = model_query(models.Restore)
        if utils.is_uuid_like(id):
            query = query.filter_by(uuid=id)
        else:
            query = query.filter_by(id=id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.RestoreNotFound(uuid=id)

        return result

    @objects.objectify(objects.restore)
    def restore_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        restore = models.Restore()
        restore.update(values)
        with _session_for_write() as session:
            try:
                session.add(restore)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.RestoreAlreadyExists(uuid=values['uuid'])

            return restore

    @objects.objectify(objects.restore)
    def restore_get(self, id):
        return self._restore_get(id)

    @objects.objectify(objects.restore)
    def restore_get_list(self, limit=None, marker=None,
                         sort_key=None, sort_dir=None):
        query = model_query(models.Restore)

        return _paginate_query(models.Restore, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.restore)
    def restore_get_one(self, filters):
        query = model_query(models.Restore)

        for key in filters if filters else {}:
            query = query.filter(getattr(models.Restore, key).in_([filters[key]]))

        try:
            return query.one()
        except NoResultFound:
            raise exception.NotFound()

    @objects.objectify(objects.restore)
    def restore_update(self, uuid, values):
        with _session_for_write() as session:
            query = model_query(models.Restore, session=session)
            query = query.filter_by(uuid=uuid)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.RestoreNotFound(uuid=uuid)
            return query.one()

    def restore_destroy(self, id):
        with _session_for_write() as session:
            query = model_query(models.Restore, session=session)
            query = query.filter_by(uuid=id)

            try:
                query.one()
            except NoResultFound:
                raise exception.RestoreNotFound(uuid=id)

            query.delete()

    def _kube_rootca_host_update_get(self, rootca_host_update_id):
        query = model_query(models.KubeRootCAHostUpdate)
        query = add_identity_filter(query, rootca_host_update_id)

        try:
            result = query.one()
        except NoResultFound:
            raise exception.KubeRootCAHostUpdateNotFound(
                rootca_host_update_id=rootca_host_update_id)

        return result

    def _kube_rootca_host_update_create(self, host_id, values=None):
        if values is None:
            values = dict()
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        values['host_id'] = int(host_id)
        ca_update = models.KubeRootCAHostUpdate()
        ca_update.update(values)
        with _session_for_write() as session:
            try:
                session.add(ca_update)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.KubeRootCAHostUpdateAlreadyExists(
                    uuid=values['uuid'], host=host_id)
            return self._kube_rootca_host_update_get(values['uuid'])

    @objects.objectify(objects.kube_rootca_host_update)
    def kube_rootca_host_update_create(self, host_id, values):
        return self._kube_rootca_host_update_create(host_id, values)

    @objects.objectify(objects.kube_rootca_host_update)
    def kube_rootca_host_update_get(self, rootca_host_update_id):
        return self._kube_rootca_host_update_get(rootca_host_update_id)

    @objects.objectify(objects.kube_rootca_host_update)
    def kube_rootca_host_update_get_by_host(self, host_id):
        query = model_query(models.KubeRootCAHostUpdate)
        query = add_kube_rootca_host_update_filter_by_host(query, host_id)
        try:
            return query.one()
        except NoResultFound:
            raise exception.NotFound()

    @objects.objectify(objects.kube_rootca_host_update)
    def kube_rootca_host_update_update(self, rootca_host_update_id, values):
        with _session_for_write() as session:
            query = model_query(models.KubeRootCAHostUpdate, read_deleted="no",
                                session=session)
            query = add_identity_filter(query, rootca_host_update_id)

            count = query.update(values, synchronize_session='fetch')

            if count != 1:
                raise exception.KubeRootCAHostUpdateNotFound(
                    rootca_host_update_id=rootca_host_update_id)
            return query.one()

    def kube_rootca_host_update_destroy(self, rootca_host_update_id):
        with _session_for_write() as session:
            # Delete physically since it has unique columns
            if uuidutils.is_uuid_like(rootca_host_update_id):
                model_query(models.KubeRootCAHostUpdate,
                            read_deleted="no", session=session).filter_by(
                    uuid=rootca_host_update_id).delete()
            else:
                model_query(models.KubeRootCAHostUpdate, read_deleted="no").\
                    filter_by(id=rootca_host_update_id).delete()

    def _kube_rootca_update_get(self, rootca_update_id):
        query = model_query(models.KubeRootCAUpdate)
        query = add_identity_filter(query, rootca_update_id)

        try:
            return query.one()
        except NoResultFound:
            raise exception.KubeRootCAUpdateNotFound(rootca_update_id=rootca_update_id)

    @objects.objectify(objects.kube_rootca_update)
    def kube_rootca_update_create(self, values):
        if not values.get('uuid'):
            values['uuid'] = uuidutils.generate_uuid()
        kube_rootca_update = models.KubeRootCAUpdate()
        kube_rootca_update.update(values)
        with _session_for_write() as session:
            try:
                session.add(kube_rootca_update)
                session.flush()
            except db_exc.DBDuplicateEntry:
                raise exception.KubeRootCAUpdateAlreadyExists(uuid=values['uuid'])
            return self._kube_rootca_update_get(values['uuid'])

    @objects.objectify(objects.kube_rootca_update)
    def kube_rootca_update_get(self, rootca_update_id):
        return self._kube_rootca_update_get(rootca_update_id)

    @objects.objectify(objects.kube_rootca_update)
    def kube_rootca_update_get_one(self):
        query = model_query(models.KubeRootCAUpdate)

        try:
            return query.one()
        except NoResultFound:
            raise exception.NotFound()

    @objects.objectify(objects.kube_rootca_update)
    def kube_rootca_update_get_list(self, limit=None, marker=None,
                              sort_key=None, sort_dir=None):

        query = model_query(models.KubeRootCAUpdate)

        return _paginate_query(models.KubeRootCAUpdate, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.kube_rootca_host_update)
    def kube_rootca_host_update_get_list(self, limit=None, marker=None,
                                   sort_key=None, sort_dir=None):
        query = model_query(models.KubeRootCAHostUpdate)
        return _paginate_query(models.KubeRootCAHostUpdate, limit, marker,
                               sort_key, sort_dir, query)

    @objects.objectify(objects.kube_rootca_update)
    def kube_rootca_update_update(self, rootca_update_id, values):
        with _session_for_write() as session:
            query = model_query(models.KubeRootCAUpdate, session=session)
            query = add_identity_filter(query, rootca_update_id)

            count = query.update(values, synchronize_session='fetch')
            if count != 1:
                raise exception.KubeRootCAUpdateNotFound(rootca_update_id=rootca_update_id)
            return self._kube_rootca_update_get(rootca_update_id)

    def kube_rootca_update_destroy(self, rootca_update_id):
        with _session_for_write() as session:
            query = model_query(models.KubeRootCAUpdate, session=session)
            query = add_identity_filter(query, rootca_update_id)

            try:
                query.one()
            except NoResultFound:
                raise exception.KubeRootCAUpdateNotFound(rootca_update_id=rootca_update_id)
            query.delete()
