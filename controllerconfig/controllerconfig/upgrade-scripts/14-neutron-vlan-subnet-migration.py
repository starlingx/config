#!/usr/bin/env python
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will migrate away from using vlan-tagged subnets,
# to using separate networks with their compute ports trunked
# from the network the vlan-tagged subnet was on.
# Once all of the compute nodes are updates, the old vlan-tagged
# subnets, as well as all of the ports on them, will be deleted.
import os
import psycopg2
import subprocess
import sys
import uuid

from psycopg2.extras import RealDictCursor

from controllerconfig.common import log

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
            migrate_vlan()
        except Exception as ex:
            LOG.exception(ex)
            print ex
            return 1

    if from_release == "17.06" and action == "activate":
        try:
            cleanup_neutron_vlan_subnets()
        except Exception as ex:
            LOG.exception(ex)
            print ex
            return 1


def run_cmd(cur, cmd):
    cur.execute(cmd)


def run_cmd_postgres(sub_cmd):
    """
    This executes the given command as user postgres.  This is necessary when
    this script is run as root, which is the case on an upgrade activation.
    """
    error_output = open(os.devnull, 'w')
    cmd = ("sudo -u postgres psql -d neutron -c \"%s\"" % sub_cmd)
    LOG.info("Executing '%s'" % cmd)
    subprocess.check_call([cmd], shell=True, stderr=error_output)


def migrate_vlan():
    conn = psycopg2.connect("dbname=neutron user=postgres")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            create_new_networks(cur)


def cleanup_neutron_vlan_subnets():
    """
    This function cleans up data leftover from migrating away from using
    vlan-tagged subnets.  Specifically, it deletes all non-compute ports
    on vlan-tagged subnets, as well as all vlan-tagged subnets.
    """
    cmd = ("DELETE FROM ports WHERE id in"
           " (SELECT port_id FROM ipallocations AS ipa"
           " JOIN subnets AS s ON ipa.subnet_id = s.id"
           " where s.vlan_id!=0)"
           " AND device_owner not like 'compute:%';")
    run_cmd_postgres(cmd)

    cmd = "DELETE FROM subnets WHERE vlan_id != 0;"
    run_cmd_postgres(cmd)


def create_new_networks(cur):
    """
    This function creates new networks for each network segment belonging to
    a vlan-tagged subnet, and clones those subnets minus the vlan ID.
    For each of those cloned subnets, it also clones all of the ports on them,
    as well as all of the IP allocations, and the bindings
    """
    cmd = ("SELECT s.vlan_id, s.network_id, m2ss.network_type,"
           " m2ss.physical_network,  m2ss.segmentation_id FROM subnets AS s"
           " JOIN ml2_subnet_segments AS m2ss ON s.id = m2ss.subnet_id"
           " WHERE s.vlan_id != 0 GROUP BY s.vlan_id, s.network_id,"
           " m2ss.network_type, m2ss.physical_network, m2ss.segmentation_id;")
    run_cmd(cur, cmd)
    networks_to_create = []
    while True:
        network = cur.fetchone()
        if network is None:
            break
        networks_to_create.append(network)

    for network in networks_to_create:
        create_and_populate_network(cur, network)


def create_standard_attribute(cur, name):
    """
    This function creates new standard attribute entries to be used by copied
    data.
    """
    cmd = ("INSERT INTO standardattributes (resource_type)"
           " VALUES ('%s') RETURNING id") %\
          (name,)
    run_cmd(cur, cmd)
    return cur.fetchone()['id']


def create_and_populate_network(cur, network):
    """
    This function takes a network segment, and copies all the data on that
    network segment to a newly-created network. For each compute port on the
    original network, a port trunk should be created from the original port
    as a parent, to the new port as a subport.  This relaces the vlan id being
    set on an individual subnet.
    """
    vlan_id = network['vlan_id']
    network_type = network['network_type']
    old_network_id = network['network_id']
    # This new network ID should be the same as neutron passes to vswitch for
    # the network-uuid of the network segment for the vlan-tagged subnet.
    network_suffix = "vlan%s" % vlan_id
    new_network_id = uuid.uuid5(uuid.UUID(old_network_id), network_suffix)
    new_networksegment_id = uuid.uuid4()
    cmd = ("INSERT INTO networks (project_id, id, name, status,"
           "admin_state_up, vlan_transparent, standard_attr_id,"
           " availability_zone_hints)"
           " (SELECT project_id, '%s',"
           " CONCAT_WS('-VLAN%d', NULLIF(name,''), ''), status,"
           " admin_state_up, vlan_transparent, '%s', availability_zone_hints"
           " FROM networks WHERE id = '%s') RETURNING id;") %\
          (new_network_id, vlan_id,
           create_standard_attribute(cur, 'networks'), old_network_id)
    run_cmd(cur, cmd)
    old_network_id = network['network_id']
    new_network_id = cur.fetchone()['id']

    cmd = ("INSERT INTO networksegments (id, network_id, network_type,"
           " physical_network, segmentation_id, is_dynamic, segment_index,"
           " standard_attr_id, name)"
           " VALUES('%s','%s','%s','%s','%s','%s','%s','%s','%s')") %\
          (new_networksegment_id, new_network_id, network_type,
           network['physical_network'], network['segmentation_id'],
           'f', '0', create_standard_attribute(cur, 'networksegments'), '')
    run_cmd(cur, cmd)

    # Get a list of vlan-tagged subnets on the network we are copying.
    # For each of these subnets, we loop through and copy them, and then loop
    # through the ip allocations on them and copy those ip allocations, along
    # with the ports that are in those ip allocations.
    sub_cmd = ("SELECT id FROM subnets"
               " WHERE vlan_id = '%s' AND network_id='%s'") %\
              (vlan_id, old_network_id)

    # Copy the subnets to the new network
    run_cmd(cur, sub_cmd)
    subnets = cur.fetchall()
    subnet_copies = {}
    for subnet in subnets:
        old_subnet_id = subnet['id']
        new_subnet_id = uuid.uuid4()
        new_ml2_subnet_segment_id = uuid.uuid4()
        subnet_copies[old_subnet_id] = new_subnet_id
        cmd = ("INSERT INTO subnets"
               " (project_id, id, name, network_id, ip_version, cidr,"
               " gateway_ip,  enable_dhcp, ipv6_ra_mode, ipv6_address_mode,"
               " subnetpool_id, vlan_id, standard_attr_id, segment_id)"
               " (SELECT project_id, '%s', name, '%s', ip_version, cidr,"
               " gateway_ip, enable_dhcp, ipv6_ra_mode, ipv6_address_mode,"
               " subnetpool_id, 0, '%s', segment_id"
               " FROM subnets WHERE id='%s')") %\
              (new_subnet_id, new_network_id,
               create_standard_attribute(cur, 'subnets'), old_subnet_id)
        run_cmd(cur, cmd)
        cmd = ("INSERT INTO ml2_subnet_segments"
               " (id, subnet_id, network_type, physical_network,"
               " segmentation_id, is_dynamic, segment_index)"
               " (SELECT '%s', '%s', network_type, physical_network,"
               " segmentation_id, is_dynamic, segment_index"
               " FROM ml2_subnet_segments WHERE subnet_id='%s')") %\
              (new_ml2_subnet_segment_id, new_subnet_id, old_subnet_id)
        run_cmd(cur, cmd)
        duplicate_ipam_subnets(cur, old_subnet_id, new_subnet_id)
        duplicate_ipallocationpools(cur, old_subnet_id, new_subnet_id)

    # Copy the ports that are related to vlan subnets such that those new
    # ports are directly attached to the network that was created to replace
    # the vlan subnet.  We ignore DHCP ports because since both the vlan
    # subnet and the new network will share the same provider network we do
    # not want 2 ports with the same IP to exist simultaneously.  Instead,
    # we let the DHCP server allocate this port when it notices that it is
    # missing which will result in a new IP allocation and should not
    # interfere with any existing allocations because they have all been
    # cloned onto the new network.
    cmd = ("SELECT DISTINCT port_id FROM ipallocations"
           " LEFT JOIN ports AS p ON p.id = ipallocations.port_id"
           " WHERE p.device_owner != 'network:dhcp'"
           " AND subnet_id IN (%s)") % sub_cmd
    run_cmd(cur, cmd)
    ports_to_copy = cur.fetchall()
    port_copies = {}
    for port in ports_to_copy:
        old_port_id = port['port_id']
        new_port_id = uuid.uuid4()
        port_copies[old_port_id] = new_port_id
        cmd = ("INSERT INTO ports (project_id, id, name, network_id,"
               " mac_address, admin_state_up, status, device_id, device_owner,"
               " standard_attr_id, ip_allocation)"
               " (SELECT project_id, '%s',"
               " CONCAT_WS('-VLAN%d', NULLIF(name,''), ''), '%s',"
               " mac_address, admin_state_up, status, device_id, device_owner,"
               "'%s', ip_allocation FROM ports WHERE id = '%s')"
               " RETURNING id, device_owner") %\
              (new_port_id, vlan_id, new_network_id,
               create_standard_attribute(cur, 'ports'), old_port_id)
        run_cmd(cur, cmd)
        new_port = cur.fetchone()
        new_port_owner = new_port['device_owner']
        cmd = ("INSERT INTO ml2_port_bindings"
               " (port_id, host, vif_type, vnic_type, profile,"
               " vif_details, vif_model, mac_filtering, mtu)"
               " (SELECT '%s', host, vif_type, vnic_type, profile,"
               " vif_details, vif_model, mac_filtering, mtu"
               " FROM ml2_port_bindings where port_id='%s')") %\
              (new_port_id, old_port_id)
        run_cmd(cur, cmd)
        cmd = ("INSERT INTO ml2_port_binding_levels"
               " (port_id, host, level, driver, segment_id)"
               " (SELECT '%s', host, level, driver, '%s'"
               " FROM ml2_port_binding_levels WHERE port_id='%s')") %\
              (new_port_id, new_networksegment_id, old_port_id)
        run_cmd(cur, cmd)
        if new_port_owner.startswith('compute:'):
            trunk_id = create_port_trunk(cur, old_port_id)
            create_subport(cur, trunk_id, new_port_id, 'vlan', vlan_id)
        elif new_port_owner.startswith('network:router'):
            cmd = ("INSERT INTO routerports (router_id, port_id, port_type)"
                   " (SELECT router_id, '%s', port_type FROM routerports"
                   "  WHERE port_id = '%s')") %\
                  (new_port_id, old_port_id)
            run_cmd(cur, cmd)
        elif new_port_owner == 'network:dhcp':
            # Set new port's device_id to DEVICE_ID_RESERVED_DHCP_PORT,
            # so that it is used by dhcp agent for new subnet.
            cmd = ("UPDATE ports SET device_id='reserved_dhcp_port'"
                   " WHERE id='%s'") %\
                  (new_port_id,)
            run_cmd(cur, cmd)

    # Copy the ipallocations
    cmd = ("SELECT * FROM ipallocations WHERE network_id='%s'") %\
          (old_network_id)
    run_cmd(cur, cmd)
    ipallocations = cur.fetchall()
    for ipallocation in ipallocations:
        old_ip_address = ipallocation['ip_address']
        old_port_id = ipallocation['port_id']
        old_subnet_id = ipallocation['subnet_id']
        new_port_id = port_copies.get(old_port_id)
        new_subnet_id = subnet_copies.get(old_subnet_id)
        if not new_port_id or not new_subnet_id:
            continue
        cmd = ("INSERT INTO ipallocations"
               " (port_id, ip_address, subnet_id, network_id)"
               " VALUES ('%s', '%s', '%s', '%s')") %\
              (new_port_id, old_ip_address, new_subnet_id, new_network_id)
        run_cmd(cur, cmd)

    # Copy the DHCP network agent bindings so that the new networks are
    # initial scheduled to the same agents as the vlan subnets they are
    # replacing.   The alternative is that all new networks are initially
    # unscheduled and they may all get scheduled to the same agent when any
    # of the agents query for new networks to service.
    cmd = ("SELECT * FROM networkdhcpagentbindings WHERE network_id='%s'" %
           old_network_id)
    run_cmd(cur, cmd)
    bindings = cur.fetchall()
    for binding in bindings:
        agent_id = binding['dhcp_agent_id']
        cmd = ("INSERT INTO networkdhcpagentbindings"
               " (network_id, dhcp_agent_id)"
               " VALUES ('%s', '%s')" %
               (new_network_id, agent_id))
        run_cmd(cur, cmd)


def duplicate_ipam_subnets(cur, old_neutron_subnet_id, new_neutron_subnet_id):
    cmd = ("SELECT id from ipamsubnets WHERE neutron_subnet_id='%s'") %\
          (old_neutron_subnet_id)
    run_cmd(cur, cmd)
    ipamsubnets = cur.fetchall()
    for ipamsubnet in ipamsubnets:
        old_ipamsubnet_id = ipamsubnet['id']
        new_ipamsubnet_id = uuid.uuid4()
        cmd = ("INSERT INTO ipamsubnets (id, neutron_subnet_id)"
               " VALUES ('%s', '%s')") %\
              (new_ipamsubnet_id, new_neutron_subnet_id)
        run_cmd(cur, cmd)
        cmd = ("SELECT * from ipamallocationpools"
               " WHERE ipam_subnet_id='%s'") %\
              (old_ipamsubnet_id)
        run_cmd(cur, cmd)
        ipamallocationpools = cur.fetchall()
        for ipamallocationpool in ipamallocationpools:
            new_ipamallocationpool_id = uuid.uuid4()
            first_ip = ipamallocationpool['first_ip']
            last_ip = ipamallocationpool['last_ip']
            cmd = ("INSERT INTO ipamallocationpools"
                   " (id, ipam_subnet_id, first_ip, last_ip)"
                   " VALUES ('%s', '%s', '%s', '%s')") %\
                  (new_ipamallocationpool_id, new_ipamsubnet_id,
                   first_ip, last_ip)
            run_cmd(cur, cmd)
        cmd = ("INSERT INTO ipamallocations"
               " (ip_address, status, ipam_subnet_id)"
               " (SELECT ip_address, status, '%s' FROM ipamallocations"
               " WHERE ipam_subnet_id='%s')") %\
              (new_ipamsubnet_id, old_ipamsubnet_id)
        run_cmd(cur, cmd)


def duplicate_ipallocationpools(cur, old_subnet_id, new_subnet_id):
    cmd = ("SELECT * from ipallocationpools WHERE subnet_id='%s'") %\
          (old_subnet_id)
    run_cmd(cur, cmd)
    ipallocationpools = cur.fetchall()
    for ipallocationpool in ipallocationpools:
        new_ipallocationpool_id = uuid.uuid4()
        first_ip = ipallocationpool['first_ip']
        last_ip = ipallocationpool['last_ip']
        cmd = ("INSERT INTO ipallocationpools"
               " (id, subnet_id, first_ip, last_ip)"
               " VALUES ('%s', '%s', '%s', '%s')") %\
              (new_ipallocationpool_id, new_subnet_id,
               first_ip, last_ip)
        run_cmd(cur, cmd)


def create_port_trunk(cur, port_id):
    """
    This function will create a trunk off of a given port if there doesn't
    already exist a trunk off of that port.  This port should be a compute
    port, where this is to replace a vlan-tagged subnet on that port.
    """
    # create trunk if not exists
    cmd = ("SELECT id FROM trunks WHERE port_id = '%s'") %\
          (port_id)
    run_cmd(cur, cmd)
    trunk = cur.fetchone()
    if trunk:
        return trunk['id']

    cmd = ("INSERT INTO trunks (admin_state_up, project_id, id, name, port_id,"
           " status, standard_attr_id)"
           " (SELECT admin_state_up, project_id, '%s', name, id, status, '%s'"
           " FROM ports WHERE id = '%s') RETURNING id") %\
          (uuid.uuid4(), create_standard_attribute(cur, 'trunks'), port_id)
    run_cmd(cur, cmd)
    trunk = cur.fetchone()
    return trunk['id']


def create_subport(cur, trunk_id, subport_id, segmentation_type,
                   segmentation_id):
    """
    Create a subport off of a given network trunk.
    The segmentation_id should be the vlan id as visible to the guest,
    not the segmentation id of the network segment.
    """
    cmd = ("INSERT INTO subports"
           " (port_id, trunk_id, segmentation_type, segmentation_id)"
           " VALUES ('%s', '%s','%s','%s')") %\
          (subport_id, trunk_id, segmentation_type, segmentation_id)
    run_cmd(cur, cmd)
    cmd = ("UPDATE ports SET device_id='', device_owner='trunk:subport'"
           " WHERE id='%s'") % subport_id
    run_cmd(cur, cmd)
    vif_details = '{\"port_filter\": true, \"vhostuser_enabled\": false}'
    cmd = ("UPDATE ml2_port_bindings SET vif_model='',vif_details='%s'"
           " WHERE port_id='%s'" % (vif_details, subport_id))
    run_cmd(cur, cmd)


if __name__ == "__main__":
    sys.exit(main())
