# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8

# Copyright 2013 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2013-2021 Wind River Systems, Inc.
#

"""
Client side of the conductor RPC API.
"""

from oslo_log import log
from sysinv.objects import base as objects_base
import sysinv.openstack.common.rpc.proxy

LOG = log.getLogger(__name__)

MANAGER_TOPIC = 'sysinv.conductor_manager'


class ConductorAPI(sysinv.openstack.common.rpc.proxy.RpcProxy):
    """Client side of the conductor RPC API.

    API version history:

        1.0 - Initial version.
        1.1 - Used for R5
    """

    RPC_API_VERSION = '1.1'

    def __init__(self, topic=None):
        if topic is None:
            topic = MANAGER_TOPIC

        super(ConductorAPI, self).__init__(
            topic=topic,
            serializer=objects_base.SysinvObjectSerializer(),
            default_version='1.0',
            version_cap=self.RPC_API_VERSION)

    def handle_dhcp_lease(self, context, tags, mac, ip_address, cid=None):
        """Synchronously, have a conductor handle a DHCP lease update.

        Handling depends on the interface:
        - management interface: creates an ihost

        :param context: request context.
        :param tags: specifies the interface type (mgmt)
        :param mac: MAC for the lease
        :param ip_address: IP address for the lease
        :param cid: Client ID for the lease
        """
        return self.call(context,
                         self.make_msg('handle_dhcp_lease',
                                       tags=tags,
                                       mac=mac,
                                       ip_address=ip_address,
                                       cid=cid))

    def create_ihost(self, context, values):
        """Synchronously, have a conductor create an ihost.

        Create an ihost in the database and return an object.

        :param context: request context.
        :param values: dictionary with initial values for new ihost object
        :returns: created ihost object, including all fields.
        """
        return self.call(context,
                         self.make_msg('create_ihost',
                                       values=values))

    def update_ihost(self, context, ihost_obj):
        """Synchronously, have a conductor update the ihosts's information.

        Update the ihost's information in the database and return an object.

        :param context: request context.
        :param ihost_obj: a changed (but not saved) ihost object.
        :returns: updated ihost object, including all fields.
        """
        return self.call(context,
                         self.make_msg('update_ihost',
                                       ihost_obj=ihost_obj))

    def configure_ihost(self, context, host,
                        do_worker_apply=False):
        """Synchronously, have a conductor configure an ihost.

        Does the following tasks:
        - Update puppet hiera configuration files for the ihost.
        - Add (or update) a host entry in the dnsmasq.conf file.
        - Set up PXE configuration to run installer

        :param context: request context.
        :param host: an ihost object.
        :param do_worker_apply: apply the newly created worker manifests.
        """
        return self.call(context,
                         self.make_msg('configure_ihost',
                                       host=host,
                                       do_worker_apply=do_worker_apply))

    def remove_host_config(self, context, host_uuid):
        """Synchronously, have a conductor remove configuration for a host.

        Does the following tasks:
        - Remove the hiera config files for the host.

        :param context: request context.
        :param host_uuid: uuid of the host.
        """
        return self.call(context,
                         self.make_msg('remove_host_config',
                                       host_uuid=host_uuid))

    def unconfigure_ihost(self, context, ihost_obj):
        """Synchronously, have a conductor unconfigure an ihost.

        Does the following tasks:
        - Remove hiera config files for the ihost.
        - Remove the host entry from the dnsmasq.conf file.
        - Remove the PXE configuration

        :param context: request context.
        :param ihost_obj: an ihost object.
        """
        return self.call(context,
                         self.make_msg('unconfigure_ihost',
                                       ihost_obj=ihost_obj))

    def create_controller_filesystems(self, context, rootfs_device):
        """Synchronously, create the controller file systems.

        Does the following tasks:
        - queries OS for root disk size
        - creates the controller file systems.
        - queries system to get region info for img_conversion_size setup.


        :param context: request context..
        :param rootfs_device: the root disk device
        """
        return self.call(context,
                         self.make_msg('create_controller_filesystems',
                                       rootfs_device=rootfs_device))

    def create_host_filesystems(self, context, ihost_uuid, fs_dict_array):
        """Create or update the filesystem for an ihost with the supplied
        data.

        This method allows records for a filesystem for ihost to be
        created, or updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param fs_dict_array: initial values for the filesystems
        :returns: pass or fail
        """

        return self.call(context,
                         self.make_msg('create_host_filesystems',
                                       ihost_uuid=ihost_uuid,
                                       fs_dict_array=fs_dict_array))

    def get_ihost_by_macs(self, context, ihost_macs):
        """Finds ihost db entry based upon the mac list

        This method returns an ihost if it matches a mac

        :param context: an admin context
        :param ihost_macs: list of mac addresses
        :returns: ihost object, including all fields.
        """

        return self.call(context,
                         self.make_msg('get_ihost_by_macs',
                                       ihost_macs=ihost_macs))

    def get_ihost_by_hostname(self, context, ihost_hostname):
        """Finds ihost db entry based upon the ihost hostname

        This method returns an ihost if it matches the
        hostname.

        :param context: an admin context
        :param ihost_hostname: ihost hostname
        :returns: ihost object, including all fields.
        """

        return self.call(context,
                         self.make_msg('get_ihost_by_hostname',
                                       ihost_hostname=ihost_hostname))

    def iport_update_by_ihost(self, context,
                              ihost_uuid, inic_dict_array):
        """Create iports for an ihost with the supplied data.

        This method allows records for iports for ihost to be created.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param inic_dict_array: initial values for iport objects
        :returns: pass or fail
        """

        return self.call(context,
                         self.make_msg('iport_update_by_ihost',
                                       ihost_uuid=ihost_uuid,
                                       inic_dict_array=inic_dict_array))

    def lldp_agent_update_by_host(self, context,
                                  host_uuid, agent_dict_array):
        """Create lldp_agents for an ihost with the supplied data.

        This method allows records for lldp_agents for a host to be created.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param agent_dict_array: initial values for lldp_agent objects
        :returns: pass or fail
        """

        return self.call(context,
                         self.make_msg('lldp_agent_update_by_host',
                                       host_uuid=host_uuid,
                                       agent_dict_array=agent_dict_array))

    def lldp_neighbour_update_by_host(self, context,
                                      host_uuid, neighbour_dict_array):
        """Create lldp_neighbours for an ihost with the supplied data.

        This method allows records for lldp_neighbours for a host to be
        created.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param neighbour_dict_array: initial values for lldp_neighbour objects
        :returns: pass or fail
        """

        return self.call(
            context,
            self.make_msg('lldp_neighbour_update_by_host',
                          host_uuid=host_uuid,
                          neighbour_dict_array=neighbour_dict_array))

    def pci_device_update_by_host(self, context,
                                  host_uuid, pci_device_dict_array,
                                  cleanup_stale=False):
        """Create pci_devices for an ihost with the supplied data.

        This method allows records for pci_devices for ihost to be created.

        :param context: an admin context
        :param host_uuid: ihost uuid unique id
        :param pci_device_dict_array: initial values for device objects
        :param cleanup_stale: Do we want to clean up stale device entries
        :returns: pass or fail
        """
        try:
            return self.call(
                context,
                self.make_msg('pci_device_update_by_host',
                              host_uuid=host_uuid,
                              pci_device_dict_array=pci_device_dict_array,
                              cleanup_stale=cleanup_stale))
        except TypeError as exc:
            # Handle talking to sysinv-conductor that doesn't understand
            # the cleanup_stale parameter.
            exc = repr(exc)
            if "unexpected keyword argument" in exc and "cleanup_stale" in exc:
                LOG.info("retrying without cleanup_stale")
                return self.call(
                    context,
                    self.make_msg('pci_device_update_by_host',
                                  host_uuid=host_uuid,
                                  pci_device_dict_array=pci_device_dict_array))
            else:
                raise

    def inumas_update_by_ihost(self, context,
                               ihost_uuid, inuma_dict_array):
        """Create inumas for an ihost with the supplied data.

        This method allows records for inumas for ihost to be created.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param inuma_dict_array: initial values for inuma objects
        :returns: pass or fail
        """

        return self.call(context,
                         self.make_msg('inumas_update_by_ihost',
                                       ihost_uuid=ihost_uuid,
                                       inuma_dict_array=inuma_dict_array))

    def icpus_update_by_ihost(self, context,
                              ihost_uuid, icpu_dict_array,
                              force_grub_update,
                              ):
        """Create cpus for an ihost with the supplied data.

        This method allows records for cpus for ihost to be created.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param icpu_dict_array: initial values for cpu objects
        :param force_grub_update: bool value to force grub update
        :returns: pass or fail
        """

        return self.call(context,
                         self.make_msg('icpus_update_by_ihost',
                                       ihost_uuid=ihost_uuid,
                                       icpu_dict_array=icpu_dict_array,
                                       force_grub_update=force_grub_update))

    def imemory_update_by_ihost(self, context,
                                ihost_uuid, imemory_dict_array,
                                force_update=False):
        """Create or update memory for an ihost with the supplied data.

        This method allows records for memory for ihost to be created,
        or updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param imemory_dict_array: initial values for memory objects
        :param force_update: force a memory update
        :returns: pass or fail
        """

        return self.call(context,
                         self.make_msg('imemory_update_by_ihost',
                                       ihost_uuid=ihost_uuid,
                                       imemory_dict_array=imemory_dict_array,
                                       force_update=force_update))

    def idisk_update_by_ihost(self, context,
                              ihost_uuid, idisk_dict_array):
        """Create or update disk for an ihost with the supplied data.

        This method allows records for disk for ihost to be created,
        or updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param idisk_dict_array: initial values for disk objects
        :returns: pass or fail
        """

        return self.call(context,
                         self.make_msg('idisk_update_by_ihost',
                                       ihost_uuid=ihost_uuid,
                                       idisk_dict_array=idisk_dict_array))

    def ilvg_update_by_ihost(self, context,
                             ihost_uuid, ilvg_dict_array):
        """Create or update local volume group for an ihost with the supplied
        data.

        This method allows records for a local volume group for ihost to be
        created, or updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param ilvg_dict_array: initial values for local volume group objects
        :returns: pass or fail
        """

        return self.call(context,
                         self.make_msg('ilvg_update_by_ihost',
                                       ihost_uuid=ihost_uuid,
                                       ilvg_dict_array=ilvg_dict_array))

    def ipv_update_by_ihost(self, context,
                            ihost_uuid, ipv_dict_array):
        """Create or update physical volume for an ihost with the supplied
        data.

        This method allows records for a physical volume for ihost to be
        created, or updated.

        R5 - Moved to version 1.1 as partition schema is no longer applicable
        to R4

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param ipv_dict_array: initial values for physical volume objects
        :returns: pass or fail
        """

        return self.call(context,
                         self.make_msg('ipv_update_by_ihost',
                                       ihost_uuid=ihost_uuid,
                                       ipv_dict_array=ipv_dict_array),
                         version='1.1')

    def ipartition_update_by_ihost(self, context,
                                   ihost_uuid, ipart_dict_array):

        """Create or update partitions for an ihost with the supplied data.

        This method allows records for a host's partition to be created or
        updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param ipart_dict_array: initial values for partition objects
        :returns: pass or fail
        """

        return self.call(context,
                         self.make_msg('ipartition_update_by_ihost',
                                       ihost_uuid=ihost_uuid,
                                       ipart_dict_array=ipart_dict_array))

    def update_partition_config(self, context, partition):
        """Asynchronously, have a conductor configure the physical volume
        partitions.

        :param context: request context.
        :param partition: dict with partition details.
        """
        LOG.debug("ConductorApi.update_partition_config: sending"
                  " partition to conductor")
        return self.cast(context, self.make_msg('update_partition_config',
                                                partition=partition))

    def iplatform_update_by_ihost(self, context,
                                  ihost_uuid, imsg_dict):
        """Create or update memory for an ihost with the supplied data.

        This method allows records for memory for ihost to be created,
        or updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param imsg_dict: inventory message dict
        :returns: pass or fail
        """

        return self.call(context,
                         self.make_msg('iplatform_update_by_ihost',
                                       ihost_uuid=ihost_uuid,
                                       imsg_dict=imsg_dict))

    def upgrade_ihost(self, context, host, load):
        """Synchronously, have a conductor upgrade a host.

        Does the following tasks:
        - Update the pxelinux.cfg file.

        :param context: request context.
        :param host: an ihost object.
        :param load: a load object.
        """
        return self.call(context,
                         self.make_msg('upgrade_ihost_pxe_config', host=host, load=load))

    def configure_isystemname(self, context, systemname):
        """Synchronously, have a conductor configure the system name.

        Does the following tasks:
        - sends a message to conductor
        - who sends a message to all inventory agents
        - who each update their /etc/platform/motd.system

        :param context: request context.
        :param systemname: the systemname
        """
        LOG.debug("ConductorApi.configure_isystemname: sending"
                  " systemname to conductor")
        return self.call(context,
                         self.make_msg('configure_isystemname',
                                       systemname=systemname))

    def configure_system_https(self, context):
        """Synchronously, have a conductor configure the system https/http
        configuration.

        Does the following tasks:
        - sends a message to conductor
        - who sends a message to all inventory agents
        - who each apply the https/http selected  manifests

        :param context: request context.
        """
        LOG.debug("ConductorApi.configure_system_https/http: sending"
                  " configure_system_https to conductor")
        return self.call(context, self.make_msg('configure_system_https'))

    def configure_system_timezone(self, context):
        """Synchronously, have a conductor configure the system timezone.

        Does the following tasks:
        - sends a message to conductor
        - who sends a message to all inventory agents
        - who each apply the timezone manifest

        :param context: request context.
        """
        LOG.debug("ConductorApi.configure_system_timezone: sending"
                  " system_timezone to conductor")
        return self.call(context, self.make_msg('configure_system_timezone'))

    def delete_flag_file(self, context, flag_file):
        """Synchronously, have a conductor delete a flag file.

        :param context: request context
        :param flag_file: path to the flag file
        """
        LOG.debug("ConductorApi.delete_flag_file: sending"
                  " delete_flag_file(%s) to conductor" % flag_file)
        return self.call(context,
                         self.make_msg('delete_flag_file',
                                       flag_file=flag_file))

    def update_route_config(self, context, host_id):
        """Synchronously, have a conductor configure static route.

        Does the following tasks:
        - sends a message to conductor
        - who sends a message to all inventory agents
        - who each apply the route manifest

        :param context: request context.
        :param host_id: the host id
        """
        LOG.debug("ConductorApi.update_route_config: sending "
                  " update_route_config to conductor for "
                  "host_id(%s)" % host_id)
        return self.call(context, self.make_msg('update_route_config',
                                                host_id=host_id))

    def update_sriov_config(self, context, host_uuid):
        """Synchronously, have a conductor configure sriov config.

        Does the following tasks:
        - sends a message to conductor
        - who sends a message to all inventory agents
        - who each apply the network manifest

        :param context: request context.
        :param host_uuid: the host unique uuid
        """
        LOG.debug("ConductorApi.update_sriov_config: sending "
                  "update_sriov_config to conductor")
        return self.call(context, self.make_msg('update_sriov_config',
                                                host_uuid=host_uuid))

    def update_sriov_vf_config(self, context, host_uuid):
        """Synchronously, have a conductor configure sriov vf config.

        Does the following tasks:
        - sends a message to conductor
        - who sends a message to all inventory agents
        - who each apply the network manifest

        :param context: request context.
        :param host_uuid: the host unique uuid
        """
        LOG.debug("ConductorApi.update_sriov_vf_config: sending "
                  "update_sriov_vf_config to conductor")
        return self.call(context, self.make_msg('update_sriov_vf_config',
                                                host_uuid=host_uuid))

    def update_pcidp_config(self, context, host_uuid):
        """Synchronously, have a conductor configure pcidp config.

        Does the following tasks:
        - sends a message to conductor
        - who sends a message to all inventory agents
        - who, upon receipt with matching host_uuid, applies the pcidp manifest

        :param context: request context.
        :param host_uuid: the host unique uuid
        """
        LOG.debug("ConductorApi.update_pcidp_config: sending "
                  "update_pcidp_config to conductor")
        return self.call(context, self.make_msg('update_pcidp_config',
                                                host_uuid=host_uuid))

    def update_distributed_cloud_role(self, context):
        """Synchronously, have a conductor configure the distributed cloud
           role of the system.

        Does the following tasks:
        - sends a message to conductor
        - who sends a message to all inventory agents
        - who each apply the config manifest

        :param context: request context.
        """
        LOG.debug("ConductorApi.update_distributed_cloud_role: sending"
                  " distributed_cloud_role to conductor")
        return self.call(context, self.make_msg('update_distributed_cloud_role'))

    def subfunctions_update_by_ihost(self, context, ihost_uuid, subfunctions):
        """Create or update local volume group for an ihost with the supplied
        data.

        This method allows records for a local volume group for ihost to be
        created, or updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param subfunctions: subfunctions of the host
        :returns: pass or fail
        """

        return self.call(context,
                         self.make_msg('subfunctions_update_by_ihost',
                                       ihost_uuid=ihost_uuid,
                                       subfunctions=subfunctions))

    def configure_osd_istor(self, context, istor_obj):
        """Synchronously, have a conductor configure an OSD istor.

        Does the following tasks:
        - Allocates an OSD.
        - Creates or resizes the OSD pools as necessary.

        :param context: request context.
        :param istor_obj: an istor object.
        :returns: istor object, with updated osdid
        """
        return self.call(context,
                         self.make_msg('configure_osd_istor',
                                       istor_obj=istor_obj))

    def unconfigure_osd_istor(self, context, istor_obj):
        """Synchronously, have a conductor unconfigure an istor.

        Does the following tasks:
        - Removes the OSD from the crush map.
        - Deletes the OSD's auth key.
        - Deletes the OSD.

        :param context: request context.
        :param istor_obj: an istor object.
        """
        return self.call(context,
                         self.make_msg('unconfigure_osd_istor',
                                       istor_obj=istor_obj))

    def get_ceph_pool_replication(self, context, ceph_backend=None):
        """Get ceph storage backend pool replication parameters

        :param context: request context.
        :param ceph_backend: ceph backend object type for a tier
        :returns: tuple with (replication, min_replication)
        """
        return self.call(context,
                         self.make_msg('get_ceph_pool_replication',
                                       ceph_backend=ceph_backend))

    def delete_osd_pool(self, context, pool_name):
        """delete an OSD pool

        :param context: request context.
        :param pool_name: the name of the OSD pool
        """
        return self.call(context,
                         self.make_msg('delete_osd_pool',
                                       pool_name=pool_name))

    def list_osd_pools(self, context):
        """list OSD pools

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('list_osd_pools'))

    def get_osd_pool_quota(self, context, pool_name):
        """Get the quota for an OSD pool

        :param context: request context.
        :param pool_name: the name of the OSD pool
        :returns: dictionary with {"max_objects": num, "max_bytes": num}
        """
        return self.call(context,
                         self.make_msg('get_osd_pool_quota',
                                       pool_name=pool_name))

    def set_osd_pool_quota(self, context, pool, max_bytes=0, max_objects=0):
        """Set the quota for an OSD pool

        :param context: request context.
        :param pool: the name of the OSD pool
        """
        return self.call(context,
                         self.make_msg('set_osd_pool_quota',
                                       pool=pool, max_bytes=max_bytes,
                                       max_objects=max_objects))

    def get_ceph_primary_tier_size(self, context):
        """Get the size of the primary storage tier in the ceph cluster.

        :param context: request context.
        :returns: integer size in GB.
        """
        return self.call(context,
                         self.make_msg('get_ceph_primary_tier_size'))

    def get_ceph_tier_size(self, context, tier_name):
        """Get the size of a storage tier in the ceph cluster.

        :param context: request context.
        :param tier_name: name of the storage tier of interest.
        :returns: integer size in GB.
        """
        return self.call(context,
                         self.make_msg('get_ceph_tier_size',
                                       tier_name=tier_name))

    def get_ceph_cluster_df_stats(self, context):
        """Get the usage information for the ceph cluster.

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('get_ceph_cluster_df_stats'))

    def get_ceph_pools_df_stats(self, context):
        """Get the usage information for the ceph pools.

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('get_ceph_pools_df_stats'))

    def get_cinder_lvm_usage(self, context):
        """Get the usage information for the LVM pools.

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('get_cinder_lvm_usage'))

    def get_cinder_volume_type_names(self, context):
        """Get the names of all currently defined cinder volume types.

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('get_cinder_volume_type_names'))

    def kill_ceph_storage_monitor(self, context):
        """Stop the ceph storage monitor.
        pmon will not restart it. This should only be used in an
        upgrade/rollback

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('kill_ceph_storage_monitor'))

    def update_dns_config(self, context):
        """Synchronously, have the conductor update the DNS configuration.

        :param context: request context.
        """
        return self.call(context, self.make_msg('update_dns_config'))

    def update_clock_synchronization_config(self, context, host):
        """Synchronously, have the conductor update the
        clock_synchronization configuration of a host.

        :param context: request context.
        :param host: the host to be modified.
        """
        return self.call(context,
                         self.make_msg('update_clock_synchronization_config',
                                       host=host))

    def update_ntp_config(self, context):
        """Synchronously, have the conductor update the NTP configuration.

        :param context: request context.
        """
        return self.call(context, self.make_msg('update_ntp_config'))

    def update_ptp_config(self, context, do_apply=False):
        """Synchronously, have the conductor update the PTP configuration.

        :param context: request context.
        :param do_apply: If the config should be applied via runtime manifests
        """
        return self.call(context, self.make_msg('update_ptp_config', do_apply=do_apply))

    def update_system_mode_config(self, context):
        """Synchronously, have the conductor update the system mode
        configuration.

        :param context: request context.
        """
        return self.call(context, self.make_msg('update_system_mode_config'))

    def update_security_feature_config(self, context):
        """Synchronously, have the conductor update the security_feature
        configuration.

        :param context: request context.
        """
        return self.call(context, self.make_msg('update_security_feature_config'))

    def initialize_oam_config(self, context, host):
        """Synchronously, have the conductor create an OAM configuration.

        :param context: request context.
        :param host: an ihost object.
        """
        return self.call(context, self.make_msg('initialize_oam_config', host=host))

    def update_oam_config(self, context):
        """Synchronously, have the conductor update the OAM configuration.

        :param context: request context.
        """
        return self.call(context, self.make_msg('update_oam_config'))

    def update_user_config(self, context):
        """Synchronously, have the conductor update the user configuration.

        :param context: request context.
        """
        return self.call(context, self.make_msg('update_user_config'))

    def update_controller_rollback_flag(self, context):
        """Synchronously, have a conductor update controller rollback flag

        :param context: request context
         """
        return self.call(context,
                         self.make_msg('update_controller_rollback_flag'))

    def update_controller_upgrade_flag(self, context):
        """Synchronously, have a conductor update controller upgrade flag

        :param context: request context
         """
        return self.call(context,
                         self.make_msg('update_controller_upgrade_flag'))

    def update_storage_config(self, context, update_storage=False,
                              reinstall_required=False, reboot_required=True,
                              filesystem_list=None):
        """Synchronously, have the conductor update the storage configuration.

        :param context: request context.
        """
        return self.call(
            context, self.make_msg(
                'update_storage_config',
                update_storage=update_storage,
                reinstall_required=reinstall_required,
                reboot_required=reboot_required,
                filesystem_list=filesystem_list
            )
        )

    def update_host_filesystem_config(self, context,
                                      host=None,
                                      filesystem_list=None):
        """Synchronously, have the conductor update the host's filesystem.

        :param context: request context.
        :param host: the host to update the filesystems on.
        :param filesystem_list: list of host filesystems.
        """
        return self.call(
            context, self.make_msg(
                'update_host_filesystem_config',
                host=host,
                filesystem_list=filesystem_list
            )
        )

    def update_lvm_config(self, context):
        """Synchronously, have the conductor update the LVM configuration.

        :param context: request context.
        """
        return self.call(context, self.make_msg('update_lvm_config'))

    def update_ceph_base_config(self, context, personalities):
        """Synchronously, have the conductor update the configuration
        for monitors and ceph.conf.

        :param context: request context.
        :param personalities: list of host personalities.
        """
        return self.call(
            context, self.make_msg(
                'update_ceph_base_config',
                personalities=personalities
            )
        )

    def update_ceph_osd_config(self, context, host, stor_uuid, runtime_manifests):
        """Synchronously, have the conductor update the configuration
        for an OSD.

        :param context: request context.
        :param host: a host to update OSDs on.
        :param stor_uuid: uuid of a storage device
        :param runtime_manifests: True if puppet manifests are to be applied at
               runtime.
        """
        return self.call(
            context, self.make_msg(
                'update_ceph_osd_config',
                host=host,
                stor_uuid=stor_uuid,
                runtime_manifests=runtime_manifests
            )
        )

    def update_drbd_config(self, context):
        """Synchronously, have the conductor update the drbd configuration.

        :param context: request context.
        """
        return self.call(context, self.make_msg('update_drbd_config'))

    def update_remotelogging_config(self, context, timeout=None):
        """Synchronously, have the conductor update the remotelogging
        configuration.

        :param context: request context.
        :param ihost_uuid: ihost uuid unique id
        """
        return self.call(context,
                         self.make_msg('update_remotelogging_config'), timeout=timeout)

    def docker_registry_image_list(self, context):
        """Synchronously, request a list of images from Docker Registry API

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('docker_registry_image_list'))

    def docker_registry_image_tags(self, context, image_name):
        """Synchronously, request a list of tags from Docker Registry API for a given image

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('docker_registry_image_tags', image_name=image_name))

    def docker_registry_image_delete(self, context, image_name_and_tag):
        """Synchronously, delete the given image tag from the local docker registry

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('docker_registry_image_delete',
                                       image_name_and_tag=image_name_and_tag))

    def docker_registry_garbage_collect(self, context):
        """Asynchronously, run the docker registry garbage collector

        :param context: request context.
        """
        return self.cast(context,
                         self.make_msg('docker_registry_garbage_collect'))

    def docker_get_apps_images(self, context):
        """Synchronously, request a dictionary of all apps and associated images for all apps.

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('docker_get_apps_images'))

    def update_lvm_cinder_config(self, context):
        """Synchronously, have the conductor update Cinder LVM on a controller.

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('update_lvm_cinder_config'))

    def update_install_uuid(self, context, host_uuid, install_uuid):
        """Synchronously, have an agent update install_uuid on
           a host.

        :param context: request context.
        :parm host_uuid: host uuid to update the install_uuid
        :parm install_uuid: install_uuid
        """
        return self.call(context,
                         self.make_msg('update_install_uuid',
                                       host_uuid=host_uuid,
                                       install_uuid=install_uuid))

    def update_ceph_config(self, context, sb_uuid, services):
        """Synchronously, have the conductor update Ceph on a controller

        :param context: request context
        :param sb_uuid: uuid of the storage backed to apply the ceph config
        :param services: list of services using Ceph.
        """
        return self.call(context,
                         self.make_msg('update_ceph_config',
                                       sb_uuid=sb_uuid,
                                       services=services))

    def update_ceph_external_config(self, context, sb_uuid, services):
        """Synchronously, have the conductor update External Ceph on a controller

        :param context: request context
        :param sb_uuid: uuid of the storage backed to apply the external ceph config
        :param services: list of services using Ceph.
        """
        return self.call(context,
                         self.make_msg('update_ceph_external_config',
                                       sb_uuid=sb_uuid,
                                       services=services))

    def update_ceph_rook_config(self, context, sb_uuid, services):
        """Synchronously, have the conductor update Rook Ceph on a controller

        :param context: request context
        :param sb_uuid: uuid of the storage backend to apply the rook ceph config
        :param services: list of services using Ceph.
        """
        return self.call(context,
                         self.make_msg('update_ceph_rook_config',
                                       sb_uuid=sb_uuid,
                                       services=services))

    def update_external_cinder_config(self, context):
        """Synchronously, have the conductor update Cinder Exernal(shared)
           on a controller.

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('update_external_cinder_config'))

    def get_k8s_namespaces(self, context):
        """Synchronously, get Kubernetes namespaces

        :returns: list of namespacea
        """
        return self.call(context,
                         self.make_msg('get_k8s_namespaces'))

    def report_config_status(self, context, iconfig,
                             status, error=None):
        """ Callback from Sysinv Agent on manifest apply success or failure

        Finalize configuration after manifest apply successfully or perform
        cleanup, log errors and raise alarms in case of failures.

        :param context: request context
        :param iconfig: configuration context
        :param status: operation status
        :param error: serialized exception as a dict of type:
                error = {
                        'class': str(ex.__class__.__name__),
                        'module': str(ex.__class__.__module__),
                        'message': six.text_type(ex),
                        'tb': traceback.format_exception(*ex),
                        'args': ex.args,
                        'kwargs': ex.kwargs
                        }

        The iconfig context is expected to contain a valid REPORT_TOPIC key,
        so that we can correctly identify the set of manifests executed.
        """
        return self.call(context,
                         self.make_msg('report_config_status',
                                       iconfig=iconfig,
                                       status=status,
                                       error=error))

    def update_grub_config(self, context, host_uuid, force=False):
        """Synchronously, have the conductor update the grub
        configuration.

        :param context: request context.
        :param host_uuid: host unique uuid
        :param force: whether force an update
        """
        return self.call(context, self.make_msg('update_grub_config',
                                                host_uuid=host_uuid,
                                                force_grub_update=force))

    def iconfig_update_by_ihost(self, context,
                                ihost_uuid, imsg_dict):
        """Create or update iconfig for an ihost with the supplied data.

        This method allows records for iconfig for ihost to be updated.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param imsg_dict: inventory message dict
        :returns: pass or fail
        """

        return self.call(context,
                         self.make_msg('iconfig_update_by_ihost',
                                       ihost_uuid=ihost_uuid,
                                       imsg_dict=imsg_dict))

    def initial_inventory_completed(self, context, host_uuid):
        """Notify of initial inventory completion for a host.

        :param context: an admin context
        :param host_uuid: host unique id
        """

        return self.call(context,
                         self.make_msg('initial_inventory_completed',
                                       host_uuid=host_uuid,
                                       ))

    def mgmt_ip_set_by_ihost(self,
                             context,
                             ihost_uuid,
                             interface_id,
                             mgmt_ip):
        """Call sysinv to update host mgmt_ip (removes previous entry if
           necessary)

        :param context: an admin context
        :param ihost_uuid: ihost uuid
        :param interface_id: interface id value
        :param mgmt_ip: mgmt_ip
        :returns: Address
        """

        return self.call(context,
                         self.make_msg('mgmt_ip_set_by_ihost',
                                       ihost_uuid=ihost_uuid,
                                       interface_id=interface_id,
                                       mgmt_ip=mgmt_ip))

    def vim_host_add(self, context, api_token, ihost_uuid,
                     hostname, subfunctions, administrative,
                     operational, availability,
                     subfunction_oper, subfunction_avail, timeout):
        """
        Asynchronously, notify VIM of host add
        """

        return self.cast(context,
                         self.make_msg('vim_host_add',
                                       api_token=api_token,
                                       ihost_uuid=ihost_uuid,
                                       hostname=hostname,
                                       personality=subfunctions,
                                       administrative=administrative,
                                       operational=operational,
                                       availability=availability,
                                       subfunction_oper=subfunction_oper,
                                       subfunction_avail=subfunction_avail,
                                       timeout=timeout))

    def mtc_host_add(self, context, mtc_address, mtc_port, ihost_mtc_dict):
        """
        Asynchronously, notify mtce of host add
        """
        return self.cast(context,
                         self.make_msg('mtc_host_add',
                                       mtc_address=mtc_address,
                                       mtc_port=mtc_port,
                                       ihost_mtc_dict=ihost_mtc_dict))

    def is_virtual_system_config(self, context):
        """
        Gets the virtual system config from service parameter
        """
        return self.call(context,
                         self.make_msg('is_virtual_system_config'))

    def ilvg_get_nova_ilvg_by_ihost(self,
                                    context,
                                    ihost_uuid):
        """
        Gets the nova ilvg by ihost.

        returns the nova ilvg if added to the host else returns empty
        list

        """

        ilvgs = self.call(context,
                          self.make_msg('ilvg_get_nova_ilvg_by_ihost',
                                        ihost_uuid=ihost_uuid))

        return ilvgs

    def get_platform_interfaces(self, context, ihost_id):
        """Synchronously, have a agent collect platform interfaces for this
           ihost.

        Gets the mgmt interface names and numa node

        :param context: request context.
        :param ihost_id: id of this host
        :returns: a list of interfaces and their associated numa nodes.
        """
        return self.call(context,
                         self.make_msg('platform_interfaces',
                                       ihost_id=ihost_id))

    def ibm_deprovision_by_ihost(self, context, ihost_uuid, ibm_msg_dict):
        """Update ihost upon notification of board management controller
           deprovisioning.

        This method also allows a dictionary of values to be passed in to
        affort additional controls, if and as needed.

        :param context: an admin context
        :param ihost_uuid: ihost uuid unique id
        :param ibm_msg_dict: values for additional controls or changes
        :returns: pass or fail
        """

        return self.call(context,
                         self.make_msg('ibm_deprovision_by_ihost',
                                       ihost_uuid=ihost_uuid,
                                       ibm_msg_dict=ibm_msg_dict))

    def configure_ttys_dcd(self, context, uuid, ttys_dcd):
        """Synchronously, have a conductor configure the dcd.

        Does the following tasks:
        - sends a message to conductor
        - who sends a message to all inventory agents
        - who has the uuid updates dcd

        :param context: request context.
        :param uuid: the host uuid
        :param ttys_dcd: the flag to enable/disable dcd
        """
        LOG.debug("ConductorApi.configure_ttys_dcd: sending (%s %s) to "
                  "conductor" % (uuid, ttys_dcd))
        return self.call(context,
                         self.make_msg('configure_ttys_dcd',
                                       uuid=uuid, ttys_dcd=ttys_dcd))

    def get_host_ttys_dcd(self, context, ihost_id):
        """Synchronously, have a agent collect carrier detect state for this
           ihost.

        :param context: request context.
        :param ihost_id: id of this host
        :returns: ttys_dcd.
        """
        return self.call(context,
                         self.make_msg('get_host_ttys_dcd',
                                       ihost_id=ihost_id))

    def start_import_load(self, context, path_to_iso, path_to_sig,
                          import_active=False):
        """Synchronously, mount the ISO and validate the load for import

        :param context: request context.
        :param path_to_iso: the file path of the iso on this host
        :param path_to_sig: the file path of the iso's detached signature on
                            this host
        :param import_active: boolean allow import of active load
        :returns: the newly create load object.
        """
        return self.call(context,
                         self.make_msg('start_import_load',
                                       path_to_iso=path_to_iso,
                                       path_to_sig=path_to_sig,
                                       import_active=import_active))

    def import_load(self, context, path_to_iso, new_load):
        """Asynchronously, import a load and add it to the database

        :param context: request context.
        :param path_to_iso: the file path of the iso on this host
        :param new_load: the load object
        :returns: none.
        """
        return self.cast(context,
                         self.make_msg('import_load',
                                       path_to_iso=path_to_iso,
                                       new_load=new_load))

    def delete_load(self, context, load_id):
        """Asynchronously, cleanup a load from both controllers

        :param context: request context.
        :param load_id: id of load to be deleted
        :returns: none.
        """
        return self.cast(context,
                         self.make_msg('delete_load',
                                       load_id=load_id))

    def finalize_delete_load(self, context, sw_version):
        """Asynchronously, delete the load from the database

        :param context: request context.
        :param sw_version: software version of load to be deleted
        :returns: none.
        """
        return self.cast(context,
                         self.make_msg('finalize_delete_load',
                                       sw_version=sw_version))

    def load_update_by_host(self, context, ihost_id, version):
        """Update the host_upgrade table with the running SW_VERSION

        :param context: request context.
        :param ihost_id: the host id
        :param version: the SW_VERSION from the host
        :returns: none.
        """
        return self.call(context,
                         self.make_msg('load_update_by_host',
                                       ihost_id=ihost_id, sw_version=version))

    def update_service_config(self, context, service=None, section=None,
                              do_apply=False):
        """Synchronously, have the conductor update the service parameter.

        :param context: request context.
        :param do_apply: apply the newly created manifests.
        """
        return self.call(context, self.make_msg('update_service_config',
                                                service=service,
                                                section=section,
                                                do_apply=do_apply))

    def start_upgrade(self, context, upgrade):
        """Asynchronously, have the conductor start the upgrade

        :param context: request context.
        :param upgrade: the upgrade object.
        """
        return self.cast(context, self.make_msg('start_upgrade',
                                                upgrade=upgrade))

    def activate_upgrade(self, context, upgrade):
        """Asynchronously, have the conductor perform the upgrade activation.

        :param context: request context.
        :param upgrade: the upgrade object.
        """
        return self.cast(context, self.make_msg('activate_upgrade',
                                                upgrade=upgrade))

    def complete_upgrade(self, context, upgrade, state):
        """Asynchronously, have the conductor complete the upgrade.

        :param context: request context.
        :param upgrade: the upgrade object.
        :param state: the state of the upgrade before completing
        """
        return self.cast(context, self.make_msg('complete_upgrade',
                                                upgrade=upgrade, state=state))

    def abort_upgrade(self, context, upgrade):
        """Synchronously, have the conductor abort the upgrade.

        :param context: request context.
        :param upgrade: the upgrade object.
        """
        return self.call(context, self.make_msg('abort_upgrade',
                                                upgrade=upgrade))

    def complete_simplex_backup(self, context, success):
        """Asynchronously, complete the simplex upgrade start process

        :param context: request context.
        :param success: If the create_simplex_backup call completed
                """
        return self.cast(context, self.make_msg('complete_simplex_backup',
                                                success=success))

    def get_system_health(self, context, force=False, upgrade=False,
                          kube_upgrade=False, kube_rootca_update=False,
                          alarm_ignore_list=None):
        """
        Performs a system health check.

        :param context: request context.
        :param force: set to true to ignore minor and warning alarms
        :param upgrade: set to true to perform an upgrade health check
        :param kube_upgrade: set to true to perform a kubernetes upgrade health
                             check
        :param alarm_ignore_list: list of alarm ids to ignore when performing
                                  a health check
        """
        return self.call(context,
                         self.make_msg('get_system_health',
                                       force=force, upgrade=upgrade,
                                       kube_upgrade=kube_upgrade,
                                       kube_rootca_update=kube_rootca_update,
                                       alarm_ignore_list=alarm_ignore_list))

    def reserve_ip_for_first_storage_node(self, context):
        """
        Reserve ip address for the first storage node for Ceph monitor
        when installing Ceph as a second backend

        :param context: request context.
        """
        self.call(context,
                  self.make_msg('reserve_ip_for_first_storage_node'))

    def reserve_ip_for_cinder(self, context):
        """
        Reserve ip address for Cinder's services

        :param context: request context.
        """
        self.call(context,
                  self.make_msg('reserve_ip_for_cinder'))

    def update_sdn_controller_config(self, context):
        """Synchronously, have the conductor update the SDN controller config.

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('update_sdn_controller_config'))

    def update_sdn_enabled(self, context):
        """Synchronously, have the conductor update the SDN enabled flag

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('update_sdn_enabled'))

    def update_vswitch_type(self, context):
        """Synchronously, have the conductor update the system vswitch type

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('update_vswitch_type'))

    def create_barbican_secret(self, context, name, payload):
        """Calls Barbican API to create a secret

        :param context: request context.
        :param name: secret name
        :param payload: secret payload
        """
        return self.call(context,
                         self.make_msg('create_barbican_secret',
                                       name=name,
                                       payload=payload))

    def delete_barbican_secret(self, context, name):
        """Calls Barbican API to delete a secret

        :param context: request context.
        :param name: secret name
        """
        return self.call(context,
                         self.make_msg('delete_barbican_secret',
                                       name=name))

    def update_snmp_config(self, context):
        """Synchronously, have a conductor configure the SNMP configuration.

        Does the following tasks:
        - Update puppet hiera configuration file and apply run time manifest

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('update_snmp_config'))

    def ceph_manager_config_complete(self, context, applied_config):
        self.call(context,
                  self.make_msg('ceph_service_config_complete',
                                applied_config=applied_config))

    def get_controllerfs_lv_sizes(self, context):
        return self.call(context,
                         self.make_msg('get_controllerfs_lv_sizes'))

    def get_cinder_gib_pv_sizes(self, context):
        return self.call(context,
                         self.make_msg('get_cinder_gib_pv_sizes'))

    def get_cinder_partition_size(self, context):
        return self.call(context,
                         self.make_msg('get_cinder_partition_size'))

    def region_has_ceph_backend(self, context):
        """
        Send a request to primary region to see if ceph backend is configured
        """
        return self.call(context, self.make_msg('region_has_ceph_backend'))

    def get_system_tpmconfig(self, context):
        """
        Retrieve the system tpmconfig object
        """
        return self.call(context, self.make_msg('get_system_tpmconfig'))

    def get_tpmdevice_by_host(self, context, host_id):
        """
        Retrieve the tpmdevice object for this host
        """
        return self.call(context,
                         self.make_msg('get_tpmdevice_by_host',
                                       host_id=host_id))

    def update_tpm_config(self, context, tpm_context):
        """Synchronously, have the conductor update the TPM config.

        :param context: request context.
        :param tpm_context: TPM object context
        """
        return self.call(context,
                         self.make_msg('update_tpm_config',
                                       tpm_context=tpm_context))

    def update_tpm_config_manifests(self, context, delete_tpm_file=None):
        """Synchronously, have the conductor update the TPM config manifests.

        :param context: request context.
        :param delete_tpm_file: tpm file to delete, optional
        """
        return self.call(context,
                         self.make_msg('update_tpm_config_manifests',
                                       delete_tpm_file=delete_tpm_file))

    def tpm_config_update_by_host(self, context,
                                  host_uuid, response_dict):
        """Get TPM configuration status from Agent host.

        This method allows for alarms to be raised for hosts if TPM
        is not configured properly.

        :param context: an admin context
        :param host_uuid: host unique id
        :param response_dict: configuration status
        :returns: pass or fail
        """
        return self.call(
            context,
            self.make_msg('tpm_config_update_by_host',
                          host_uuid=host_uuid,
                          response_dict=response_dict))

    def tpm_device_update_by_host(self, context,
                                  host_uuid, tpmdevice_dict):
        """Synchronously , have the conductor create or update
        a tpmdevice per host.

        :param context: request context.
        :param host_uuid: uuid or id of the host
        :param tpmdevice_dict: a dictionary of tpm device attributes

        :returns: tpmdevice object
        """
        return self.call(
            context,
            self.make_msg('tpm_device_update_by_host',
                          host_uuid=host_uuid,
                          tpmdevice_dict=tpmdevice_dict))

    def cinder_prepare_db_for_volume_restore(self, context):
        """
        Send a request to cinder to remove all volume snapshots and set all
        volumes to error state in preparation for restoring all volumes.

        This is needed for cinder disk replacement.
        """
        return self.call(context,
                         self.make_msg('cinder_prepare_db_for_volume_restore'))

    def get_ceph_object_pool_name(self, context):
        """
        Get Rados Gateway object data pool name

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('get_ceph_object_pool_name'))

    def get_software_upgrade_status(self, context):
        """
        Software upgrade status is needed by ceph-manager to take ceph specific
        upgrade actions

        This rpcapi function is added to signal that conductor's
        get_software_upgrade_status function is used by an RPC client

        ceph-manager however doesn't call rpcapi.get_software_upgrade_status and
        instead it uses oslo_messaging to construct a call on conductor's topic
        for this function. The reason is that sysinv is using an old version of
        openstack common and messaging libraries incompatible with the one used
        by ceph-manager.
        """
        return self.call(context,
                         self.make_msg('get_software_upgrade_status'))

    def distribute_ceph_external_config(self, context, ceph_conf_filename):
        """Synchronously, have the conductor update the Ceph configuration
        file for external cluster.

        :param context: request context.
        :param ceph_conf_filename: Ceph conf file

        """
        return self.call(context,
                         self.make_msg('distribute_ceph_external_config',
                                       ceph_conf_filename=ceph_conf_filename))

    def store_ceph_external_config(self, context, contents, ceph_conf_filename):
        """Synchronously, have the conductor to write the ceph config file content
        to /opt/platform/config

        :param context: request context.
        :param contents: file content of the Ceph conf file
        :param ceph_conf_filename: Ceph conf file

        """
        return self.call(context,
                         self.make_msg('store_ceph_external_config',
                                       contents=contents,
                                       ceph_conf_filename=ceph_conf_filename))

    def update_partition_information(self, context, partition_data):
        """Synchronously, have the conductor update partition information.

        :param context: request context.
        :param host_uuid: host UUID
        :param partition_uuid: partition UUID
        :param info: dict containing partition information to update

        """
        return self.call(context,
                         self.make_msg('update_partition_information',
                                       partition_data=partition_data))

    def install_license_file(self, context, contents):
        """Sychronously, have the conductor install the license file.

        :param context: request context.
        :param contents: content of license file.
        """
        return self.call(context,
                         self.make_msg('install_license_file',
                                       contents=contents))

    def config_certificate(self, context, pem_contents, config_dict):
        """Synchronously, have the conductor configure the certificate.

        :param context: request context.
        :param pem_contents: contents of certificate in pem format.
        :param config_dict: dictionary of certificate config attributes.

        """
        return self.call(context,
                         self.make_msg('config_certificate',
                                       pem_contents=pem_contents,
                                       config_dict=config_dict,
                                       ))

    def delete_certificate(self, context, mode, signature):
        """Synchronously, have the conductor delete the certificate.

        :param context: request context.
        :param mode: the mode of the certificate
        :param signature: the signature of the certificate.

        """
        return self.call(context,
                         self.make_msg('delete_certificate',
                                       mode=mode,
                                       signature=signature,
                                       ))

    def update_admin_ep_certificate(self, context):
        """Synchronously, have the conductor update the admin endpoint
        certificate and dc root ca cert

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('update_admin_ep_certificate'))

    def update_intermediate_ca_certificate(self, context,
                                    root_ca_crt, sc_ca_cert, sc_ca_key):
        """Update intermediate CA certificate
        :param context: request context
        :param root_ca_crt:  root CA certificate
        :param sc_ca_cert:   intermediate CA certificate
        :param sc_ca_key:    private key
        """
        return self.call(context,
                         self.make_msg('update_intermediate_ca_certificate',
                                       root_ca_crt=root_ca_crt,
                                       sc_ca_cert=sc_ca_cert,
                                       sc_ca_key=sc_ca_key))

    def get_helm_chart_namespaces(self, context, chart_name):
        """Get supported chart namespaces.

        This method retrieves the namespace supported by a given chart.

        :param context: request context.
        :param chart_name: name of the chart
        :returns: list of supported namespaces that associated overrides may be
                  provided.
        """
        return self.call(context,
                         self.make_msg('get_helm_chart_namespaces',
                                       chart_name=chart_name))

    def get_helm_chart_overrides(self, context, app_name, chart_name,
                                 cnamespace=None):
        """Get the overrides for a supported chart.

        :param context: request context.
        :param app_name: name of a supported application
        :param chart_name: name of a supported chart
        :param cnamespace: (optional) namespace
        :returns: dict of overrides.

        """
        return self.call(context,
                         self.make_msg('get_helm_chart_overrides',
                                       app_name=app_name,
                                       chart_name=chart_name,
                                       cnamespace=cnamespace))

    def app_has_system_plugins(self, context, app_name):

        """Determine if the application has system plugin support.

        :returns: True if the application has system plugins and can generate
                  system overrides.
        """
        return self.call(context,
                         self.make_msg('app_has_system_plugins',
                                       app_name=app_name))

    def get_helm_application_namespaces(self, context, app_name):
        """Get supported application namespaces.

        :param app_name: name of the bundle of charts required to support an
                         application
        :returns: dict of charts and supported namespaces that associated
                  overrides may be provided.
        """
        return self.call(context,
                         self.make_msg('get_helm_application_namespaces',
                                       app_name=app_name))

    def get_helm_application_overrides(self, context, app_name, cnamespace=None):
        """Get the overrides for a supported set of charts.

        :param context: request context.
        :param app_name: name of a supported application (set of charts)
        :param cnamespace: (optional) namespace
        :returns: dict of overrides.

        """
        return self.call(context,
                         self.make_msg('get_helm_application_overrides',
                                       app_name=app_name,
                                       cnamespace=cnamespace))

    def merge_overrides(self, context, file_overrides=None, set_overrides=None):
        """Merge the file and set overrides into a single chart overrides.

        :param context: request context.
        :param file_overrides: (optional) list of overrides from files
        :param set_overrides: (optional) list of parameter overrides
        :returns: merged overrides string

        """
        if file_overrides is None:
            file_overrides = []
        if set_overrides is None:
            set_overrides = []
        return self.call(context,
                         self.make_msg('merge_overrides',
                                       file_overrides=file_overrides,
                                       set_overrides=set_overrides))

    def update_kubernetes_label(self, context, host_uuid, label_dict):
        """Synchronously, have the conductor update kubernetes label.

        :param context: request context.
        :param host_uuid: uuid or id of the host
        :param label_dict: a dictionary of kubernetes labels
        """
        return self.call(context,
                         self.make_msg('update_kubernetes_label',
                                       host_uuid=host_uuid,
                                       label_dict=label_dict))

    def update_host_memory(self, context, host_uuid):
        """Asynchronously, have a conductor update the host memory

        :param context: request context.
        :param host_uuid: duuid or id of the host.
        """
        LOG.info("ConductorApi.update_host_memory: sending"
                 " host memory update request to conductor")
        return self.cast(context, self.make_msg('update_host_memory',
                                                host_uuid=host_uuid))

    def update_fernet_repo(self, context, keys=None):
        """Synchronously, have the conductor update fernet keys.

        :param context: request context.
        :param keys: a list of fernet keys
        """
        return self.call(context, self.make_msg('update_fernet_repo',
                                                keys=keys))

    def get_fernet_keys(self, context, key_id=None):
        """Synchronously, have the conductor to retrieve fernet keys.

        :param context: request context.
        :param key_id: (optional)
        :returns: a list of fernet keys.
        """
        return self.call(context, self.make_msg('get_fernet_keys',
                                                key_id=key_id))

    def evaluate_apps_reapply(self, context, trigger):
        """Synchronously, determine whether an application
        re-apply is needed, and if so, raise the re-apply flag.

        :param context: request context.
        :param trigger: dictionary containing at least the 'type' field

        """
        return self.call(context, self.make_msg('evaluate_apps_reapply',
                                                trigger=trigger))

    def evaluate_app_reapply(self, context, app_name):
        """Synchronously, determine whether an application
        re-apply is needed, and if so, raise the re-apply flag.

        :param context: request context.
        :param app_name: application name
        """
        return self.call(context, self.make_msg('evaluate_app_reapply',
                                                app_name=app_name))

    def mtc_action_apps_semantic_checks(self, context, action):
        """Synchronously, call apps semantic check for maintenance actions

        :param context: request context.
        :param action: maintenance action
        """
        return self.call(context, self.make_msg('mtc_action_apps_semantic_checks',
                                                action=action))

    def app_lifecycle_actions(self, context, rpc_app, hook_info):
        """Synchronously, perform any lifecycle actions required
        for the operation

        :param context: request context.
        :param rpc_app: data object provided in the rpc request
        :param hook_info: LifecycleHookInfo object

        """
        return self.call(context, self.make_msg('app_lifecycle_actions',
                                                rpc_app=rpc_app,
                                                hook_info=hook_info))

    def backup_restore_lifecycle_actions(self, context, operation, success):
        """Synchronously, perform any lifecycle actions required
        for backup and restore operations
        :param context: request context.
        :param operation: what operation to notify about.
        :param success: True if the operation was successful, False if it fails.
                        used in post-*-action to indicate that an operation in progress failed.
        """
        return self.call(context, self.make_msg('backup_restore_lifecycle_actions',
                                                operation=operation, success=success))

    def perform_app_upload(self, context, rpc_app, tarfile, lifecycle_hook_info, images=False):
        """Handle application upload request

        :param context: request context.
        :param rpc_app: data object provided in the rpc request
        :param tarfile: location of application tarfile to be extracted
        :param lifecycle_hook_info: LifecycleHookInfo object
        :param images: save application images in the registry as part of app upload

        """
        return self.cast(context,
                         self.make_msg('perform_app_upload',
                                       rpc_app=rpc_app,
                                       tarfile=tarfile,
                                       lifecycle_hook_info_app_upload=lifecycle_hook_info,
                                       images=images))

    def perform_app_apply(self, context, rpc_app, mode, lifecycle_hook_info):
        """Handle application apply request

        :param context: request context.
        :param rpc_app: data object provided in the rpc request
        :param mode: mode to control how to apply application manifest
        :param lifecycle_hook_info: LifecycleHookInfo object

        """
        return self.cast(context,
                         self.make_msg(
                             'perform_app_apply',
                             rpc_app=rpc_app,
                             mode=mode,
                             lifecycle_hook_info_app_apply=lifecycle_hook_info))

    def perform_app_update(self, context, from_rpc_app, to_rpc_app, tarfile,
                           operation, lifecycle_hook_info, reuse_user_overrides=None):
        """Handle application update request

        :param context: request context.
        :param from_rpc_app: data object provided in the rpc request that
                             application update from
        :param to_rpc_app: data object provided in the rpc request that
                           application update to
        :param tarfile: location of application tarfile to be extracted
        :param operation: apply or rollback
        :param lifecycle_hook_info: LifecycleHookInfo object

        :param reuse_user_overrides: (optional) True or False
        """
        return self.cast(context,
                         self.make_msg('perform_app_update',
                                       from_rpc_app=from_rpc_app,
                                       to_rpc_app=to_rpc_app,
                                       tarfile=tarfile,
                                       operation=operation,
                                       lifecycle_hook_info_app_update=lifecycle_hook_info,
                                       reuse_user_overrides=reuse_user_overrides))

    def perform_app_remove(self, context, rpc_app, lifecycle_hook_info):
        """Handle application remove request

        :param context: request context.
        :param rpc_app: data object provided in the rpc request
        :param lifecycle_hook_info: LifecycleHookInfo object

        """
        return self.cast(context,
                         self.make_msg('perform_app_remove',
                                       rpc_app=rpc_app,
                                       lifecycle_hook_info_app_remove=lifecycle_hook_info))

    def perform_app_abort(self, context, rpc_app, lifecycle_hook_info):
        """Handle application abort request

        :param context: request context.
        :param rpc_app: data object provided in the rpc request
        :param lifecycle_hook_info: LifecycleHookInfo object

        """
        return self.call(context,
                         self.make_msg('perform_app_abort',
                                       rpc_app=rpc_app,
                                       lifecycle_hook_info_app_abort=lifecycle_hook_info))

    def perform_app_delete(self, context, rpc_app, lifecycle_hook_info):
        """Handle application delete request

        :param context: request context.
        :param rpc_app: data object provided in the rpc request
        :param lifecycle_hook_info: LifecycleHookInfo object

        """
        return self.call(context,
                         self.make_msg('perform_app_delete',
                                       rpc_app=rpc_app,
                                       lifecycle_hook_info_app_delete=lifecycle_hook_info))

    def reconfigure_service_endpoints(self, context, host):
        """Synchronously, reconfigure service endpoints upon the creation of
        initial controller host and management/oam network change during
        bootstrap playbook play and replay.

        :param context: request context.
        :param host: an ihost object
        """
        return self.call(context,
                         self.make_msg('reconfigure_service_endpoints',
                                       host=host))

    def mgmt_mac_set_by_ihost(self, context, host, mgmt_mac):
        """Update the management mac address upon management interface
        during bootstrap.

        :param context: request context
        :param host: an ihost object
        :param mgmt_mac: mac address of management interface
        """
        return self.call(context,
                         self.make_msg('mgmt_mac_set_by_ihost',
                                       host=host,
                                       mgmt_mac=mgmt_mac))

    def configure_system_controller(self, context, host):
        """Synchronously, configure system controller database and file system
        upon the creation of initial controller host and distributed_cloud_role
        change from 'none' to 'systemcontroller' during bootstrap
        playbook play and replay.

        :param context: request context.
        :param host: an ihost object
        """
        return self.call(context,
                         self.make_msg('configure_system_controller',
                                       host=host))

    def store_default_config(self, context):
        """
        :param context: request context.
        :return:
        """
        return self.call(context, self.make_msg('store_default_config'))

    def kube_download_images(self, context, kube_version):
        """Asynchronously, have the conductor download the kubernetes images
        for this new version.

        :param context: request context
        :param kube_version: kubernetes version to download
        """
        return self.cast(context, self.make_msg('kube_download_images',
                                                kube_version=kube_version))

    def kube_upgrade_control_plane(self, context, host_uuid):
        """Asynchronously, have the conductor upgrade the kubernetes control
        plane on this host.

        :param context: request context
        :param host_uuid: uuid or id of the host
        """
        return self.cast(context, self.make_msg(
            'kube_upgrade_control_plane', host_uuid=host_uuid))

    def kube_upgrade_kubelet(self, context, host_uuid):
        """Asynchronously, have the conductor upgrade the kubernetes kubelet
        plane on this host.

        :param context: request context
        :param host_uuid: uuid or id of the host
        """
        return self.cast(context, self.make_msg('kube_upgrade_kubelet',
                                                host_uuid=host_uuid))

    def kube_upgrade_networking(self, context, kube_version):
        """Asynchronously, have the conductor upgrade networking for this
        new version.

        :param context: request context
        :param kube_version: kubernetes version being upgraded to
        """
        return self.cast(context, self.make_msg('kube_upgrade_networking',
                                                kube_version=kube_version))

    def store_bitstream_file(self, context, filename):
        """Asynchronously, have the conductor store the device image
        on this host.

        :param context: request context
        :param filename: name of the bitstream file
        """
        return self.cast(context, self.make_msg('store_bitstream_file',
                                                filename=filename))

    def delete_bitstream_file(self, context, filename):
        """Asynchronously, have the conductor remove the device image
        on this host.

        :param context: request context
        :param filename: name of the bitstream file
        """
        return self.cast(context, self.make_msg('delete_bitstream_file',
                                                filename=filename))

    def apply_device_image(self, context):
        """Asynchronously, have the conductor apply the device image

        :param context: request context
        """
        return self.cast(context, self.make_msg('apply_device_image'))

    def clear_device_image_alarm(self, context):
        """Asynchronously, have the conductor  clear device image alarm

        :param context: request context
        """
        return self.cast(context, self.make_msg('clear_device_image_alarm'))

    def host_device_image_update(self, context, host_uuid):
        """Asynchronously, have the conductor update the device image
        on this host.

        :param context: request context
        :param host_uuid: uuid or id of the host
        """
        return self.cast(context, self.make_msg('host_device_image_update',
                                                host_uuid=host_uuid))

    def host_device_image_update_abort(self, context, host_uuid):
        """Asynchronously, have the conductor abort the device image update
        on this host.

        :param context: request context
        :param host_uuid: uuid or id of the host
        """
        return self.cast(context, self.make_msg('host_device_image_update_abort',
                                                host_uuid=host_uuid))

    def fpga_device_update_by_host(self, context, host_uuid,
                                   fpga_device_dict_array):
        """
        Asynchronously, update information on FPGA device.

        This will check whether the current state of the device matches the
        expected state, and if it doesn't then an alarm will be raised.
        :param context:
        :param host_uuid:  The host_uuid for the caller.
        :param fpga_device_dict_array:  An array of device information.
        :return:
        """
        return self.cast(context,
                         self.make_msg('fpga_device_update_by_host',
                                       host_uuid=host_uuid,
                                       fpga_device_dict_array=fpga_device_dict_array))

    def device_update_image_status(self, context, host_uuid, transaction_id,
                                   status, progress=None, err=None):
        """
        Asynchronously, update status of firmware update operation

        This is used to report progress and final success/failure of an FPGA image write
        operation.  The transaction ID maps to a unique identifier in the sysinv DB so
        we don't need to report host_uuid or device PCI address.
        :param context:
        :param host_uuid:       The host_uuid for the host that is reporting the status.
        :param transaction_id:  The transaction ID representing this image-update operation.
        :param status:          The status of the image-update operation.
        :param progress:        Optional progress indicator.
        :param err:             Optional error message.
        :return:
        """
        return self.cast(context,
                         self.make_msg('device_update_image_status',
                                       host_uuid=host_uuid,
                                       transaction_id=transaction_id,
                                       status=status,
                                       progress=progress,
                                       err=err))

    def start_restore(self, context):
        """Synchronously, have the conductor start the restore

        :param context: request context.
        """
        return self.call(context, self.make_msg('start_restore'))

    def complete_restore(self, context):
        """Synchronously, have the conductor complete the restore

        :param context: request context.
        """
        return self.call(context, self.make_msg('complete_restore'))

    def get_restore_state(self, context):
        """Get the restore state

        :param context: request context.
        """
        return self.call(context, self.make_msg('get_restore_state'))

    def update_ldap_client_config(self, context):
        """Synchronously, have a conductor configure LDAP client configureation

        Does the following tasks:
        - Update puppet hiera configuration file and apply run time manifest.

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('update_ldap_client_config'))

    def update_dnsmasq_config(self, context):
        """Synchronously, have a conductor configure the DNS configuration

        Does the following tasks:
        - Update puppet hiera configuration file and apply run time manifest.

        :param context: request context.
        """
        return self.call(context,
                         self.make_msg('update_dnsmasq_config'))

    def save_kubernetes_rootca_cert(self, context, certificate_file):
        """Save the new uploaded k8s root CA certificate

        :param context: request context.
        :certificate_file: the new rootca PEM file
        """
        return self.call(context, self.make_msg('save_kubernetes_rootca_cert',
                                             ca_file=certificate_file))

    def generate_kubernetes_rootca_cert(self, context):
        """Generate new kubernetes root CA certificate

        :param context: request context.
        """
        return self.call(context, self.make_msg('generate_kubernetes_rootca_cert'))

    def kube_certificate_update_by_host(self, context, host_uuid, phase):
        """
        Asynchronously, have the conductor update the host's kube certificates.

        :param context: request context.
        :param host_uuid: the host to update the certificate on.
        :param phase: the phase of the update.
        """
        return self.cast(
            context, self.make_msg(
                'kube_certificate_update_by_host',
                host_uuid=host_uuid,
                phase=phase
            )
        )
