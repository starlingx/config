#
# Copyright (c) 2017-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import netaddr
import glob
import ipaddress

from oslo_log import log

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils

from sysinv.puppet import base
from sysinv.puppet import interface

LOG = log.getLogger(__name__)

IPv4 = constants.IP_FAMILIES[constants.IPV4_FAMILY].lower()
IPv6 = constants.IP_FAMILIES[constants.IPV6_FAMILY].lower()


class NetworkingPuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for networking configuration"""

    def get_system_config(self):
        config = {}
        config.update(self._get_pxeboot_network_config())
        config.update(self._get_mgmt_network_config())
        config.update(self._get_oam_network_config())
        config.update(self._get_cluster_network_config())
        config.update(self._get_ironic_network_config())
        config.update(self._get_admin_network_config())
        config.update(self._get_storage_network_config())

        config.update(self._get_cluster_pod_config())
        config.update(self._get_cluster_service_config())
        config.update(self._get_blackhole_address())
        return config

    def get_host_config(self, host):
        config = {}
        config.update(self._get_pxeboot_interface_config())
        config.update(self._get_mgmt_interface_config())
        config.update(self._get_cluster_interface_config())
        config.update(self._get_ironic_interface_config())
        config.update(self._get_storage_interface_config())
        config.update(self._get_admin_interface_config())
        config.update(self._get_instance_ptp_config(host))
        if host.personality == constants.CONTROLLER:
            config.update(self._get_oam_interface_config())
        return config

    def _get_pxeboot_network_config(self):
        return self._get_network_config(constants.NETWORK_TYPE_PXEBOOT)

    def _get_mgmt_network_config(self):
        networktype = constants.NETWORK_TYPE_MGMT

        config = self._get_network_config(networktype)

        config = self._get_network_gateway_config(networktype, config)

        # create flag for the mate controller to use FQDN or not
        if utils.is_fqdn_ready_to_use(True):
            fqdn_ready = True
        else:
            fqdn_ready = False

        config.update({
            'platform::network::%s::params::fqdn_ready' % networktype:
                fqdn_ready,
        })

        # TODO(fcorream): platform-nfs-iaddress is just necessary to allow
        # an upgrade from StarlingX releases 6 or 7 to new releases.
        # remove it when StarlingX rel. 6 or 7 are not being used anymore
        # During the upgrade If platform-nfs-ip is still available in the DB,
        # add it to the config to allow downgrade if something goes wrong
        try:
            platform_nfs_address = self._get_address_by_name(
                'controller-platform-nfs', networktype).address
        except exception.AddressNotFoundByName:
            platform_nfs_address = None

        if platform_nfs_address is not None:
            config.update({
                'platform::network::%s::params::platform_nfs_address' % networktype:
                    platform_nfs_address,
            })

        return config

    def _get_cluster_network_config(self):
        networktype = constants.NETWORK_TYPE_CLUSTER_HOST
        config = self._get_network_config(networktype)
        return config

    def _get_cluster_pod_config(self):
        networktype = constants.NETWORK_TYPE_CLUSTER_POD
        config = self._get_network_config(networktype)
        return config

    def _get_cluster_service_config(self):
        networktype = constants.NETWORK_TYPE_CLUSTER_SERVICE
        config = self._get_network_config(networktype)
        return config

    def _get_oam_network_config(self):
        networktype = constants.NETWORK_TYPE_OAM

        config = self._get_network_config(networktype)

        config = self._get_network_gateway_config(networktype, config)

        return config

    def _get_ironic_network_config(self):
        networktype = constants.NETWORK_TYPE_IRONIC
        config = self._get_network_config(networktype)
        return config

    def _get_storage_network_config(self):
        networktype = constants.NETWORK_TYPE_STORAGE
        config = self._get_network_config(networktype)
        return config

    def _get_admin_network_config(self):
        networktype = constants.NETWORK_TYPE_ADMIN
        config = self._get_network_config(networktype)
        return config

    def _get_network_config(self, networktype):
        try:
            network = self.dbapi.network_get_by_type(networktype)
        except exception.NetworkTypeNotFound:
            LOG.debug(f"Network type {networktype} not found")
            return {}

        net_pools = self.dbapi.network_addrpool_get_by_network_id(network.id)
        pool_uuid_list = list()
        if net_pools:
            for net_pool in net_pools:
                pool_uuid_list.append(net_pool.address_pool_uuid)
        else:
            # we are coming from an upgrade without data-migration implemented for the
            # dual stack feature
            LOG.warning(f"Network {network.name} does not have network to address pool objects")
            pool_uuid_list.append(network.pool_uuid)

        configdata = dict()
        config = dict()

        for pool_uuid in pool_uuid_list:

            address_pool = self.dbapi.address_pool_get(pool_uuid)

            family_name = IPv4 if address_pool.family == constants.IPV4_FAMILY else IPv6
            configdata.update({family_name: {}})

            subnet = netaddr.IPNetwork(
                str(address_pool.network) + '/' + str(address_pool.prefix))
            configdata[family_name].update({'subnet': subnet})

            configdata[family_name].update({'subnet_version': address_pool.family})
            configdata[family_name].update({'subnet_network': str(subnet.network)})
            configdata[family_name].update({'subnet_netmask': str(subnet.netmask)})
            configdata[family_name].update({'subnet_prefixlen': subnet.prefixlen})
            configdata[family_name].update({'subnet_start': str(address_pool.ranges[0][0])})
            configdata[family_name].update({'subnet_end': str(address_pool.ranges[0][-1])})

            try:
                controller_address = self._get_address_by_name_and_family(
                    constants.CONTROLLER_HOSTNAME, address_pool.family, networktype).address
            except exception.AddressNotFoundByNameAndFamily:
                controller_address = None
            configdata[family_name].update({'controller_address': controller_address})

            try:
                controller0_address = self._get_address_by_name_and_family(
                    constants.CONTROLLER_0_HOSTNAME, address_pool.family, networktype).address
            except exception.AddressNotFoundByNameAndFamily:
                controller0_address = None
            configdata[family_name].update({'controller0_address': controller0_address})

            if (
                utils.is_aio_simplex_system(self.dbapi)
                and controller0_address is None
                and networktype in (
                        constants.NETWORK_TYPE_ADMIN,
                        constants.NETWORK_TYPE_MGMT,
                        constants.NETWORK_TYPE_CLUSTER_HOST,
                        constants.NETWORK_TYPE_STORAGE,
                )
            ):
                configdata[family_name].update({'controller0_address': controller_address})

            try:
                controller1_address = self._get_address_by_name_and_family(
                    constants.CONTROLLER_1_HOSTNAME, address_pool.family, networktype).address
            except exception.AddressNotFoundByNameAndFamily:
                controller1_address = None
            configdata[family_name].update({'controller1_address': controller1_address})

            configdata[family_name].update({'controller_address_url':
                                            self._format_url_address(controller_address)})
            configdata[family_name].update({'subnet_network_url':
                                            self._format_url_address(str(subnet.network))})

        # Convert the dash to underscore because puppet parameters cannot have
        # dashes
        networktype = networktype.replace('-', '_')

        for family in configdata:
            config[f'platform::network::{networktype}::{family}::params::subnet_version'] = \
                configdata[family]['subnet_version']
            config[f'platform::network::{networktype}::{family}::params::subnet_network'] = \
                configdata[family]['subnet_network']
            config[f'platform::network::{networktype}::{family}::params::subnet_network_url'] = \
                configdata[family]['subnet_network_url']
            config[f'platform::network::{networktype}::{family}::params::subnet_prefixlen'] = \
                configdata[family]['subnet_prefixlen']
            config[f'platform::network::{networktype}::{family}::params::subnet_netmask'] = \
                configdata[family]['subnet_netmask']
            config[f'platform::network::{networktype}::{family}::params::subnet_start'] = \
                configdata[family]['subnet_start']
            config[f'platform::network::{networktype}::{family}::params::subnet_end'] = \
                configdata[family]['subnet_end']
            config[f'platform::network::{networktype}::{family}::params::controller_address'] = \
                configdata[family]['controller_address']
            config[f'platform::network::{networktype}::{family}::params::controller_address_url'] = \
                configdata[family]['controller_address_url']
            config[f'platform::network::{networktype}::{family}::params::controller0_address'] = \
                configdata[family]['controller0_address']
            config[f'platform::network::{networktype}::{family}::params::controller1_address'] = \
                configdata[family]['controller1_address']

        if network.primary_pool_family \
                and (network.primary_pool_family).lower() in configdata.keys():
            family = network.primary_pool_family.lower()
            config[f'platform::network::{networktype}::params::subnet_version'] = \
                configdata[family]['subnet_version']
            config[f'platform::network::{networktype}::params::subnet_network'] = \
                configdata[family]['subnet_network']
            config[f'platform::network::{networktype}::params::subnet_network_url'] = \
                configdata[family]['subnet_network_url']
            config[f'platform::network::{networktype}::params::subnet_prefixlen'] = \
                configdata[family]['subnet_prefixlen']
            config[f'platform::network::{networktype}::params::subnet_netmask'] = \
                configdata[family]['subnet_netmask']
            config[f'platform::network::{networktype}::params::subnet_start'] = \
                configdata[family]['subnet_start']
            config[f'platform::network::{networktype}::params::subnet_end'] = \
                configdata[family]['subnet_end']
            config[f'platform::network::{networktype}::params::controller_address'] = \
                configdata[family]['controller_address']
            config[f'platform::network::{networktype}::params::controller_address_url'] = \
                configdata[family]['controller_address_url']
            config[f'platform::network::{networktype}::params::controller0_address'] = \
                configdata[family]['controller0_address']
            config[f'platform::network::{networktype}::params::controller1_address'] = \
                configdata[family]['controller1_address']
        else:
            LOG.error(f"Network {network.name}, type {network.type} does not have a valid"
                      f" primary pool address family: {network.primary_pool_family}.")

        return config

    def _get_pxeboot_interface_config(self):
        return self._get_interface_config(constants.NETWORK_TYPE_PXEBOOT)

    def _get_mgmt_interface_config(self):
        return self._get_interface_config(constants.NETWORK_TYPE_MGMT)

    def _get_oam_interface_config(self):
        return self._get_interface_config(constants.NETWORK_TYPE_OAM)

    def _get_cluster_interface_config(self):
        return self._get_interface_config(constants.NETWORK_TYPE_CLUSTER_HOST)

    def _get_ironic_interface_config(self):
        return self._get_interface_config(constants.NETWORK_TYPE_IRONIC)

    def _get_storage_interface_config(self):
        return self._get_interface_config(constants.NETWORK_TYPE_STORAGE)

    def _get_admin_interface_config(self):
        return self._get_interface_config(constants.NETWORK_TYPE_ADMIN)

    def _get_network_gateway_config(self, networktype, config):
        try:
            network = self.dbapi.network_get_by_type(networktype)
        except exception.NetworkTypeNotFound:
            LOG.debug(f"Network type {networktype} not found")
            return {}

        net_pools = self.dbapi.network_addrpool_get_by_network_id(network.id)
        pool_uuid_list = list()
        if net_pools:
            for net_pool in net_pools:
                pool_uuid_list.append(net_pool.address_pool_uuid)
        else:
            # we are coming from an upgrade without data-migration implemented for the
            # dual stack feature
            LOG.warning(f"Network {network.name} does not have network to address pool objects")
            pool_uuid_list.append(network.pool_uuid)

        configdata = dict()
        for pool_uuid in pool_uuid_list:
            address_pool = self.dbapi.address_pool_get(pool_uuid)

            family = IPv4 if address_pool.family == constants.IPV4_FAMILY else IPv6
            configdata.update({family: {}})

            try:
                gateway_address = self._get_address_by_name_and_family(
                    constants.CONTROLLER_GATEWAY, address_pool.family, networktype).address
            except exception.AddressNotFoundByNameAndFamily:
                gateway_address = None
            configdata[family].update({'gateway_address': gateway_address})

        for family in configdata:
            config.update({f'platform::network::{networktype}::{family}::params::gateway_address':
                                configdata[family]['gateway_address']})

        if network.primary_pool_family \
                and (network.primary_pool_family).lower() in configdata.keys():
            family = network.primary_pool_family.lower()
            config.update({f'platform::network::{networktype}::params::gateway_address':
                                configdata[family]['gateway_address']})
        else:
            LOG.error(f"Network {network.name}, type {network.type} does not have a valid"
                      f" primary pool address family: {network.primary_pool_family}.")

        return config

    def _get_blackhole_address(self):
        """ returm the address to be added as a blackhole route to be used when an address
            needs to be provided to the configuration but it is not used and traffic to be discarded
        """
        config = dict()

        # RFC6666
        config.update({'platform::network::blackhole::ipv6_subnet': "100::/64"})
        config.update({'platform::network::blackhole::ipv6_host': "100::1"})

        # there is no specification for IPv4, selecting a single host address, as more is not needed
        # creating a list of possible candidates:
        ipv4_blackhole_list = ["169.254.254.254/32",  # preferred option, non-routable address
                               "169.254.127.254/32",  # non-routable address
                               "169.254.64.254/32",   # non-routable address
                               "192.168.254.254/32",  # address in the private network range
                               "192.168.127.254/32",  # address in the private network range
                               "192.168.64.254/32",  # address in the private network range
                               "10.254.254.254/32",   # address in the private network range
                               "10.254.127.254/32",   # address in the private network range
                               "10.254.64.254/32",   # address in the private network range
                               "172.16.254.254/32",   # address in the private network range
                               "172.16.127.254/32",   # address in the private network range
                               "172.16.64.254/32"]   # address in the private network range
        addr_pool_list = self.dbapi.address_pools_get_all()
        for subnet in ipv4_blackhole_list:
            overlap = False
            for pool in addr_pool_list:
                try:
                    blackhole_net = ipaddress.ip_network(subnet, strict=False)
                    pool_net = ipaddress.ip_network(f"{pool.network}/{pool.prefix}", strict=False)
                    if blackhole_net.overlaps(pool_net):
                        overlap = True
                except ValueError as e:
                    LOG.info(f"Error: Invalid network address provided: {e}")
                    overlap = False
            if not overlap:
                config.update({'platform::network::blackhole::ipv4_subnet': subnet})
                config.update({'platform::network::blackhole::ipv4_host': subnet.split('/')[0]})
                break

        if 'platform::network::blackhole::ipv4_host' not in config.keys():
            LOG.error("cannot select an IPv4 address from the blackhole candidate list")

        return config

    def _set_ptp_instance_monitoring_global_parameters(
        self, instance, ptp_parameters_instance
    ):
        default_global_parameters = {
            "satellite_count": constants.PTP_MONITORING_SATELLITE_COUNT,
            "signal_quality_db": constants.PTP_MONITORING_SIGNAL_QUALITY_DB_VALUE,
        }
        default_cmdline_opts = ""

        # Add default global parameters the instance
        instance["global_parameters"] = default_global_parameters
        instance["cmdline_opts"] = default_cmdline_opts

        for global_param in ptp_parameters_instance:
            # Add the supplied instance parameters to global_parameters
            if instance["uuid"] in global_param["owners"]:
                instance["global_parameters"][global_param["name"]] = global_param[
                    "value"
                ]
            if "cmdline_opts" in instance["global_parameters"]:
                cmdline = instance["global_parameters"].pop("cmdline_opts")
                quotes = {"'", "\\'", '"', '\\"'}
                for quote in quotes:
                    cmdline = cmdline.strip(quote)
                instance["cmdline_opts"] = cmdline

        allowed_instance_fields = ["global_parameters", "cmdline_opts"]
        monitoring_config = {r: instance[r] for r in allowed_instance_fields}

        return monitoring_config

    def _set_ptp_instance_global_parameters(self, ptp_instances, ptp_parameters_instance):
        default_global_parameters = {
            # Default ptp4l parameters were determined during the original integration of PTP.
            # These defaults maintain the same PTP behaviour as single instance implementation.
            'ptp4l': {
                'tx_timestamp_timeout': constants.PTP_TX_TIMESTAMP_TIMEOUT,
                'summary_interval': constants.PTP_SUMMARY_INTERVAL,
                'clock_servo': constants.PTP_CLOCK_SERVO_LINREG,
                'network_transport': constants.PTP_NETWORK_TRANSPORT_IEEE_802_3,
                'time_stamping': constants.PTP_TIME_STAMPING_HARDWARE,
                'delay_mechanism': constants.PTP_DELAY_MECHANISM_E2E
            },
            'phc2sys': {},
            # Default ts2phc paramters taken from the user documentation for
            # Intel E810-XXVDA4T NICs
            'ts2phc': {
                'ts2phc.pulsewidth': constants.PTP_TS2PHC_PULSEWIDTH_100000000,
                'leapfile': constants.PTP_LEAPFILE_PATH
            },
            'synce4l': {}
        }

        default_cmdline_opts = {
            'ptp4l': '',
            'phc2sys': '-a -r -R 2 -u 600',
            'ts2phc': '-s nmea',
            'synce4l': '',
        }

        default_pmc_parameters = {
            'clockClass': constants.PTP_PMC_CLOCK_CLASS,
            'clockAccuracy': constants.PTP_PMC_CLOCK_ACCURACY,
            'offsetScaledLogVariance': constants.PTP_PMC_OFFSET_SCALED_LOG_VARIANCE,
            'currentUtcOffset': constants.PTP_PMC_CURRENT_UTC_OFFSET,
            'leap61': constants.PTP_PMC_LEAP61,
            'leap59': constants.PTP_PMC_LEAP59,
            'currentUtcOffsetValid': constants.PTP_PMC_CURRENT_UTC_OFFSET_VALID,
            'ptpTimescale': constants.PTP_PMC_PTP_TIMESCALE,
            'timeTraceable': constants.PTP_PMC_TIME_TRACEABLE,
            'frequencyTraceable': constants.PTP_PMC_FREQUENCY_TRACEABLE,
            'timeSource': constants.PTP_PMC_TIME_SOURCE
        }

        default_device_parameters = {
            'input_mode': constants.PTP_SYNCE_INPUT_MODE_LINE,
            'input_QL': constants.PTP_SYNCE_EXTERNAL_INPUT_QL,
            'input_ext_QL': constants.PTP_SYNCE_EXTERNAL_INPUT_EXT_QL,
            'extended_tlv': constants.PTP_SYNCE_EXTERNAL_TLV,
            'network_option': constants.PTP_SYNCE_NETWORK_OPTION,
            'recover_time': constants.PTP_SYNCE_RECOVER_TIME,
            'eec_holdover_value': constants.PTP_SYNCE_EEC_HOLDOVER_VALUE,
            'eec_locked_ho_value': constants.PTP_SYNCE_EEC_LOCKED_HO_VALUE,
            'eec_locked_value': constants.PTP_SYNCE_EEC_LOCKED_VALUE,
            'eec_freerun_value': constants.PTP_SYNCE_EEC_FREERUN_VALUE,
            'eec_invalid_value': constants.PTP_SYNCE_EEC_INVALID_VALUE
        }

        allowed_instance_fields = ['global_parameters', 'interfaces', 'name', 'service',
                                   'cmdline_opts', 'id', 'pmc_gm_settings', 'device_parameters',
                                   'gnss_uart_disable', 'external_source']
        ptp_config = {}

        for instance in ptp_instances:
            # Add default global parameters the instance
            instance['global_parameters'] = {}
            instance['cmdline_opts'] = ""
            instance['global_parameters'].update(default_global_parameters[instance['service']])
            instance['cmdline_opts'] = default_cmdline_opts[instance['service']]
            instance['interfaces'] = []
            instance['pmc_gm_settings'] = {}
            instance['device_parameters'] = {}
            instance['gnss_uart_disable'] = True
            instance['external_source'] = {}

            # Additional defaults for ptp4l instances
            if instance['service'] == constants.PTP_INSTANCE_TYPE_PTP4L:
                uds_address_path = '/var/run/' + instance['service'] + '-' + instance['name']
                instance['global_parameters'].update({
                    'message_tag': instance['name'],
                    'uds_address': uds_address_path
                })
                if utils.is_centos():
                    # Currently only CentOS's linuxptp has support to UDS-RO
                    instance['global_parameters'].update({
                        'uds_ro_address': uds_address_path + 'ro'
                    })
            elif instance['service'] == constants.PTP_INSTANCE_TYPE_PHC2SYS:
                instance['global_parameters'].update({
                    'message_tag': instance['name']
                })
            elif instance['service'] == constants.PTP_INSTANCE_TYPE_SYNCE4L:
                instance['global_parameters'].update({
                    'message_tag': instance['name'],
                    'smc_socket_path': '/tmp/synce4l_socket_%s' % instance['name']
                })
                instance['device_parameters'].update(default_device_parameters)
            elif instance['service'] == constants.PTP_INSTANCE_TYPE_TS2PHC:
                instance['global_parameters'].update({
                    'message_tag': instance['name']
                })

            for global_param in ptp_parameters_instance:
                # Add the supplied instance parameters to global_parameters
                if instance['uuid'] in global_param['owners']:
                    if instance['service'] != constants.PTP_INSTANCE_TYPE_SYNCE4L:
                        instance['global_parameters'][global_param['name']] = global_param['value']
                    else:
                        # Separate the global and device parameters for synce4l
                        if global_param['name'] in ['logging_level', 'use_syslog',
                                                    'verbose', 'message_tag']:
                            instance['global_parameters'][global_param['name']] = global_param['value']
                        else:
                            instance['device_parameters'][global_param['name']] = global_param['value']
                if 'cmdline_opts' in instance['global_parameters']:
                    cmdline = instance['global_parameters'].pop('cmdline_opts')
                    quotes = {"'", "\\'", '"', '\\"'}
                    for quote in quotes:
                        cmdline = cmdline.strip(quote)
                    instance['cmdline_opts'] = cmdline

                # Move out special gnss_uart_disable from ts2phc's global_parameters
                if instance['service'] == constants.PTP_INSTANCE_TYPE_TS2PHC:
                    if 'gnss_uart_disable' in instance['global_parameters']:
                        tmp = instance['global_parameters'].pop('gnss_uart_disable')
                        instance['gnss_uart_disable'] = tmp.lower() == 'true'

            if instance['service'] == constants.PTP_INSTANCE_TYPE_PTP4L:
                # Add pmc parameters so that they can be set by puppet
                instance['pmc_gm_settings'].update(default_pmc_parameters)
                for key in default_pmc_parameters:
                    if key in instance['global_parameters'].keys():
                        instance['pmc_gm_settings'][key] = instance['global_parameters'][key]
                # currentUtcOffsetValid is a special case, it is not a valid parameter to leave
                # in the global_parameters section of the ptp4l config
                if 'currentUtcOffsetValid' in instance['global_parameters']:
                    instance['global_parameters'].pop('currentUtcOffsetValid')
                # utc_offset is another special case. It has different naming from its pmc
                # parameter and needs to be renamed to 'currentUtcOffset'
                # It should still be left in the global section of the ptp4l config
                if 'utc_offset' in instance['global_parameters']:
                    instance['pmc_gm_settings']['currentUtcOffset'] = \
                        instance['global_parameters']['utc_offset']

                if (instance['global_parameters']['time_stamping'] ==
                        constants.PTP_TIME_STAMPING_HARDWARE):
                    instance['global_parameters'][constants.PTP_PARAMETER_BC_JBOD] = (
                        constants.PTP_BOUNDARY_CLOCK_JBOD_1)

            # Prune fields and add the instance to the config
            # Change 'name' key to '_name' because it is unusable in puppet
            pruned_instance = {r: instance[r] for r in allowed_instance_fields}
            pruned_instance['_name'] = pruned_instance.pop('name')
            ptp_config[pruned_instance['_name']] = pruned_instance

        return ptp_config

    def _set_ptp_instance_interfaces(self, host, ptp_instances, ptp_interfaces):
        allowed_interface_fields = ['ifname',
                                    'port_names',
                                    'parameters',
                                    'uuid']

        for instance in ptp_instances:
            for iface in ptp_interfaces:
                # Find the interfaces that belong to this instance
                if iface['ptp_instance_id'] == ptp_instances[instance]['id']:
                    iface['parameters'] = {}
                    # Find the underlying port name for the interface because
                    # ptp can't use the custom interface name (exception: AE)
                    for hostinterface in iface['interface_names']:
                        temp_host = hostinterface.split('/')[0]
                        temp_interface = hostinterface.split('/')[1]
                        if host.hostname == temp_host:
                            iinterface = self.context['interfaces'].get(temp_interface)
                            if (iinterface is None or iinterface.ihost_uuid != host.uuid):
                                iinterface = self.dbapi.iinterface_get(
                                    temp_interface, host.uuid)
                            if iinterface['iftype'] == constants.INTERFACE_TYPE_AE:
                                if_devices = [temp_interface]
                            elif iinterface['iftype'] == constants.INTERFACE_TYPE_VLAN:
                                if_devices = [interface.get_interface_os_ifname(
                                    self.context, iinterface)]
                            else:
                                if_devices = interface.get_interface_devices(
                                    self.context, iinterface)
                            iface['port_names'] = if_devices
                            iface['ifname'] = temp_interface

                            # Prune fields and add the interface to the
                            # instance
                            pruned_iface = \
                                {r: iface[r] for r in allowed_interface_fields}
                            ptp_instances[instance]['interfaces'].append(
                                pruned_iface)

        return ptp_instances

    def _set_ptp_instance_interface_parameters(self, host, ptp_instances, ptp_parameters_interface):

        default_interface_parameters = {
            'ptp4l': {},
            'phc2sys': {},
            'ha_phc2sys': {
                'ha_priority': '0'
            },
            'ts2phc': {
                'ts2phc.extts_polarity': 'rising'
            },
            'clock': {},
            'synce4l': {
                'tx_heartbeat_msec': constants.PTP_SYNCE_TX_HEARTBEAT_MSEC,
                'rx_heartbeat_msec': constants.PTP_SYNCE_RX_HEARTBEAT_MSEC,
            },
        }
        recover_clk_cmd_fmt = 'echo %s 0 > /sys/class/net/%s/device/phy/synce'
        ecc_get_state_cmd_fmt = 'cat /sys/class/net/%s/device/dpll_0_state'

        for instance in ptp_instances:
            current_instance = ptp_instances[instance]
            for iface in current_instance['interfaces']:
                # Add default interface values
                iface['parameters'].update(default_interface_parameters
                                          [current_instance['service']])
                # Handle HA phc2sys
                if current_instance['service'] == constants.PTP_INSTANCE_TYPE_PHC2SYS:
                    if 'ha_enabled' in current_instance['global_parameters'] and \
                            current_instance['global_parameters']['ha_enabled'] == '1':
                        iface['parameters'].update(default_interface_parameters
                                                   ['ha_phc2sys'])
                # Handle synce4l dynamic parameters
                if current_instance['service'] == constants.PTP_INSTANCE_TYPE_SYNCE4L:
                    base_port = None
                    port_name = iface['port_names'][0]
                    if port_name:
                        iface['parameters'].update({'recover_clock_disable_cmd':
                            recover_clk_cmd_fmt % (0, port_name)})
                        iface['parameters'].update({'recover_clock_enable_cmd':
                            recover_clk_cmd_fmt % (1, port_name)})
                        base_port = self._get_base_port(host, port_name)
                        if base_port:
                            current_instance['device_parameters'].update({'eec_get_state_cmd':
                                ecc_get_state_cmd_fmt % base_port})
                    # Handle synce4l external source parameters
                    current_instance['external_source'] = self._set_external_source_parameters(
                        iface['uuid'],
                        ptp_parameters_interface,
                        base_port)
                # Add supplied params to the interface
                for param in ptp_parameters_interface:
                    if iface['uuid'] in param['owners']:
                        iface['parameters'][param['name']] = param['value']

        return ptp_instances

    def _generate_clock_port_dict(self, host, nic_clock_config, host_port_list):
        port_dict = {}
        for instance in nic_clock_config:
            for iface in nic_clock_config[instance]['interfaces']:
                # Rebuild list by port_names rather than interface names
                for port in iface['port_names']:
                    port_dict[port] = iface
                    port_dict[port]['base_port'] = ""
                    base_port = self._get_base_port(host, port)
                    if base_port:
                        port_dict[port]['base_port'] = base_port
        return port_dict

    def _get_base_port(self, host, port_name):
        base_port = ""
        host_port_list = self.dbapi.port_get_all(hostid=host.id)
        # Get port 0 for the configured NIC
        for p in host_port_list:
            if port_name == p['name']:
                # Take the PCI address of the supplied port and replace the end
                # value with 0 to identify the base port on that nic
                port_pci_base = p['pciaddr'].split('.')[0] + ".0"
                # Find the port that has the matching pci address and take this
                # as the base port
                for q in host_port_list:
                    if q['pciaddr'] == port_pci_base:
                        base_port = q['name']
                        break
        return base_port

    def _get_ptp_dev_info(self, base_port, meta_params_dict):
        pin = meta_params_dict['external_source']
        direction_map = {'input': 1, 'output': 2}
        default_pin_map = {'SMA1': 'input',
                           'SMA2': 'output',
                           'U.FL1': 'input',
                           'U.FL2': 'output',
                           }

        # Validate PTP dev and get pin path
        path = '/sys/class/net/%s/device/ptp/*/pins/%s' % (base_port, pin)
        path_list = glob.glob(path)
        if len(path_list) != 1:
            LOG.error(f'Cannot find a PTP device in {path}')
            return None
        pin_path = path_list[0]
        # Get the pin channel
        try:
            with open(pin_path) as f:
                line = f.readline().strip('\n')
                channel = line.split(' ')[1]
        except Exception:
            LOG.error(f'Cannot find a PTP pin channel device in {pin_path}')
            return None
        if 'external_source_direction' in meta_params_dict:
            direction = meta_params_dict['external_source_direction']
        else:
            direction = default_pin_map[pin]
            LOG.info(f'PTP pin {pin} direction not specified, using the default: {direction}')
        if direction not in direction_map.keys():
            LOG.error(f'Bad PTP pin direction: \'{direction}\'')
            return None
        return {'func': direction_map[direction], 'channel': channel, 'path': pin_path}

    def _ptp_parameters_interface_del(self, ptp_parameters_interface, param, iface_uuid):
        if len(param['owners']) > 1:
            param['owners'].remove(iface_uuid)
        else:
            ptp_parameters_interface.remove(param)

    def _set_external_source_parameters(self, iface_uuid, ptp_parameters_interface, base_port):
        if not base_port:
            LOG.warning('Cannot set synce4l external source, no base port')
            return

        default_params = {
            'input_QL': constants.PTP_SYNCE_EXTERNAL_INPUT_QL,
            'input_ext_QL': constants.PTP_SYNCE_EXTERNAL_INPUT_EXT_QL,
            'internal_prio': constants.PTP_SYNCE_INTERNAL_PRIO,
        }

        meta_params = ('external_source', 'external_source_direction')
        synce4l_params = ('input_QL', 'input_ext_QL', 'internal_prio', 'external_enable_cmd', 'external_disable_cmd')

        # Handle meta parameters first (not forwarded to the sync4l config)
        meta_params_dict = {}
        for param in ptp_parameters_interface[:]:
            if iface_uuid not in param['owners']:
                continue
            if param['name'] in meta_params:
                meta_params_dict[param['name']] = param['value']
                self._ptp_parameters_interface_del(ptp_parameters_interface, param, iface_uuid)

        # Create the external source section
        external_source = {}
        if 'external_source' in meta_params_dict:
            info = self._get_ptp_dev_info(base_port, meta_params_dict)
            if info:
                external_source['name'] = meta_params_dict['external_source']
                external_source['params'] = default_params
                external_source['params'].update({'external_disable_cmd':
                    'echo %s %s > %s' % (0, info['channel'], info['path'])})
                external_source['params'].update({'external_enable_cmd':
                    'echo %s %s > %s' % (info['func'], info['channel'], info['path'])})

        # Finish handling the real parameters
        if 'name' in external_source:
            for param in ptp_parameters_interface[:]:
                if iface_uuid not in param['owners']:
                    continue
                if param['name'] in synce4l_params:
                    external_source['params'].update({param['name']: param['value']})
                    self._ptp_parameters_interface_del(ptp_parameters_interface, param, iface_uuid)
        return external_source

    def _get_instance_ptp_config(self, host):

        if (host.clock_synchronization != constants.PTP):
            ptpinstance_enabled = False
            return {'platform::ptpinstance::enabled': ptpinstance_enabled}
        else:
            ptpinstance_enabled = True

        # Get the database entries for instances, interfaces, parameters, ports
        ptp_instances = self.dbapi.ptp_instances_get_list(host=host.id)
        ptp_interfaces = self.dbapi.ptp_interfaces_get_list(host=host.uuid)
        ptp_parameters_instance = self.dbapi.ptp_parameters_get_list_by_type(
                                  constants.PTP_PARAMETER_OWNER_INSTANCE)
        ptp_parameters_interface = self.dbapi.ptp_parameters_get_list_by_type(
                                   constants.PTP_PARAMETER_OWNER_INTERFACE)

        nic_clocks = {}
        nic_clock_config = {}
        nic_clock_enabled = False
        ptp_instance_configs = []
        monitoring_instance_configs = []

        for index, instance in enumerate(ptp_instances):
            if ptp_instances[index]['service'] == constants.PTP_INSTANCE_TYPE_CLOCK:
                clock_instance = ptp_instances[index]
                nic_clocks[instance['name']] = clock_instance.as_dict()
                nic_clocks[instance['name']]['interfaces'] = []
            elif (
                ptp_instances[index]["service"]
                == constants.PTP_INSTANCE_TYPE_MONITORING
            ):
                ptp_instances[index][instance["name"]] = instance.as_dict()
                ptp_instances[index][instance["name"]]["interfaces"] = []
                monitoring_instance_configs.append(ptp_instances[index])
            else:
                ptp_instances[index][instance['name']] = instance.as_dict()
                ptp_instances[index][instance['name']]['interfaces'] = []
                ptp_instance_configs.append(ptp_instances[index])
        for index, iface in enumerate(ptp_interfaces):
            ptp_interfaces[index] = iface.as_dict()
        for index, param in enumerate(ptp_parameters_instance):
            ptp_parameters_instance[index] = param.as_dict()
        for index, param in enumerate(ptp_parameters_interface):
            ptp_parameters_interface[index] = param.as_dict()

        # Generate the nic clock config
        if len(nic_clocks) > 0:
            nic_clock_enabled = True
            host_port_list = self.dbapi.port_get_all(hostid=host.id)
            nic_clock_config = self._set_ptp_instance_interfaces(host, nic_clocks, ptp_interfaces)
            nic_clock_config = self._set_ptp_instance_interface_parameters(host, nic_clock_config,
                                                                           ptp_parameters_interface)
            nic_clock_config = self._generate_clock_port_dict(host, nic_clock_config,
                                                              host_port_list)

        # Generate the ptp instance config if ptp is enabled
        if ptpinstance_enabled:
            ptp_config = self._set_ptp_instance_global_parameters(ptp_instance_configs,
                                                                  ptp_parameters_instance)
            ptp_config = self._set_ptp_instance_interfaces(host, ptp_config,
                                                           ptp_interfaces)
            ptp_config = self._set_ptp_instance_interface_parameters(host, ptp_config,
                                                                     ptp_parameters_interface)
        else:
            ptp_config = {}

        # Generate the monitoring config
        monitoring_enabled = False
        monitoring_config = {}
        len_monitoring_instance_configs = len(monitoring_instance_configs)

        if ptpinstance_enabled and len_monitoring_instance_configs > 0:
            # Only single monitoring instance per host is allowed.
            if len_monitoring_instance_configs == 1:
                monitoring_enabled = True
                monitoring_config = self._set_ptp_instance_monitoring_global_parameters(
                    monitoring_instance_configs[0], ptp_parameters_instance
                )
            else:
                LOG.warning(
                    f"PTP monitoring instances are {len_monitoring_instance_configs > 1} on host id {host.id}."
                )

        return {
            'platform::ptpinstance::config': ptp_config,
            'platform::ptpinstance::enabled': ptpinstance_enabled,
            'platform::ptpinstance::monitoring::monitoring_config': monitoring_config,
            'platform::ptpinstance::monitoring::monitoring_enabled': monitoring_enabled,
            'platform::ptpinstance::nic_clock::nic_clock_config': nic_clock_config,
            'platform::ptpinstance::nic_clock::nic_clock_enabled': nic_clock_enabled,
        }

    def _get_interface_config(self, networktype):
        config = {}
        network_interface = interface.find_interface_by_type(
            self.context, networktype)

        if network_interface:
            interface_name = interface.get_interface_os_ifname(
                self.context, network_interface)
            interface_devices = interface.get_interface_devices(
                self.context, network_interface)
            # Convert the dash to underscore because puppet parameters cannot
            # have dashes
            network = self.context['networks'].get(networktype, None)
            networktype = networktype.replace('-', '_')
            config.update({
                'platform::network::%s::params::interface_name' % networktype:
                    interface_name,
                'platform::network::%s::params::interface_devices' % networktype:
                    interface_devices,
                'platform::network::%s::params::mtu' % networktype:
                    network_interface.imtu
            })

            addresses = self.context['addresses'].get(network_interface['ifname'], [])
            for address in addresses:
                family = "ipv4" if address.family == constants.IPV4_FAMILY else "ipv6"
                config.update({
                    f'platform::network::{networktype}::{family}::params::interface_address':
                        address.address
                })

            if network:
                for address in addresses:
                    family = "ipv4" if address.family == constants.IPV4_FAMILY else "ipv6"
                    prim_family = network.primary_pool_family.lower()
                    if prim_family == family:
                        config.update({
                            f'platform::network::{networktype}::params::interface_address':
                                address.address
                        })
                    break

        return config
