#
# Copyright (c) 2017-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import netaddr

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils

from sysinv.puppet import base
from sysinv.puppet import interface


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

        try:
            gateway_address = self._get_address_by_name(
                constants.CONTROLLER_GATEWAY, networktype).address
        except exception.AddressNotFoundByName:
            gateway_address = None

        config.update({
            'platform::network::%s::params::gateway_address' % networktype:
                gateway_address,
        })

        return config

    def _get_cluster_network_config(self):
        networktype = constants.NETWORK_TYPE_CLUSTER_HOST
        config = self._get_network_config(networktype)
        return config

    def _get_oam_network_config(self):
        networktype = constants.NETWORK_TYPE_OAM

        config = self._get_network_config(networktype)

        try:
            gateway_address = self._get_address_by_name(
                constants.CONTROLLER_GATEWAY, networktype).address
        except exception.AddressNotFoundByName:
            gateway_address = None

        config.update({
            'platform::network::%s::params::gateway_address' % networktype:
                gateway_address,
        })

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
            # network not configured
            return {}

        address_pool = self.dbapi.address_pool_get(network.pool_uuid)

        subnet = netaddr.IPNetwork(
            str(address_pool.network) + '/' + str(address_pool.prefix))

        subnet_version = address_pool.family
        subnet_network = str(subnet.network)
        subnet_netmask = str(subnet.netmask)
        subnet_prefixlen = subnet.prefixlen

        subnet_start = str(address_pool.ranges[0][0])
        subnet_end = str(address_pool.ranges[0][-1])

        try:
            controller_address = self._get_address_by_name(
                constants.CONTROLLER_HOSTNAME, networktype).address
        except exception.AddressNotFoundByName:
            controller_address = None

        try:
            controller0_address = self._get_address_by_name(
                constants.CONTROLLER_0_HOSTNAME, networktype).address
        except exception.AddressNotFoundByName:
            controller0_address = None

        try:
            controller1_address = self._get_address_by_name(
                constants.CONTROLLER_1_HOSTNAME, networktype).address
        except exception.AddressNotFoundByName:
            controller1_address = None

        controller_address_url = self._format_url_address(controller_address)
        subnet_network_url = self._format_url_address(subnet_network)

        # Convert the dash to underscore because puppet parameters cannot have
        # dashes
        networktype = networktype.replace('-', '_')

        return {
            'platform::network::%s::params::subnet_version' % networktype:
                subnet_version,
            'platform::network::%s::params::subnet_network' % networktype:
                subnet_network,
            'platform::network::%s::params::subnet_network_url' % networktype:
                subnet_network_url,
            'platform::network::%s::params::subnet_prefixlen' % networktype:
                subnet_prefixlen,
            'platform::network::%s::params::subnet_netmask' % networktype:
                subnet_netmask,
            'platform::network::%s::params::subnet_start' % networktype:
                subnet_start,
            'platform::network::%s::params::subnet_end' % networktype:
                subnet_end,
            'platform::network::%s::params::controller_address' % networktype:
                controller_address,
            'platform::network::%s::params::controller_address_url' % networktype:
                controller_address_url,
            'platform::network::%s::params::controller0_address' % networktype:
                controller0_address,
            'platform::network::%s::params::controller1_address' % networktype:
                controller1_address,
        }

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
            'external_input_QL': constants.PTP_SYNCE_EXTERNAL_INPUT_QL,
            'external_input_ext_QL': constants.PTP_SYNCE_EXTERNAL_INPUT_EXT_QL,
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
                                   'cmdline_opts', 'id', 'pmc_gm_settings', 'device_parameters']
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
                    'message_tag': instance['name']
                })
                instance['device_parameters'].update(default_device_parameters)

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
                    instance['cmdline_opts'] = instance['global_parameters'].pop('cmdline_opts')
                # Add pmc parameters so that currentUtcOffsetValid can be set by puppet
                if 'currentUtcOffsetValid' in instance['global_parameters']:
                    offset_valid = instance['global_parameters'].pop('currentUtcOffsetValid')
                    if (offset_valid == constants.PTP_PMC_CURRENT_UTC_OFFSET_VALID and
                    instance['service'] == 'ptp4l'):
                        instance['pmc_gm_settings'].update(default_pmc_parameters)

            if instance['service'] == constants.PTP_INSTANCE_TYPE_PTP4L:
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

    def _set_ptp_instance_interface_parameters(self, ptp_instances, ptp_parameters_interface):

        default_interface_parameters = {
            'ptp4l': {},
            'phc2sys': {},
            'ts2phc': {
                'ts2phc.extts_polarity': 'rising'
            },
            'clock': {},
            'synce4l': {
                'tx_heartbeat_msec': constants.PTP_SYNCE_TX_HEARTBEAT_MSEC,
                'rx_heartbeat_msec': constants.PTP_SYNCE_RX_HEARTBEAT_MSEC,
            },
        }

        for instance in ptp_instances:
            for iface in ptp_instances[instance]['interfaces']:
                # Add default interface values
                iface['parameters'].update(default_interface_parameters
                                          [ptp_instances[instance]['service']])
                # Add supplied params to the interface
                for param in ptp_parameters_interface:
                    if iface['uuid'] in param['owners']:
                        iface['parameters'][param['name']] = param['value']

        return ptp_instances

    def _generate_clock_port_dict(self, nic_clock_config, host_port_list):
        port_dict = {}
        for instance in nic_clock_config:
            for iface in nic_clock_config[instance]['interfaces']:
                # Rebuild list by port_names rather than interface names
                for port in iface['port_names']:
                    port_dict[port] = iface
                    port_dict[port]['base_port'] = ""
                # Get port 0 for the configured NIC
                for p in host_port_list:
                    if port_dict.get(p['name'], None):
                        port_dict_name = p['name']
                        # Take the PCI address of the supplied port and replace the end
                        # value with 0 to identify the base port on that nic
                        port_pci_base = p['pciaddr'].split('.')[0] + ".0"
                        # Find the port that has the matching pci address and take this
                        # as the base port
                        for q in host_port_list:
                            if q['pciaddr'] == port_pci_base:
                                port_dict[port_dict_name]['base_port'] = q['name']
                                break
        return port_dict

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

        for index, instance in enumerate(ptp_instances):
            if ptp_instances[index]['service'] == constants.PTP_INSTANCE_TYPE_CLOCK:
                clock_instance = ptp_instances[index]
                nic_clocks[instance['name']] = clock_instance.as_dict()
                nic_clocks[instance['name']]['interfaces'] = []
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
            nic_clock_config = self._set_ptp_instance_interface_parameters(nic_clock_config,
                                                                           ptp_parameters_interface)
            nic_clock_config = self._generate_clock_port_dict(nic_clock_config, host_port_list)

        # Generate the ptp instance config if ptp is enabled
        if ptpinstance_enabled:
            ptp_config = self._set_ptp_instance_global_parameters(ptp_instance_configs,
                                                                  ptp_parameters_instance)
            ptp_config = self._set_ptp_instance_interfaces(host, ptp_config,
                                                           ptp_interfaces)
            ptp_config = self._set_ptp_instance_interface_parameters(ptp_config,
                                                                     ptp_parameters_interface)
        else:
            ptp_config = {}

        return {'platform::ptpinstance::config': ptp_config,
                'platform::ptpinstance::enabled': ptpinstance_enabled,
                'platform::ptpinstance::nic_clock::nic_clock_config': nic_clock_config,
                'platform::ptpinstance::nic_clock::nic_clock_enabled': nic_clock_enabled}

    def _get_interface_config(self, networktype):
        config = {}

        network_interface = interface.find_interface_by_type(
            self.context, networktype)

        if network_interface:
            interface_name = interface.get_interface_os_ifname(
                self.context, network_interface)
            interface_devices = interface.get_interface_devices(
                self.context, network_interface)
            network_id = interface.find_network_id_by_networktype(
                self.context, networktype)
            # Convert the dash to underscore because puppet parameters cannot
            # have dashes
            networktype = networktype.replace('-', '_')
            config.update({
                'platform::network::%s::params::interface_name' % networktype:
                    interface_name,
                'platform::network::%s::params::interface_devices' % networktype:
                    interface_devices,
                'platform::network::%s::params::mtu' % networktype:
                    network_interface.imtu
            })

            interface_address = interface.get_interface_primary_address(
                self.context, network_interface, network_id)
            if interface_address:
                config.update({
                    'platform::network::%s::params::interface_address' %
                    networktype:
                        interface_address['address']
                })

        return config
