#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import copy
import os
import subprocess
import yaml

from oslo_log import log as logging

from sysinv.common import utils as cutils

from sysinv.ipsec_auth.common import constants

LOG = logging.getLogger(__name__)


class StrongswanConf(object):
    """Class to generate strongswan configuration file"""

    def __init__(self):
        self.strongswan = {}
        self.plugins = {}

    def add_strongswan(self, key, value):
        self.strongswan[key] = value

    def add_plugins(self, key, value):
        self.plugins[key] = value

    def get_conf(self):
        self.strongswan['plugins'] = self.plugins
        return self.strongswan


class CharonLoggingConf(object):
    """Class to generate charon-logging configuration file"""

    def __init__(self):
        self.charon_logging = {}
        self.filelog = {}
        self.main_log = {}

    def add_main_log(self, key, value):
        self.main_log[key] = value

    def get_conf(self):
        self.filelog['main_log'] = self.main_log
        self.charon_logging['filelog'] = self.filelog
        return self.charon_logging


class CharonConf(object):
    """Class to generate charon configuration file"""

    def __init__(self):
        self.charon = {}
        self.start_scripts = {}
        self.stop_scripts = {}

    def add_charon(self, key, value):
        self.charon[key] = value

    def add_start_scripts(self, key, value):
        self.start_scripts[key] = value

    def add_stop_scripts(self, key, value):
        self.stop_scripts[key] = value

    def get_conf(self):
        self.charon['start-scripts'] = self.start_scripts
        self.charon['stop-scripts'] = self.stop_scripts
        return self.charon


class SwanctlConf(object):
    """Class to generate swanctl configuration file"""

    def __init__(self):
        self.connections = {}

    def add_connection(self, key, value):
        self.connections[key] = value

    def update_connection(self, key, value):
        if key in self.connections:
            self.connections[key] = value

    def get_conf(self):
        return self.connections


class StrongswanPuppet(object):
    """ Class to encapsulate puppet operations for ipsec configuration. """

    def __init__(self, hostname, personality, local_addrs, network_addrs, unit_ip, floating_ip):
        self.hostname = hostname
        self.personality = personality
        self.local_addrs = local_addrs
        self.network_addrs = network_addrs
        self.unit_ip = unit_ip
        self.floating_ip = floating_ip
        self.path = '/tmp/puppet/hieradata'
        self.filename = 'ipsec.yaml'

    def generate_file(self):
        config = {}
        config.update(self.get_strongswan_config())
        config.update(self.get_charon_logging_config())
        config.update(self.get_charon_config())
        config.update(self.get_swanctl_config())
        self.write_config(config)

    def get_strongswan_config(self):
        strong = StrongswanConf()
        strong.add_strongswan('load_modular', 'yes')
        strong.add_plugins('include', 'strongswan.d/charon/*.conf')

        return {
                'platform::strongswan::params::strongswan': strong.get_conf()
        }

    def get_charon_logging_config(self):
        charon_logging = CharonLoggingConf()

        charon_logging.add_main_log('default', 2)
        charon_logging.add_main_log('net', 1)
        charon_logging.add_main_log('enc', 1)
        charon_logging.add_main_log('asn', 1)
        charon_logging.add_main_log('job', 1)
        charon_logging.add_main_log('ike_name', 'yes')
        charon_logging.add_main_log('append', 'yes')
        charon_logging.add_main_log('flush_line', 'yes')
        charon_logging.add_main_log('path', '/var/log/charon.log')
        charon_logging.add_main_log('time_add_ms', 'yes')
        charon_logging.add_main_log('time_format', '\"%y-%m-%d %H:%M:%S\"')

        return {
                'platform::strongswan::params::charon_logging': charon_logging.get_conf()
        }

    def get_charon_config(self):
        charon = CharonConf()

        charon.add_charon('make_before_break', 'yes')
        charon.add_charon('retransmit_tries', '3')
        charon.add_charon('close_ike_on_child_failure', 'yes')
        charon.add_charon('inactivity_close_ike', 'yes')
        charon.add_charon('check_current_path', 'yes')
        charon.add_start_scripts('load-all', '/usr/sbin/swanctl --load-all')

        stop_scripts = '/usr/sbin/swanctl --terminate --ike ' + constants.IKE_SA_NAME
        charon.add_stop_scripts('stop-all', stop_scripts)

        return {
                'platform::strongswan::params::charon': charon.get_conf()
        }

    def get_swanctl_config(self):
        swanctl = SwanctlConf()

        # remote_addrs for the connection between nodes.
        if cutils.is_valid_ipv6_cidr(self.network_addrs):
            remote_addrs = '%any6'
        else:
            remote_addrs = '%any'
        certs = constants.CERT_NAME_PREFIX + self.hostname + '.crt'

        # Add connection between nodes.
        conn = {
            # connection reauth_time 14400s (4h)
            'reauth_time': '14400',
            # connection rekey_time 3600s (1h)
            'rekey_time': '3600',
            'unique': 'never',
            'mobike': 'no',
            'dpd_delay': '10',
            'dpd_timeout': '10',
            'local_addrs': self.local_addrs,
            'remote_addrs': remote_addrs,

            'local': {
                'auth': 'pubkey',
                'certs': certs,
            },
            'remote': {
                'id': 'CN=*',
                'auth': 'pubkey',
                'cacerts': constants.TRUSTED_CA_CERT_FILES,
            },
            'children': {
                constants.CHILD_SA_NAME: {
                    'mode': 'transport',
                    'start_action': 'trap',
                    'inactivity': '15',
                    'local_ts': self.network_addrs,
                    'remote_ts': self.network_addrs,
                },
            },
        }
        swanctl.add_connection(constants.IKE_SA_NAME, conn)

        # Add local bypass connection to bypass local to local traffic,
        # eg, traffic from unit IP to floating IP on active controller.
        # Without this connection, "system host-list" and such will hang,
        # because it's accessing services on floating IP from unit IP.

        # The local_ts and remote_ts for local bypass connection.
        local_ts = self.unit_ip
        remote_ts = self.unit_ip

        # Add connection for local traffic within a node.
        conn = {
            'children': {
                'node-bypass': {
                    'mode': 'pass',
                    'start_action': 'trap',
                    'local_ts': local_ts,
                    'remote_ts': remote_ts,
                },
            },
        }
        swanctl.add_connection('system-nodes-local', conn)

        # Add connections to bypass some services. These services are already
        # secured.
        conn = {
            'remote_addrs': '127.0.0.1',
            'children': {
                'service-bypass': {
                    'mode': 'pass',
                    'start_action': 'trap',
                    'local_ts': '0.0.0.0/0, ::/0',
                    'remote_ts': ('dynamic[tcp/22],'
                                  'dynamic[tcp/443],'
                                  'dynamic[tcp/8443],'
                                  'dynamic[tcp/9001],'
                                  'dynamic[tcp/9002],'
                                  'dynamic[tcp/6800-6815],'
                                  'dynamic[tcp/6816-6847],'
                                  'dynamic[tcp/6848-6911],'
                                  'dynamic[tcp/6912-7167],'
                                  'dynamic[tcp/7168-7295],'
                                  'dynamic[tcp/7296-7299],'
                                  'dynamic[tcp/7300],'
                                  'dynamic[tcp/7793],'
                                  'dynamic[tcp/7797],'
                                  'dynamic[tcp/7798-7799],'
                                  'dynamic[tcp/7788-7789],'
                                  'dynamic[tcp/7790],'
                                  'dynamic[tcp/7794]'),
                },
            },
        }
        swanctl.add_connection('services-bypass-egress', conn)

        conn = {
            'remote_addrs': '127.0.0.1',
            'children': {
                'service-bypass': {
                    'mode': 'pass',
                    'start_action': 'trap',
                    'local_ts': ('dynamic[tcp/22],'
                                 'dynamic[tcp/443],'
                                 'dynamic[tcp/8443],'
                                 'dynamic[tcp/9001],'
                                 'dynamic[tcp/9002],'
                                 'dynamic[tcp/6800-6815],'
                                 'dynamic[tcp/6816-6847],'
                                 'dynamic[tcp/6848-6911],'
                                 'dynamic[tcp/6912-7167],'
                                 'dynamic[tcp/7168-7295],'
                                 'dynamic[tcp/7296-7299],'
                                 'dynamic[tcp/7300],'
                                 'dynamic[tcp/7793],'
                                 'dynamic[tcp/7797],'
                                 'dynamic[tcp/7798-7799],'
                                 'dynamic[tcp/7788-7789],'
                                 'dynamic[tcp/7790],'
                                 'dynamic[tcp/7794]'),
                    'remote_ts': '0.0.0.0/0, ::/0',
                },
            },
        }
        swanctl.add_connection('services-bypass-ingress', conn)

        # Add ndp bypass connection for IPv6 only.
        # Reference: https://wiki.strongswan.org/projects/strongswan/wiki/IPv6NDP/1
        if cutils.is_valid_ipv6_cidr(self.network_addrs):
            conn = {
                'children': {
                    'icmpv6-bypass': {
                        'mode': 'pass',
                        'start_action': 'trap',
                        'local_ts': '\"::/0[ipv6-icmp]\"',
                        'remote_ts': '\"::/0[ipv6-icmp]\"',
                    },
                },
            }
            swanctl.add_connection('ndp', conn)

        config = {
            'platform::strongswan::params::swanctl':
                swanctl.get_conf(),
        }

        # swanctl configurtion for controller when it is active controller,
        # where only the 'system-nodes-local' connection is different.
        if self.personality == constants.CONTROLLER:
            swanctl_active = copy.deepcopy(swanctl)

            local_ts = self.unit_ip + ", " + self.floating_ip
            remote_ts = self.unit_ip + ", " + self.floating_ip
            conn = {
                'children': {
                    'node-bypass': {
                        'mode': 'pass',
                        'start_action': 'trap',
                        'local_ts': local_ts,
                        'remote_ts': remote_ts,
                    },
                },
            }
            swanctl_active.update_connection('system-nodes-local', conn)

            # Check if this node has the floating IP.
            cmd = 'ip addr | grep ' + self.floating_ip + '/'
            output = subprocess.run(cmd,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    check=False,
                                    shell=True)
            has_floating_ip = True if output.returncode == 0 else False

            config.update({
                'platform::strongswan::params::swanctl_active':
                    swanctl_active.get_conf(),
                'platform::strongswan::params::is_active_controller':
                    has_floating_ip,
            })

        return config

    def write_config(self, config):
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        filepath = os.path.join(self.path, self.filename)
        try:
            with open(filepath, 'w') as f:
                yaml.dump(config, f, sort_keys=False, default_flow_style=False)
        except Exception:
            LOG.exception("Failed to write config file: %s" % filepath)
            raise
