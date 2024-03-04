#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
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

    def add_charon(self, key, value):
        self.charon[key] = value

    def add_start_scripts(self, key, value):
        self.start_scripts[key] = value

    def get_conf(self):
        self.charon['start-scripts'] = self.start_scripts
        return self.charon


class SwanctlConf(object):
    """Class to generate swanctl configuration file"""

    def __init__(self):
        self.connections = {}

    def add_connection(self, key, value):
        self.connections[key] = value

    def get_conf(self):
        return self.connections


class StrongswanPuppet(object):
    """ Class to encapsulate puppet operations for ipsec configuration. """

    def __init__(self, hostname, local_addrs, network_addrs, unit_ip, floating_ip):
        self.hostname = hostname
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
        charon.add_start_scripts('load-all', '/usr/sbin/swanctl --load-all')

        return {
                'platform::strongswan::params::charon': charon.get_conf()
        }

    def get_swanctl_config(self):
        swanctl = SwanctlConf()

        # Add system-nodes connection, this is the connection between nodes.
        if cutils.is_valid_ipv6_cidr(self.network_addrs):
            remote_addrs = '%any6'
        else:
            remote_addrs = '%any'
        certs = constants.CERT_NAME_PREFIX + self.hostname + '.crt'

        conn = {
            # connection reauth_time 14400s (4h)
            'reauth_time': '14400',
            'rekey_time': '3600',
            'unique': 'never',
            'mobike': 'no',
            'local_addrs': self.local_addrs,
            'remote_addrs': remote_addrs,

            'local': {
                'auth': 'pubkey',
                'certs': certs,
            },
            'remote': {
                'id': 'CN=*',
                'auth': 'pubkey',
                'cacerts': constants.TRUSTED_CA_CERT_FILE,
            },
            'children': {
                constants.CHILD_SA_NAME: {
                    'mode': 'transport',
                    'start_action': 'trap',
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

        # Check if this node has the floating IP
        cmd = 'ip addr | grep ' + self.floating_ip + '/'
        output = subprocess.run(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                check=False,
                                shell=True)
        if output.returncode == 0:
            conn = {
                'children': {
                    'node-bypass': {
                        'mode': 'pass',
                        'start_action': 'trap',
                        'local_ts': self.unit_ip + ", " + self.floating_ip,
                        'remote_ts': self.unit_ip + ", " + self.floating_ip,
                    },
                },
            }
            swanctl.add_connection('system-nodes-local', conn)

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

        return {
                'platform::strongswan::params::swanctl': swanctl.get_conf()
        }

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
