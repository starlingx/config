#!/usr/bin/env python
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import sys
import yaml

from sysinv.common import constants
from sysinv.common import service
from sysinv.db import api

from oslo_config import cfg
from oslo_log import log as logging


# Log and config
LOG = logging.getLogger(__name__)

CONF = cfg.CONF


def create_host_overrides(filename):
    try:
        dbapi = api.get_instance()
        data = {}

        # Get the DNS info
        dns = dbapi.idns_get_one()
        if dns.nameservers:
            dns_list = dns.nameservers.split(',')
            data.update({'dns_servers': dns_list})

        # Get the address pool info
        pools = dbapi.address_pools_get_all()
        for pool in pools:
            subnet = pool.network + '/' + str(pool.prefix)
            range_start = pool.ranges[0][0].encode('utf-8')
            range_end = pool.ranges[0][-1].encode('utf-8')

            if pool.name == 'pxeboot':
                pool_data = {'pxeboot_subnet': subnet,
                             'pxeboot_start_address': range_start,
                             'pxeboot_end_address': range_end,
                             'pxeboot_floating_address': pool.floating_address,
                             'pxeboot_node_0_address': pool.controller0_address,
                             'pxeboot_node_1_address': pool.controller1_address
                             }
                data.update(pool_data)

            elif pool.name == 'management':
                pool_data = {'management_subnet': subnet,
                             'management_start_address': range_start,
                             'management_end_address': range_end,
                             'management_floating_address': pool.floating_address,
                             'management_node_0_address': pool.controller0_address,
                             'management_node_1_address': pool.controller1_address
                             }
                data.update(pool_data)

            elif pool.name == 'multicast-subnet':
                pool_data = {'management_multicast_subnet': subnet,
                             'management_multicast_start_address': range_start,
                             'management_multicast_end_address': range_end
                             }
                data.update(pool_data)

            elif pool.name == 'cluster-host-subnet':
                pool_data = {'cluster_host_subnet': subnet,
                             'cluster_host_start_address': range_start,
                             'cluster_host_end_address': range_end,
                             'cluster_host_floating_address': pool.floating_address,
                             'cluster_host_node_0_address': pool.controller0_address,
                             'cluster_host_node_1_address': pool.controller1_address
                             }
                data.update(pool_data)

            elif pool.name == 'cluster-pod-subnet':
                pool_data = {'cluster_pod_subnet': subnet,
                             'cluster_pod_start_address': range_start,
                             'cluster_pod_end_address': range_end
                             }
                data.update(pool_data)

            elif pool.name == 'cluster-service-subnet':
                pool_data = {'cluster_service_subnet': subnet,
                             'cluster_sevice_start_address': range_start,
                             'cluster_service_end_address': range_end
                             }
                data.update(pool_data)

            elif pool.name == 'oam':
                pool_data = {'external_oam_subnet': subnet,
                             'external_oam_start_address': range_start,
                             'external_oam_end_address': range_end,
                             'external_oam_floating_address': pool.floating_address,
                             'external_oam_gateway_address': pool.gateway_address
                             }
                data.update(pool_data)

                system = dbapi.isystem_get_one()
                if system.system_mode != constants.SYSTEM_MODE_SIMPLEX:
                    pool_data = {'external_oam_node_0_address': pool.controller0_address,
                                 'external_oam_node_1_address': pool.controller1_address,
                                 }
                    data.update(pool_data)

        docker_list = dbapi.service_parameter_get_all(service=constants.SERVICE_TYPE_DOCKER,
                                                      section=constants.SERVICE_PARAM_SECTION_DOCKER_PROXY)
        for docker in docker_list:
            # Get the docker no-proxy info if it exists
            if docker.name == constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY:
                # Remove the open and close parenthesis if address is IPV6
                _value = docker.value.strip("[]")
                no_proxy_list = _value.split(',')
                data.update({'docker_no_proxy': no_proxy_list})

            # Get the docker http_proxy info if it exists
            elif docker.name == constants.SERVICE_PARAM_NAME_DOCKER_HTTP_PROXY:
                data.update({'docker_http_proxy': docker.value})

            # Get the docker https_proxy info if it exists
            elif docker.name == constants.SERVICE_PARAM_NAME_DOCKER_HTTPS_PROXY:
                data.update({'docker_https_proxy': docker.value})

        # Save collected information in file
        with open(filename, 'w') as outfile:
            yaml.safe_dump(data, outfile, default_flow_style=False)
    except Exception as e:
        LOG.error("Error with create_host_overrides: %s", e)
        sys.exit(1)


def add_action_parsers(subparsers):

    parser = subparsers.add_parser('create-host-overrides')
    parser.set_defaults(func=create_host_overrides)
    parser.add_argument('filename', nargs='?')


CONF.register_cli_opt(
    cfg.SubCommandOpt('action',
                      title='actions',
                      help='Perform sysinv operations',
                      handler=add_action_parsers))


def main():
    service.prepare_service(sys.argv)

    if CONF.action.name == 'create-host-overrides':
        if not CONF.action.filename:
            LOG.error("filename is required")
        else:
            CONF.action.func(CONF.action.filename)
    else:
        CONF.action.func()
