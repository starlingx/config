#!/usr/bin/env python
#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import sys
import yaml

from sysinv.common import constants
from sysinv.common import service
from sysinv.conductor import rpcapi as conductor_rpcapi
from sysinv.db import api
from sysinv.openstack.common import context

from oslo_config import cfg
from oslo_log import log as logging


# Log and config
LOG = logging.getLogger(__name__)

CONF = cfg.CONF


def local_registry_list(filename, included_apps, include_all_apps=False):
    """ Save the list of images present in the local registry
    to a file in yaml format.

    :param filename: name of the file to save to.
    :param include_apps: list of applications for which images are saved in yaml format.
    :param include_all_apps: if True then the list of apps images will include all apps
                             regardless of include_apps list.
    """

    ctxt = context.get_admin_context()
    rpcapi = conductor_rpcapi.ConductorAPI(
        topic=conductor_rpcapi.MANAGER_TOPIC)

    # Save local registry images tags
    image_name_tag_list = []
    temp_image_name_list = rpcapi.docker_registry_image_list(ctxt)
    if not temp_image_name_list:
        raise Exception("Image list could not be retrieved "
                        "from local registry")

    for temp_image_name in temp_image_name_list:
        image_name = temp_image_name.get('name', None)
        if image_name:
            temp_image_tags = rpcapi.docker_registry_image_tags(ctxt,
                                                                image_name)

            for image_name_tag in temp_image_tags:
                image_tag = image_name_tag.get('tag', None)
                if image_tag:
                    image_name_tag_list.append("%s:%s" % (image_name, image_tag))

    # Retrieve the images used by apps that should be excluded from yaml file
    excluded_images = []
    if not include_all_apps:
        apps_images = rpcapi.docker_get_apps_images(ctxt).items()
        if not apps_images:
            raise Exception("Apps image list could not be retrieved")
        for app, images in apps_images:
            if included_apps is None or app not in included_apps:
                excluded_images.extend(images)

    # Exclude apps images
    image_name_tag_list = list(set(image_name_tag_list) - set(excluded_images))

    data = {}
    data.update({'images': image_name_tag_list})

    try:
        with open(filename, 'w') as outfile:
            yaml.safe_dump(data, outfile, default_flow_style=False)
    except Exception as e:
        LOG.error("Error with local_registry_list: %s", e)
        sys.exit(1)


def create_host_overrides(filename):
    try:
        dbapi = api.get_instance()
        data = {}

        # Get the distributed cloud role info
        system = dbapi.isystem_get_one()
        if system.distributed_cloud_role:
            data.update({'distributed_cloud_role': system.distributed_cloud_role})
        else:
            data.update({'distributed_cloud_role': 'none'})

        # region_config and region_name are overriden for subclouds
        if (system.distributed_cloud_role and
                system.distributed_cloud_role == constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
            data.update({'region_config': True})
            data.update({'region_name': system.region_name})

        data.update({'system_mode': system.system_mode})
        if system.location:
            data.update({'location': system.location})
        if system.description:
            data.update({'description': system.description})

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

            elif pool.name == 'system-controller-subnet':
                pool_data = {'system_controller_subnet': subnet,
                             'system_controller_floating_address': pool.floating_address,
                             }
                data.update(pool_data)

            elif pool.name == 'system-controller-oam-subnet':
                pool_data = {'system_controller_oam_subnet': subnet,
                             'system_controller_oam_floating_address': pool.floating_address,
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

    parser = subparsers.add_parser('local-registry-list')
    parser.set_defaults(func=local_registry_list)
    parser.add_argument('filename', nargs='?')
    parser.add_argument('--all-apps', action='store_true', default=False)
    parser.add_argument('--apps', nargs='*', required=False, default=None)


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
    elif CONF.action.name == 'local-registry-list':
        if not CONF.action.filename:
            LOG.error("filename is required")
        else:
            CONF.action.func(CONF.action.filename, CONF.action.apps, CONF.action.all_apps)
    else:
        CONF.action.func()
