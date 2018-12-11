#
# Copyright (c) 2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Cluster Services API
"""

import json

import pacemaker as crm
import cluster_services as cluster
import logging

LOG = logging.getLogger(__name__)

CLUSTER_NODE_STATE_ONLINE = "online"
CLUSTER_NODE_STATE_OFFLINE = "offline"


def __set_service_overall_state__(service):
    """ Internal function used to set the overall state of a
        service based on the state of the service instances.
    """

    service.state = cluster.SERVICE_STATE_DISABLED

    for instance in service.instances:
        if instance.activity == cluster.SERVICE_ACTIVITY_ACTIVE:
            service.state = cluster.SERVICE_STATE_ENABLED


def __set_service_instance_state__(instance, resource_name, crm_resource):
    """ Internal function used to set the state of a service
        instance based on a cluster resource manager resource.
    """

    if crm_resource is None:
        if (instance.state != cluster.SERVICE_STATE_DISABLED and
                instance.state != cluster.SERVICE_STATE_FAILED):
            instance.state = cluster.SERVICE_STATE_UNKNOWN
        instance.reason.append("%s is unknown" % resource_name)
        return

    if crm_resource.state == crm.RESOURCE_STATE_UNKNOWN:
        if (instance.state != cluster.SERVICE_STATE_DISABLED and
                instance.state != cluster.SERVICE_STATE_FAILED):
            instance.state = cluster.SERVICE_STATE_UNKNOWN
        instance.reason.append("%s is unknown" % crm_resource.name)

    elif crm_resource.state == crm.RESOURCE_STATE_ENABLED:
        if instance.state == cluster.SERVICE_STATE_NOT_SET:
            instance.state = cluster.SERVICE_STATE_ENABLED
            instance.reason.append("")

    elif crm_resource.state == crm.RESOURCE_STATE_DISABLED:
        if instance.state != cluster.SERVICE_STATE_FAILED:
            instance.state = cluster.SERVICE_STATE_DISABLED
        instance.reason.append("%s is disabled" % crm_resource.name)

    elif crm_resource.state == crm.RESOURCE_STATE_FAILED:
        instance.state = cluster.SERVICE_STATE_FAILED
        instance.reason.append("%s is failed" % crm_resource.name)

    else:
        if (instance.state != cluster.SERVICE_STATE_DISABLED and
                instance.state != cluster.SERVICE_STATE_FAILED):
            instance.state = cluster.SERVICE_STATE_UNKNOWN
        instance.reason.append("%s unknown state" % crm_resource.name)

    # Remove any empty strings from reason if the state is not enabled.
    if instance.state != cluster.SERVICE_STATE_ENABLED:
        instance.reason = [_f for _f in instance.reason if _f]


def __set_service_instance_activity__(instance, crm_resource):
    """ Internal function used to set the activity of a service
        instance based on a cluster resource manager resource.
    """

    if crm_resource is None:
        instance.activity = cluster.SERVICE_ACTIVITY_STANDBY
        return

    if crm_resource.state == crm.RESOURCE_STATE_ENABLED:
        if instance.activity == cluster.SERVICE_ACTIVITY_NOT_SET:
            instance.activity = cluster.SERVICE_ACTIVITY_ACTIVE

    else:
        instance.activity = cluster.SERVICE_ACTIVITY_STANDBY


def _get_cluster_controller_services(host_names):
    """ Internal function used to fetches the state of nodes and
        resources from the cluster resource manager and calculate
        the state of the services making up the cluster.

        returns: services
    """

    services = cluster.ClusterServices()
    manager = crm.Pacemaker()

    services.load(host_names)
    manager.load()

    for service in services.list:
        for instance in service.instances:
            crm_node = manager.get_node(instance.host_name)

            if crm_node is None:
                instance.activity = cluster.SERVICE_ACTIVITY_STANDBY
                instance.state = cluster.SERVICE_STATE_DISABLED
                instance.reason.append("%s is unavailable"
                                       % instance.host_name)
            else:
                if crm_node.state == crm.NODE_STATE_OFFLINE:
                    instance.activity = cluster.SERVICE_ACTIVITY_STANDBY
                    instance.state = cluster.SERVICE_STATE_DISABLED
                    instance.reason.append("%s is offline"
                                           % instance.host_name)

                elif crm_node.state == crm.NODE_STATE_ONLINE:
                    for resource_name in service.activity_follows:
                        crm_resource = manager.get_resource(instance.host_name,
                                                            resource_name)
                        __set_service_instance_activity__(instance,
                                                          crm_resource)

                    for resource_name in service.resources:
                        crm_resource = manager.get_resource(instance.host_name,
                                                            resource_name)
                        __set_service_instance_state__(instance, resource_name,
                                                       crm_resource)

                    if instance.state != cluster.SERVICE_STATE_ENABLED:
                        instance.activity = cluster.SERVICE_ACTIVITY_STANDBY

                    # Remap standby disabled service instance to standby
                    # enabled for now.  Needed to make the presentation
                    # better for cold-standby.
                    if instance.activity == cluster.SERVICE_ACTIVITY_STANDBY:
                        if instance.state == cluster.SERVICE_STATE_DISABLED:
                            instance.state = cluster.SERVICE_STATE_ENABLED

            __set_service_overall_state__(service)

    return services


def get_cluster_controller_services(host_names, print_to_screen=False,
                                    print_json_str=False):
    """ Fetches the state of nodes and resources from the cluster
        resource manager and calculate the state of the services
        making up the cluster.

        returns: json string
    """

    services = _get_cluster_controller_services(host_names)

    # Build Json Data
    services_data = []

    for service in services.list:
        if print_to_screen:
            print(" ")
            print("servicename: %s" % service.name)
            print("status     : %s" % service.state)

        instances_data = []

        for instance in service.instances:
            if print_to_screen:
                print("\thostname: %s" % instance.host_name)
                print("\tactivity: %s" % instance.activity)
                print("\tstate   : %s" % instance.state)
                print("\treason  : %s" % instance.reason)
                print(" ")

            instances_data += ([{'hostname': instance.host_name,
                                 'activity': instance.activity,
                                 'state': instance.state,
                                 'reason': instance.reason}])

        services_data += ([{'servicename': service.name,
                            'state': service.state,
                            'instances': instances_data}])

    if print_json_str:
        print(json.dumps(services_data))

    return json.dumps(services_data)


def cluster_controller_node_exists(host_name):
    """ Cluster node exists.

        returns: True exists, otherwise False
    """

    manager = crm.Pacemaker()
    manager.load()

    crm_node = manager.get_node(host_name)

    return crm_node is not None


def get_cluster_controller_node_state(host_name, print_to_screen=False,
                                      print_json_str=False):
    """ Fetches the state of a cluster node.

        returns: json string
    """

    manager = crm.Pacemaker()
    manager.load()

    crm_node = manager.get_node(host_name)

    if crm_node is None:
        state = "unknown"
    else:
        if crm_node.state == crm.NODE_STATE_OFFLINE:
            state = "offline"
        elif crm_node.state == crm.NODE_STATE_ONLINE:
            state = "online"
        else:
            state = "unknown"

    if print_to_screen:
        print(" ")
        print("%s state is %s" % (host_name, state))

    # Build Json Data
    node_data = ({'hostname': host_name, 'state': state})

    if print_json_str:
        print(json.dumps(node_data))

    return json.dumps(node_data)


def set_cluster_controller_node_state(host_name, state):
    """ Set the state of a cluster node

        returns: True success, otherwise False
    """

    if state == CLUSTER_NODE_STATE_OFFLINE:
        node_state = crm.NODE_STATE_OFFLINE
    elif state == CLUSTER_NODE_STATE_ONLINE:
        node_state = crm.NODE_STATE_ONLINE
    else:
        LOG.warning("Unsupported state (%s) given for %s."
                    % (state, host_name))
        return False

    manager = crm.Pacemaker()

    return manager.set_node_state(host_name, node_state)


def have_active_cluster_controller_services(host_name):
    """ Determine if there are any active services on the given host.

        returns: True success, otherwise False
    """

    services = _get_cluster_controller_services([host_name])
    for service in services.list:
        for instance in service.instances:
            if instance.activity == cluster.SERVICE_ACTIVITY_ACTIVE:
                return True
    return False


def migrate_cluster_controller_services(host_name):
    """ Migrates all services to a particular host.

        returns: True success, otherwise False
    """

    manager = crm.Pacemaker()

    services = _get_cluster_controller_services(host_name)
    for service in services.list:
        for resource_name in service.activity_follows:
            manager.migrate_resource_to_node(resource_name, host_name,
                                             service.migration_timeout)
    return True
