#
# Copyright (c) 2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Cluster Services
"""

import sys
import cluster_xml as xml
import logging

from lxml import etree

LOG = logging.getLogger(__name__)

SERVICE_ACTIVITY_NOT_SET = ''
SERVICE_ACTIVITY_UNKNOWN = 'unknown'
SERVICE_ACTIVITY_ACTIVE = 'active'
SERVICE_ACTIVITY_STANDBY = 'standby'

SERVICE_STATE_NOT_SET = ''
SERVICE_STATE_UNKNOWN = 'unknown'
SERVICE_STATE_ENABLED = 'enabled'
SERVICE_STATE_DISABLED = 'disabled'
SERVICE_STATE_FAILED = 'failed'


class ClusterServiceInstance(object):
    """ Cluster Service Instance information about the service running
        on a particular host in the cluster (state and activity)
    """

    def __init__(self, name, host_name):
        self.name = name
        self.host_name = host_name
        self.activity = SERVICE_ACTIVITY_NOT_SET
        self.state = SERVICE_STATE_NOT_SET
        self.reason = []


class ClusterService(object):
    """ Cluster Service contains information about the service running
        in the cluster (overall service state and service instances state)
    """

    def __init__(self, service_name):
        self.name = service_name
        self.state = SERVICE_STATE_NOT_SET
        self.instances = []
        self.activity_follows = []
        self.resources = []
        self.migration_timeout = 0


class ClusterServices(object):
    """ Cluster Services holds a listing of all services running
        in the cluster
    """

    def __init__(self):
        self.list = []
        self.__cluster_data = ""
        self.__loaded = False

    def load(self, host_names):
        """ Load services
        """

        if self.__loaded:
            if self.__cluster_data == xml.CLUSTER_DATA:
                return

        self.__cluster_data = ""
        self.__loaded = False
        self.list[:] = []

        try:
            xmlroot = etree.fromstring(xml.CLUSTER_DATA)

            if not etree.iselement(xmlroot):
                return

            if len(xmlroot) == 0:
                return

            xmlservices = xmlroot.find(".//services")
            if not etree.iselement(xmlservices):
                return

            for xmlservice in xmlservices.iterchildren():

                service = ClusterService(xmlservice.attrib["id"])

                # Hosts that the service runs on
                for host_name in host_names:
                    instance = ClusterServiceInstance(xmlservice.attrib["id"],
                                                      host_name)
                    service.instances.append(instance)

                # Get migration attributes of a service
                xmlmigration = xmlroot.find(".//services/service[@id='%s']/"
                                            "migration"
                                            % xmlservice.attrib["id"])
                if not etree.iselement(xmlmigration):
                    return

                service.migration_timeout = xmlmigration.attrib["timeout"]

                # Get resources that determine activity of service
                xmlactivity = xmlroot.find(".//services/service[@id='%s']/"
                                           "activity"
                                           % xmlservice.attrib["id"])
                if not etree.iselement(xmlactivity):
                    return

                for xmlresource in xmlactivity.iterchildren():
                    service.activity_follows.append(xmlresource.attrib["id"])

                # Get resources that make up service
                xmlresources = xmlroot.find(".//services/service[@id='%s']/"
                                            "resources"
                                            % xmlservice.attrib["id"])
                if not etree.iselement(xmlresources):
                    return

                for xmlresource in xmlresources.iterchildren():
                    service.resources.append(xmlresource.attrib["id"])

                self.list.append(service)

            self.__cluster_data = xml.CLUSTER_DATA
            self.__loaded = True

        except Exception:
            LOG.error("error:", sys.exc_info()[0])
