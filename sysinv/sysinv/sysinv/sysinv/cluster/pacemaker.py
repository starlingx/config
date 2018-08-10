#
# Copyright (c) 2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
PaceMaker
"""

import os
import sys
import uuid
import logging
from lxml import etree

LOG = logging.getLogger(__name__)

NODE_STATE_NOT_SET = ''
NODE_STATE_OFFLINE = 'offline'
NODE_STATE_ONLINE = 'online'

RESOURCE_STATE_NOT_SET = ''
RESOURCE_STATE_UNKNOWN = 'unknown'
RESOURCE_STATE_ENABLED = 'enabled'
RESOURCE_STATE_DISABLED = 'disabled'
RESOURCE_STATE_FAILED = 'failed'


class PaceMakerNode(object):
    """ Pacemaker Node information about a node making up the cluster
    """

    def __init__(self, node_name):
        self.name = node_name
        self.state = NODE_STATE_NOT_SET


class PaceMakerResource(object):
    """ Pacemaker Resource information on a resource running on a node
        in the cluster
    """

    def __init__(self, node_name, resource_name):
        self.name = resource_name
        self.node_name = node_name
        self.last_operation = ""
        self.state = RESOURCE_STATE_NOT_SET


class Pacemaker(object):
    """ Pacemaker
    """

    def __init__(self):
        self._xmldoc = None

    def load(self):
        """ Ask for the latest information on the cluster
        """

        pacemaker_xml_filename = ('/tmp/pacemaker_%s.xml'
                                  % str(uuid.uuid4()))

        try:
            if not os.path.exists('/usr/sbin/cibadmin'):
                return

            os.system("/usr/sbin/cibadmin --query > %s"
                      % pacemaker_xml_filename)

            if not os.path.exists(pacemaker_xml_filename):
                return

            self._xmldoc = etree.parse(pacemaker_xml_filename)
            if self._xmldoc is None:
                os.remove(pacemaker_xml_filename)
                return

            if not etree.iselement(self._xmldoc.getroot()):
                self._xmldoc = None
                os.remove(pacemaker_xml_filename)
                return

            if len(self._xmldoc.getroot()) == 0:
                self._xmldoc = None
                os.remove(pacemaker_xml_filename)
                return

            os.remove(pacemaker_xml_filename)

        except Exception:
            if os.path.exists(pacemaker_xml_filename):
                os.remove(pacemaker_xml_filename)

            LOG.error("error:", sys.exc_info()[0])

    def get_resource(self, node_name, resource_name):
        """ Get a resource's information and state
        """

        if self._xmldoc is None:
            return None

        xmlroot = self._xmldoc.getroot()

        xmlresource = xmlroot.find(".//status/node_state[@id='%s']/"
                                   "lrm[@id='%s']/lrm_resources/"
                                   "lrm_resource[@id='%s']/lrm_rsc_op"
                                   % (node_name, node_name, resource_name))
        if not etree.iselement(xmlresource):
            return None

        resource = PaceMakerResource(node_name, resource_name)

        resource.last_operation = xmlresource.attrib["operation"]

        if (xmlresource.attrib["operation"] == "start" or
                xmlresource.attrib["operation"] == "promote"):
            if xmlresource.attrib["rc-code"] == "0":
                resource.state = RESOURCE_STATE_ENABLED
            else:
                resource.state = RESOURCE_STATE_FAILED

        elif (xmlresource.attrib["operation"] == "stop" or
              xmlresource.attrib["operation"] == "demote"):
            if xmlresource.attrib["rc-code"] == "0":
                resource.state = RESOURCE_STATE_DISABLED
            else:
                resource.state = RESOURCE_STATE_FAILED

        elif xmlresource.attrib["operation"] == "monitor":
            if xmlresource.attrib["rc-code"] == "0":
                resource.state = RESOURCE_STATE_ENABLED
            elif xmlresource.attrib["rc-code"] == "7":
                resource.state = RESOURCE_STATE_DISABLED
            else:
                resource.state = RESOURCE_STATE_FAILED
        else:
            resource.state = RESOURCE_STATE_UNKNOWN

        return resource

    def get_node(self, node_name):
        """ Get a node's information and state
        """

        if self._xmldoc is None:
            return None

        node = PaceMakerNode(node_name)

        xmlroot = self._xmldoc.getroot()

        # Check the static configuration for state.
        xmlnode = xmlroot.find((".//nodes/node[@id='%s']"
                                "/instance_attributes[@id='nodes-%s']"
                                "/nvpair[@id='nodes-%s-standby']"
                                % (node_name, node_name, node_name)))
        if etree.iselement(xmlnode):
            if xmlnode.attrib["name"] == "standby":
                if xmlnode.attrib["value"] == "on":
                    node.state = NODE_STATE_OFFLINE
                    return node

        # Now check the running status for state.
        xmlnode = xmlroot.find(".//status/node_state[@id='%s']"
                               % node_name)
        if not etree.iselement(xmlnode):
            return None

        if xmlnode.attrib["in_ccm"] == "true":
            if xmlnode.attrib["crmd"] == "online":
                node.state = NODE_STATE_ONLINE
            else:
                node.state = NODE_STATE_OFFLINE
        else:
            node.state = NODE_STATE_OFFLINE

        return node

    def set_node_state(self, node_name, node_state):
        """ Set the state of a node in the cluster
        """

        try:
            if not os.path.exists('/usr/sbin/crm'):
                return False

            if node_state == NODE_STATE_OFFLINE:
                action = "standby"
            elif node_state == NODE_STATE_ONLINE:
                action = "online"
            else:
                LOG.warning("Unsupported state (%s) requested for %s."
                            % (node_state, node_name))
                return False

            os.system("/usr/sbin/crm node %s %s" % (action, node_name))
            return True

        except Exception:
            LOG.error("error:", sys.exc_info()[0])
            return False

    def migrate_resource_to_node(self, resource_name, node_name, lifetime):
        """ Migrate resource to a node in the cluster.
        """

        try:
            if not os.path.exists('/usr/sbin/crm'):
                return False

            # Lifetime follows the duration format specified in ISO_8601
            os.system("/usr/sbin/crm resource migrate %s %s P%sS"
                      % (resource_name, node_name, lifetime))
            return True

        except Exception:
            os.system("/usr/sbin/crm resource unmigrate %s" % resource_name)
            LOG.error("error:", sys.exc_info()[0])
            return False
