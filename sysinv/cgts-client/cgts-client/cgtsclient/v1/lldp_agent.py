#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base


class LldpAgent(base.Resource):
    def __repr__(self):
        return "<LldpAgent %s>" % self._info


class LldpAgentManager(base.Manager):
    resource_class = LldpAgent

    def list(self, ihost_id):
        path = '/v1/ihosts/%s/lldp_agents' % ihost_id
        agents = self._list(path, "lldp_agents")
        return agents

    def get(self, uuid):
        path = '/v1/lldp_agents/%s' % uuid
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def get_by_port(self, port_id):
        path = '/v1/ports/%s/lldp_agents' % port_id
        return self._list(path, "lldp_agents")
