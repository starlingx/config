#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base


class LldpNeighbour(base.Resource):
    def __repr__(self):
        return "<LldpNeighbour %s>" % self._info


class LldpNeighbourManager(base.Manager):
    resource_class = LldpNeighbour

    def list(self, ihost_id):
        path = '/v1/ihosts/%s/lldp_neighbours' % ihost_id
        neighbours = self._list(path, "lldp_neighbours")
        return neighbours

    def list_by_port(self, port_id):
        path = '/v1/ports/%s/lldp_neighbours' % port_id
        return self._list(path, "lldp_neighbours")

    def get(self, uuid):
        path = '/v1/lldp_neighbours/%s' % uuid
        try:
            return self._list(path)[0]
        except IndexError:
            return None
