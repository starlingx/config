#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base


class Port(base.Resource):
    def __repr__(self):
        return "<Port %s>" % self._info


class PortManager(base.Manager):
    resource_class = Port

    def list(self, ihost_id):
        path = '/v1/ihosts/%s/ports' % ihost_id
        return self._list(path, "ports")

    def get(self, port_id):
        path = '/v1/ports/%s' % port_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None


def get_port_display_name(p):
    if p.name:
        return p.name
    if p.namedisplay:
        return p.namedisplay
    else:
        return '(' + str(p.uuid)[-8:] + ')'
