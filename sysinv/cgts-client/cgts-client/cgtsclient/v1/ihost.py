#
# Copyright (c) 2013-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import icpu


CREATION_ATTRIBUTES = ['hostname', 'personality', 'subfunctions',
                       'mgmt_mac', 'mgmt_ip',
                       'bm_ip', 'bm_type', 'bm_username',
                       'bm_password', 'serialid', 'location',
                       'boot_device', 'rootfs_device', 'install_output',
                       'console', 'tboot', 'vsc_controllers', 'ttys_dcd',
                       'administrative', 'operational', 'availability',
                       'invprovision', 'clock_synchronization']


class ihost(base.Resource):
    def __repr__(self):
        return "<ihost %s>" % self._info


class ihostManager(base.Manager):
    resource_class = ihost

    @staticmethod
    def _path(id=None):
        return '/v1/ihosts/%s' % id if id else '/v1/ihosts'

    def list(self):
        return self._list(self._path(), "ihosts")

    def list_profiles(self):
        path = "/v1/ihosts/personality_profile"
        return self._list(self._path(path), "ihosts")

    def list_port(self, ihost_id):
        path = "%s/ports" % ihost_id
        return self._list(self._path(path), "ports")

    def list_ethernet_port(self, ihost_id):
        path = "%s/ethernet_ports" % ihost_id
        return self._list(self._path(path), "ethernet_ports")

    def list_iinterface(self, ihost_id):
        path = "%s/iinterfaces" % ihost_id
        return self._list(self._path(path), "iinterfaces")

    def list_personality(self, personality):
        path = self._path() + "?personality=%s" % personality
        return self._list(path, "ihosts")

    def get(self, ihost_id):
        try:
            return self._list(self._path(ihost_id))[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute()
        return self._create(self._path(), new)

    def upgrade(self, hostid, force):
        new = {}
        new['force'] = force
        resp, body = self.api.json_request(
            'POST', self._path(hostid) + "/upgrade", body=new)
        return self.resource_class(self, body)

    def downgrade(self, hostid, force):
        new = {}
        new['force'] = force
        resp, body = self.api.json_request(
            'POST', self._path(hostid) + "/downgrade", body=new)
        return self.resource_class(self, body)

    def create_many(self, body):
        return self._upload(self._path() + "/bulk_add", body)

    def host_cpus_modify(self, hostid, patch):
        path = self._path(hostid) + "/state/host_cpus_modify"

        resp, body = self.api.json_request(
            'PUT', path, body=patch)
        self.resource_class = icpu.icpu
        obj_class = self.resource_class

        try:
            data = body["icpus"]
        except KeyError:
            return []

        if not isinstance(data, list):
            data = [data]
        return [obj_class(self, res, loaded=True) for res in data if res]

    def update_install_uuid(self, hostid, install_uuid):
        path = self._path(hostid) + "/state/update_install_uuid"

        self.api.json_request('PUT', path, body=install_uuid)

    def delete(self, ihost_id):
        return self._delete(self._path(ihost_id))

    def update(self, ihost_id, patch):
        return self._update(self._path(ihost_id), patch)

    def bulk_export(self):
        result = self._json_get(self._path('bulk_export'))
        return result

    def kube_upgrade_control_plane(self, hostid, force):
        post_body = {}
        post_body['force'] = force
        resp, body = self.api.json_request(
            'POST', self._path(hostid) + "/kube_upgrade_control_plane",
            body=post_body)
        return self.resource_class(self, body)

    def kube_upgrade_kubelet(self, hostid, force):
        post_body = {}
        post_body['force'] = force
        resp, body = self.api.json_request(
            'POST', self._path(hostid) + "/kube_upgrade_kubelet",
            body=post_body)
        return self.resource_class(self, body)


def _find_ihost(cc, ihost):
    if ihost.isdigit() or utils.is_uuid_like(ihost):
        try:
            h = cc.ihost.get(ihost)
        except exc.HTTPNotFound:
            raise exc.CommandError('host not found: %s' % ihost)
        else:
            return h
    else:
        hostlist = cc.ihost.list()
        for h in hostlist:
            if h.hostname == ihost:
                return h
        else:
            raise exc.CommandError('host not found: %s' % ihost)
