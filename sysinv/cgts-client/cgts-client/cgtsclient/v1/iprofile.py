#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient.common import utils
from cgtsclient import exc


CREATION_ATTRIBUTES = ['profiletype', 'profilename', 'ihost_uuid']


class iprofile(base.Resource):
    def __repr__(self):
        return "<iprofile %s>" % self._info


class iprofileManager(base.Manager):
    resource_class = iprofile

    @staticmethod
    def _path(id=None):
        return '/v1/iprofile/%s' % id if id else '/v1/iprofile'

    def list(self):
        return self._list(self._path(), "iprofiles")

    def list_interface_profiles(self):
        path = "ifprofiles_list"
        profiles = self._list(self._path(path))
        for profile in profiles:
            profile.ports = [utils.objectify(n) for n in profile.ports]
            profile.interfaces = [utils.objectify(n) for n in
                                  profile.interfaces]
        return profiles

    def list_cpu_profiles(self):
        path = "cpuprofiles_list"
        profiles = self._list(self._path(path))
        for profile in profiles:
            profile.cpus = [utils.objectify(n) for n in profile.cpus]
            profile.nodes = [utils.objectify(n) for n in profile.nodes]
        return profiles

    def list_memory_profiles(self):
        path = "memprofiles_list"
        profiles = self._list(self._path(path))
        for profile in profiles:
            profile.memory = [utils.objectify(n) for n in profile.memory]
            profile.nodes = [utils.objectify(n) for n in profile.nodes]
        return profiles

    def list_storage_profiles(self):
        path = "storprofiles_list"
        profiles = self._list(self._path(path))
        for profile in profiles:
            profile.disks = [utils.objectify(n) for n in profile.disks]
            profile.partitions = [utils.objectify(n) for n in
                                  profile.partitions]
            profile.stors = [utils.objectify(n) for n in profile.stors]
            profile.lvgs = [utils.objectify(n) for n in profile.lvgs]
            profile.pvs = [utils.objectify(n) for n in profile.pvs]
        return profiles

    def list_ethernet_port(self, iprofile_id):
        path = "%s/ethernet_ports" % iprofile_id
        return self._list(self._path(path), "ethernet_ports")

    def list_iinterface(self, iprofile_id):
        path = "%s/iinterfaces" % iprofile_id
        return self._list(self._path(path), "iinterfaces")

    def list_icpus(self, iprofile_id):
        path = "%s/icpus" % iprofile_id
        return self._list(self._path(path), "icpus")

    def list_inodes(self, iprofile_id):
        path = "%s/inodes" % iprofile_id
        return self._list(self._path(path), "inodes")

    def list_imemorys(self, iprofile_id):
        path = "%s/imemorys" % iprofile_id
        return self._list(self._path(path), "imemorys")

    def list_idisks(self, iprofile_id):
        path = "%s/idisks" % iprofile_id
        return self._list(self._path(path), "idisks")

    def list_partitions(self, iprofile_id):
        path = "%s/partitions" % iprofile_id
        return self._list(self._path(path), "partitions")

    def list_istors(self, iprofile_id):
        path = "%s/istors" % iprofile_id
        return self._list(self._path(path), "istors")

    def list_ilvgs(self, iprofile_id):
        path = "%s/ilvgs" % iprofile_id
        return self._list(self._path(path), "ilvgs")

    def list_ipvs(self, iprofile_id):
        path = "%s/ipvs" % iprofile_id
        return self._list(self._path(path), "ipvs")

    def get(self, iprofile_id):
        try:
            return self._list(self._path(iprofile_id))[0]
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

    def delete(self, iprofile_id):
        return self._delete(self._path(iprofile_id))

    def update(self, iprofile_id, patch):
        return self._update(self._path(iprofile_id), patch)

    def import_profile(self, file):
        path = self._path("import_profile")
        return self._upload(path, file)


def _find_iprofile(cc, iprofilenameoruuid):
    iprofiles = cc.iprofile.list()
    for ip in iprofiles:
        if ip.hostname == iprofilenameoruuid or ip.uuid == iprofilenameoruuid:
            break
    else:
        raise exc.CommandError('Profile not found: %s' % iprofilenameoruuid)
    return ip
