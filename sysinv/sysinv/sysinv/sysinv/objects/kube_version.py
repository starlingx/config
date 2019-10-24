#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log

from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.objects import base
from sysinv.objects import utils

LOG = log.getLogger(__name__)


class KubeVersion(base.SysinvObject):
    # VERSION 1.0: Initial version
    VERSION = '1.0'

    fields = {'version': utils.str_or_none,
              'upgrade_from': utils.list_of_strings_or_none,
              'downgrade_to': utils.list_of_strings_or_none,
              'applied_patches': utils.list_of_strings_or_none,
              'available_patches': utils.list_of_strings_or_none,
              'target': utils.bool_or_none,
              'state': utils.str_or_none,
              }

    @classmethod
    def get_by_version(cls, version):
        for kube_version in kubernetes.get_kube_versions():
            if kube_version['version'] == version:
                version_obj = KubeVersion()
                # Must set created/updated_at as these are defined in the
                # base class.
                version_obj.created_at = None
                version_obj.updated_at = None
                version_obj.version = kube_version['version']
                version_obj.upgrade_from = kube_version['upgrade_from']
                version_obj.downgrade_to = kube_version['downgrade_to']
                version_obj.applied_patches = kube_version['applied_patches']
                version_obj.available_patches = kube_version['available_patches']
                version_obj.target = False
                version_obj.state = 'unknown'
                return version_obj

        raise exception.KubeVersionNotFound(version)

    def can_upgrade_from(self, version):
        return version in self.upgrade_from

    def can_downgrade_to(self, version):
        return version in self.downgrade_to
