#
# Copyright (c) 2017-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base


class License(base.Resource):
    def __repr__(self):
        return "<license %s>" % self._info


class LicenseManager(base.Manager):
    @staticmethod
    def _path(id=None):
        return '/v1/license/%s' % id if id else '/v1/license'

    def show(self):
        path = "get_license_file"
        return self._json_get(self._path(path))

    def install_license(self, file):
        path = self._path("install_license")
        return self._upload(path, file)
