#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base

CREATION_ATTRIBUTES = ['cert_path', 'public_path', 'tpm_path']


class Certificate(base.Resource):
    def __repr__(self):
        return "<certificate %s>" % self._info


class CertificateManager(base.Manager):
    resource_class = Certificate

    @staticmethod
    def _path(id=None):
        return '/v1/certificate/%s' % id if id else '/v1/certificate'

    def list(self):
        return self._list(self._path(), "certificates")

    def get(self, certificate_id):
        try:
            return self._list(self._path(certificate_id))[0]
        except IndexError:
            return None

    def certificate_install(self, certificate_file, data=None):
        path = self._path("certificate_install")
        return self._upload(path, certificate_file, data=data)

    def certificate_uninstall(self, uuid):
        path = self._path(uuid)
        _, body = self.api.json_request('DELETE', path)
        return body
