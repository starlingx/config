#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import base


class KubeRootCAUpdate(base.Resource):
    def __repr__(self):
        return "<kube_rootca_update %s>" % self._info


class KubeRootCAUpdateManager(base.Manager):
    resource_class = KubeRootCAUpdate

    @staticmethod
    def _path(uuid=None):
        return 'v1/kube_rootca_update/%s' % uuid if uuid else 'v1/kube_rootca_update/'

    def create(self, force):
        """Create a new entry for kubernetes rootca update operation """
        return self._create(self._path() + '?force=' + str(force), {})

    def get(self, uuid=None):
        """Retrieve the details of a given kubernetes rootca update.

        :param uuid: uuid of update
        """

        try:
            return self._list(self._path(uuid))[0]
        except IndexError:
            return None

    def get_list(self, uuid=None):
        """Retrieve the details of a given kubernetes rootca update.

        :param uuid: uuid of update
        """
        try:
            return self._list(self._path(uuid), 'kube_rootca_updates')
        except IndexError:
            return []

    def rootCA_upload(self, pem_content):
        """Retrieve the details of a given kubernetes rootca update.

        :param pem_content: the content of the PEM file to be uploaded
        """

        path = self._path('upload_cert')
        return self._upload(path, pem_content)

    def rootCA_generate(self, expiry_date=None, subject=None):
        """Generate a root CA to be applied during
           kubernetes rootca update procedure.

           :param expiry_date: stores data from CLI arg expiry_date.
           A datetime string in ISO 8601 format (YYYY-MM-DD)
           specifying the expiry date for the certificate to be
           generated.
           :param subject: A string specifying the subject to be set
           for the certificate.
        """

        path = self._path('generate_cert')
        generate_body = {}
        generate_body['expiry_date'] = expiry_date
        generate_body['subject'] = subject
        return self._create(path, generate_body)

    def rootCA_pods_update(self, phase):
        """Kubernetes rootca update for pods.

        :param phase: the phase of the update request.
        """

        post_body = {}
        post_body['phase'] = phase
        resp, body = self.api.json_request('POST', self._path() + "pods",
                                           body=post_body)
        return self.resource_class(self, body)

    def host_update_list(self):
        """Retrieves Kubernetes root CA update status by hosts"""

        return self._list(self._path('hosts'), 'kube_host_updates')

    def update_complete(self, patch, force):
        """Marks the Kubernetes rootca update as complete

        :param patch: a json PATCH document to apply on complete API.
        :param force: A CLI argument to indicate if the API should ignore
        minor alarms on eventual health checks.
        """

        return self._update(self._path() + '?force=' + str(force), patch)
