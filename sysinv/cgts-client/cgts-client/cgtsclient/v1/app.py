#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


class App(base.Resource):
    def __repr__(self):
        return "<app %s>" % self._info


class AppManager(base.Manager):
    resource_class = App

    @staticmethod
    def _path(name=None):
        return '/v1/apps/%s' % name if name else '/v1/apps'

    def list(self):
        """Retrieve the list of containerized apps known to the system."""

        return self._list(self._path(), 'apps')

    def get(self, app_name):
        """Retrieve the details of a given app

        :param name: name of the application
        """
        try:
            return self._list(self._path(app_name))[0]
        except IndexError:
            return None

    def upload(self, data):
        """Stage the specified application, getting it ready for deployment.

        :param data: application name and location of tarfile
        """
        return self._create(self._path(), data)

    def apply(self, app_name, data):
        """Install/upgrade the specified application.

        :param app_name: name of the application
        :param data: extra arguments
        """
        return self._update(self._path(app_name) + '?directive=apply',
                            {'values': data})

    def update(self, data):
        """Upgrade/rollback the deployed application to a different version.

        :param data: location of tarfile, optional application name and version
        """
        resp, body = self.api.json_request('POST', self._path() + "/update", body=data)
        return self.resource_class(self, body)

    def remove(self, app_name):
        """Uninstall the specified application

        :param name: app_name
        """
        return self._update(self._path(app_name) + '?directive=remove',
                            {'values': {}})

    def abort(self, app_name):
        """Abort the operation that is still in progress for the specified application

        :param name: app_name
        """
        return self._update(self._path(app_name) + '?directive=abort',
                            {'values': {}})

    def delete(self, app_name):
        """Delete application data

        :param name: app_name
        """
        return self._delete(self._path(app_name))


def _find_app(cc, app_name):
    try:
        app = cc.app.get(app_name)
    except exc.HTTPNotFound:
        raise exc.CommandError('Application not found: %s' % app_name)
    else:
        return app
