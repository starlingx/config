#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base


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

    def apply(self, app_name):
        """Install/upgrade the specified application.

        :param app_name: name of the application
        """
        return self._update(self._path(app_name) + '?directive=apply',
                            {'values': {}})

    def remove(self, app_name):
        """Uninstall the specified application

        :param name: app_name
        """
        return self._update(self._path(app_name) + '?directive=remove',
                            {'values': {}})

    def delete(self, app_name):
        """Delete application data

        :param name: app_name
        """
        return self._delete(self._path(app_name))
