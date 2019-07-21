#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base


class Helm(base.Resource):
    def __repr__(self):
        return "<helm %s>" % self._info


class HelmManager(base.Manager):
    resource_class = Helm

    @staticmethod
    def _path(name=''):
        return '/v1/helm_charts/%s' % name

    def list_charts(self, app):
        """Get list of charts

        For each chart it will show any overrides for that chart along
        with the namespace of the overrides.
        """
        return self._list(self._path() + '?app_name=' + app, 'charts')

    def get_overrides(self, app, name, namespace):
        """Get overrides for a given chart.

        :param app_name: name of application
        :param name: name of the chart
        :param namespace: namespace for the chart overrides

        This will return the end-user, system, and combined overrides for the
        specified chart.
        """
        try:
            return self._list(self._path(app) +
                              '?name=' + name +
                              '&namespace=' + namespace)[0]
        except IndexError:
            return None

    def update_overrides(self, app, name, namespace,
                         flag='reset', override_values={}):
        """Update overrides for a given chart.

        :param app_name: name of application
        :param name: name of the chart
        :param namespace: namespace for the chart overrides
        :param flag: 'reuse' or 'reset' to indicate how to handle existing
                     user overrides for this chart
        :param override_values: a dict representing the overrides

        This will return the end-user overrides for the specified chart.
        """
        body = {'flag': flag, 'values': override_values, 'attributes': {}}
        return self._update(self._path(app) +
                            '?name=' + name +
                            '&namespace=' + namespace, body)

    def delete_overrides(self, app, name, namespace):
        """Delete overrides for a given chart.

        :param app_name: name of application
        :param name: name of the chart
        :param namespace: namespace for the chart overrides
        """
        return self._delete(self._path(app) +
                            '?name=' + name +
                            '&namespace=' + namespace)

    def update_chart(self, app, name, namespace, attributes=None):
        """Update non-override attributes for a given chart.

        :param app_name: name of application
        :param name: name of the chart
        :param namespace: namespace for the chart overrides
        :param attributes: dict of chart attributes to be updated

        This will return the updated attributes for the specified chart.
        """
        if not attributes:
            attributes = {}
        body = {'flag': None, 'values': {}, 'attributes': attributes}
        return self._update(self._path(app) +
                            '?name=' + name +
                            '&namespace=' + namespace, body)
