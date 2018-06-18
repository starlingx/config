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

    def list_charts(self):
        return self._list(self._path(), 'charts')

    def get_overrides(self, name):
        """Get overrides for a given chart.

        :param name: name of the chart

        This will return the end-user, system, and combined overrides for the
        specified chart.
        """
        try:
            return self._list(self._path(name))[0]
        except IndexError:
            return None

    def update_overrides(self, name, flag='reset', override_values={}):
        """Update overrides for a given chart.

        :param name: name of the chart
        :param flag: 'reuse' or 'reset' to indicate how to handle existing
                     user overrides for this chart
        :param override_values: a dict representing the overrides

        This will return the end-user overrides for the specified chart.
        """
        body = {'flag': flag, 'values': override_values}
        return self._update(self._path(name), body)

    def delete_overrides(self, name):
        """Delete overrides for a given chart.

        :param name: name of the chart
        """
        return self._delete(self._path(name))
