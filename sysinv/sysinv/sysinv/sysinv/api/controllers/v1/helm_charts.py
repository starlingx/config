#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan
from pecan import rest
import yaml

import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv import objects
from sysinv.common import exception
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _


LOG = log.getLogger(__name__)


class HelmChartsController(rest.RestController):

    @wsme_pecan.wsexpose(wtypes.text, wtypes.text)
    def get_all(self, app_name):
        """Provides information about the available charts to override."""

        try:
            namespaces = pecan.request.rpcapi.get_helm_application_namespaces(
                pecan.request.context, app_name)
        except Exception as e:
            raise wsme.exc.ClientSideError(_("Unable to get the helm charts for "
                                             "application %s: %s" % (app_name, str(e))))

        charts = [{'name': chart, 'namespaces': namespaces[chart]}
                  for chart in namespaces]

        return {'charts': charts}

    @wsme_pecan.wsexpose(wtypes.text, wtypes.text, wtypes.text, wtypes.text)
    def get_one(self, app_name, name, namespace):
        """Retrieve information about the given chart.

        :param app_name: name of application
        :param name: name of helm chart
        :param namespace: namespace of chart overrides
        """
        self.validate_name_and_namespace(name, namespace)

        # Get any user-specified overrides.
        try:
            app = objects.kube_app.get_by_name(
                pecan.request.context, app_name)
            db_chart = objects.helm_overrides.get_by_appid_name(
                pecan.request.context, app.id, name, namespace)
            user_overrides = db_chart.user_overrides
        except exception.KubeAppNotFound:
            raise wsme.exc.ClientSideError(_("Application %s not found." % app_name))
        except exception.HelmOverrideNotFound:
            user_overrides = None

        system_apps = pecan.request.rpcapi.get_helm_applications(
                      pecan.request.context)
        if app_name in system_apps:
            # Get any system overrides for system app.
            try:
                system_overrides = pecan.request.rpcapi.get_helm_chart_overrides(
                    pecan.request.context, name, namespace)
                system_overrides = yaml.safe_dump(system_overrides) \
                    if system_overrides else None
            except Exception as e:
                raise wsme.exc.ClientSideError(_("Unable to get the helm chart overrides "
                                                 "for chart %s under Namespace %s: %s"
                                                 % (name, namespace, str(e))))
        else:
            # No system overrides for generic app
            system_overrides = None

        # Merge the system overrides with the saved user-specified overrides,
        # with user-specified overrides taking priority over the system
        # overrides.
        file_overrides = []
        if system_overrides:
            file_overrides.append(system_overrides)
        if user_overrides:
            file_overrides.append(user_overrides)

        combined_overrides = None
        if file_overrides:
            combined_overrides = pecan.request.rpcapi.merge_overrides(
                pecan.request.context, file_overrides=file_overrides)

        rpc_chart = {'name': name,
                     'namespace': namespace,
                     'system_overrides': system_overrides,
                     'user_overrides': user_overrides,
                     'combined_overrides': combined_overrides}

        return rpc_chart

    def validate_name_and_namespace(self, name, namespace):
        if not name:
                raise wsme.exc.ClientSideError(_("Name must be specified."))
        if not namespace:
            raise wsme.exc.ClientSideError(_("Namespace must be specified."))

    @wsme_pecan.wsexpose(wtypes.text, wtypes.text, wtypes.text,
                         wtypes.text, wtypes.text, wtypes.text)
    def patch(self, app_name, name, namespace, flag, values):
        """ Update user overrides.

        :param app_name: name of application
        :param name: chart name
        :param namespace: namespace of chart overrides
        :param flag: one of "reuse" or "reset", describes how to handle
                     previous user overrides
        :param values: a dict of different types of user override values
        """
        self.validate_name_and_namespace(name, namespace)

        file_overrides = values.get('files', [])
        set_overrides = values.get('set', [])

        if set_overrides:
            for overrides in set_overrides:
                if ',' in overrides:
                    raise wsme.exc.ClientSideError(
                        _("Invalid input: One (or more) set overrides contains "
                          "multiple values. Consider using --values option "
                          "instead."))

        # Get any stored user overrides for this chart.  We'll need this
        # object later either way.
        try:
            app = objects.kube_app.get_by_name(
                pecan.request.context, app_name)
            db_chart = objects.helm_overrides.get_by_appid_name(
                pecan.request.context, app.id, name, namespace)
        except exception.KubeAppNotFound:
            raise wsme.exc.ClientSideError(_("Application %s not found." % app_name))
        except exception.HelmOverrideNotFound:
            pecan.request.dbapi.helm_override_create({
                'name': name,
                'namespace': namespace,
                'app_id': app.id})
            db_chart = objects.helm_overrides.get_by_appid_name(
                pecan.request.context, app.id, name, namespace)

        user_overrides = db_chart.user_overrides
        if flag == 'reuse':
            if user_overrides is not None:
                file_overrides.insert(0, user_overrides)
        elif flag == 'reset':
            pass
        else:
            raise wsme.exc.ClientSideError(_("Invalid flag: %s must be either "
                                             "'reuse' or 'reset'.") % flag)

        if file_overrides or set_overrides:
            user_overrides = pecan.request.rpcapi.merge_overrides(
                pecan.request.context, file_overrides=file_overrides,
                set_overrides=set_overrides)

        # save chart overrides back to DB
        db_chart.user_overrides = user_overrides
        db_chart.save()

        chart = {'name': name, 'namespace': namespace,
                 'user_overrides': user_overrides}

        return chart

    @wsme_pecan.wsexpose(None, wtypes.text, wtypes.text,
                         wtypes.text, status_code=204)
    def delete(self, app_name, name, namespace):
        """Delete user overrides for a chart

        :param app_name: name of application
        :param name: chart name.
        :param namespace: namespace of chart overrides
        """
        self.validate_name_and_namespace(name, namespace)
        try:
            app = objects.kube_app.get_by_name(pecan.request.context, app_name)
            pecan.request.dbapi.helm_override_update(app.id, name, namespace,
                                                     {'user_overrides': None})
        except exception.KubeAppNotFound:
            raise wsme.exc.ClientSideError(_("Application %s not found." % app_name))
        except exception.HelmOverrideNotFound:
            pass
