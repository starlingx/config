#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import pecan
from pecan import rest
import subprocess
import tempfile
import yaml

import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv import objects
from sysinv.common import constants
from sysinv.common import exception
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _


LOG = log.getLogger(__name__)

SYSTEM_CHARTS = ['mariadb', 'rabbitmq', 'ingress']


class HelmChartsController(rest.RestController):

    def merge_overrides(self, file_overrides=[], set_overrides=[]):
        """ Merge helm overrides together.

        :param values: A dict of different types of user override values,
                       'files' (which generally specify many overrides) and
                       'set' (which generally specify one override).
        """

        # At this point we have potentially two separate types of overrides
        # specified by system or user, values from files and values passed in
        # via --set .  We need to ensure that we call helm using the same
        # mechanisms to ensure the same behaviour.
        cmd = ['helm', 'install', '--dry-run', '--debug']

        # Process the newly-passed-in override values
        tmpfiles = []
        for value_file in file_overrides:
            # For values passed in from files, write them back out to
            # temporary files.
            tmpfile = tempfile.NamedTemporaryFile(delete=False)
            tmpfile.write(value_file)
            tmpfile.close()
            tmpfiles.append(tmpfile.name)
            cmd.extend(['--values', tmpfile.name])

        for value_set in set_overrides:
            cmd.extend(['--set', value_set])

        env = os.environ.copy()
        env['KUBECONFIG'] = '/etc/kubernetes/admin.conf'

        # Make a temporary directory with a fake chart in it
        try:
            tmpdir = tempfile.mkdtemp()
            chartfile = tmpdir + '/Chart.yaml'
            with open(chartfile, 'w') as tmpchart:
                tmpchart.write('name: mychart\napiVersion: v1\n'
                               'version: 0.1.0\n')
            cmd.append(tmpdir)

            # Apply changes by calling out to helm to do values merge
            # using a dummy chart.
            # NOTE: this requires running sysinv-api as root, will fix it
            # to use RPC in a followup patch.
            output = subprocess.check_output(cmd, env=env)

            # Check output for failure

            # Extract the info we want.
            values = output.split('USER-SUPPLIED VALUES:\n')[1].split(
                                  '\nCOMPUTED VALUES:')[0]
        except Exception:
            raise
        finally:
            os.remove(chartfile)
            os.rmdir(tmpdir)

        for tmpfile in tmpfiles:
            os.remove(tmpfile)

        return values

    @wsme_pecan.wsexpose(wtypes.text)
    def get_all(self):
        """Provides information about the available charts to override."""

        namespaces = pecan.request.rpcapi.get_helm_application_namespaces(
            pecan.request.context, constants.HELM_APP_OPENSTACK)
        charts = [{'name': chart, 'namespaces': namespaces[chart]}
                  for chart in namespaces]

        return {'charts': charts}

    @wsme_pecan.wsexpose(wtypes.text, wtypes.text, wtypes.text)
    def get_one(self, name, namespace):
        """Retrieve information about the given event_log.

        :param name: name of helm chart
        :param namespace: namespace of chart overrides
        """

        # Get any user-specified overrides.
        try:
            db_chart = objects.helm_overrides.get_by_name(
                pecan.request.context, name, namespace)
            user_overrides = db_chart.user_overrides
        except exception.HelmOverrideNotFound:
            if name in constants.SUPPORTED_HELM_CHARTS:
                user_overrides = ''
            else:
                raise

        # Get any system overrides.
        try:
            system_overrides = pecan.request.rpcapi.get_helm_chart_overrides(
                pecan.request.context, name, namespace)
            system_overrides = yaml.safe_dump(system_overrides)
        except (exception.InvalidHelmChart, exception.InvalidHelmNamespace):
            raise

        # Merge the system overrides with the saved user-specified overrides,
        # with user-specified overrides taking priority over the system
        # overrides.
        file_overrides = [system_overrides, user_overrides]
        combined_overrides = self.merge_overrides(
            file_overrides=file_overrides)

        rpc_chart = {'name': name,
                     'namespace': namespace,
                     'system_overrides': system_overrides,
                     'user_overrides': user_overrides,
                     'combined_overrides': combined_overrides}

        return rpc_chart

    def validate_name_and_namespace(self, name, namespace):
        if not name:
                raise wsme.exc.ClientSideError(_(
                    "Helm-override-update rejected: name must be specified"))
        if not namespace:
            raise wsme.exc.ClientSideError(_(
                "Helm-override-update rejected: namespace must be specified"))

    @wsme_pecan.wsexpose(wtypes.text, wtypes.text, wtypes.text, wtypes.text, wtypes.text)
    def patch(self, name, namespace, flag, values):
        """ Update user overrides.

        :param name: chart name
        :param namespace: namespace of chart overrides
        :param flag: one of "reuse" or "reset", describes how to handle
                     previous user overrides
        :param values: a dict of different types of user override values
        """
        self.validate_name_and_namespace(name, namespace)

        file_overrides = values.get('files', [])
        set_overrides = values.get('set', [])

        # Get any stored user overrides for this chart.  We'll need this
        # object later either way.
        try:
            db_chart = objects.helm_overrides.get_by_name(
                pecan.request.context, name, namespace)
        except exception.HelmOverrideNotFound:
            if name in SYSTEM_CHARTS:
                pecan.request.dbapi.helm_override_create({
                    'name': name,
                    'namespace': namespace,
                    'user_overrides': ''})
                db_chart = objects.helm_overrides.get_by_name(
                    pecan.request.context, name, namespace)
            else:
                raise

        if flag == 'reuse':
            file_overrides.insert(0, db_chart.user_overrides)
        elif flag == 'reset':
            pass
        else:
            raise wsme.exc.ClientSideError(_("Invalid flag: %s must be either "
                                             "'reuse' or 'reset'.") % flag)

        user_overrides = self.merge_overrides(
            file_overrides=file_overrides, set_overrides=set_overrides)

        # save chart overrides back to DB
        db_chart.user_overrides = user_overrides
        db_chart.save()

        chart = {'name': name, 'namespace': namespace,
                 'user_overrides': user_overrides}

        return chart

    @wsme_pecan.wsexpose(None, wtypes.text, wtypes.text, status_code=204)
    def delete(self, name, namespace):
        """Delete user overrides for a chart

        :param name: chart name.
        :param namespace: namespace of chart overrides
        """
        self.validate_name_and_namespace(name, namespace)
        try:
            pecan.request.dbapi.helm_override_destroy(name, namespace)
        except exception.HelmOverrideNotFound:
            pass
