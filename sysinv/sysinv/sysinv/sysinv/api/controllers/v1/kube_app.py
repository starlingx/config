#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import pecan
from pecan import rest
import shutil
import tempfile
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from contextlib import contextmanager
from sysinv import objects
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import patch_api
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _

import cgcs_patch.constants as patch_constants

LOG = log.getLogger(__name__)


@contextmanager
def TempDirectory():
    tmpdir = tempfile.mkdtemp()
    saved_umask = os.umask(0o077)
    try:
        yield tmpdir
    finally:
        LOG.debug("Cleaning up temp directory %s" % tmpdir)
        os.umask(saved_umask)
        shutil.rmtree(tmpdir)


class KubeApp(base.APIBase):
    """API representation of a containerized application."""

    id = int
    "Unique ID for this application"

    name = wtypes.text
    "Represents the name of the application"

    app_version = wtypes.text
    "Represents the version of the application"

    created_at = wtypes.datetime.datetime
    "Represents the time the application was uploaded"

    updated_at = wtypes.datetime.datetime
    "Represents the time the application was updated"

    manifest_name = wtypes.text
    "Represents the name of the application manifest"

    manifest_file = wtypes.text
    "Represents the filename of the application manifest"

    status = wtypes.text
    "Represents the installation status of the application"

    progress = wtypes.text
    "Represents the installation progress of the application"

    def __init__(self, **kwargs):
        self.fields = objects.kube_app.fields.keys()
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    @classmethod
    def convert_with_links(cls, rpc_app, expand=True):
        app = KubeApp(**rpc_app.as_dict())
        if not expand:
            app.unset_fields_except(['name', 'app_version', 'manifest_name',
                                     'manifest_file', 'status', 'progress'])

        # skip the id
        app.id = wtypes.Unset

        return app


class KubeAppCollection(collection.Collection):
    """API representation of a collection of Helm applications."""

    apps = [KubeApp]
    "A list containing application objects"

    def __init__(self, **kwargs):
        self._type = 'apps'

    @classmethod
    def convert_with_links(cls, rpc_apps, expand=False):
        collection = KubeAppCollection()
        collection.apps = [KubeApp.convert_with_links(n, expand)
                           for n in rpc_apps]
        return collection


LOCK_NAME = 'KubeAppController'


class KubeAppController(rest.RestController):
    """REST controller for Helm applications."""

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    def _check_environment(self):
        if not utils.is_kubernetes_config():
            raise exception.OperationNotPermitted

    def _check_tarfile(self, app_tarfile, app_name, app_version):
        def _handle_upload_failure(reason):
            raise wsme.exc.ClientSideError(_(
                "Application-upload rejected: " + reason))

        if app_tarfile:
            if not os.path.isfile(app_tarfile):
                _handle_upload_failure(
                    "application tar file {} does not exist.".format(app_tarfile))
            if (not app_tarfile.endswith('.tgz') and
                    not app_tarfile.endswith('.tar.gz')):
                _handle_upload_failure(
                    "{} has unrecognizable tar file extension. Supported "
                    "extensions are: .tgz and .tar.gz.".format(app_tarfile))

            with TempDirectory() as app_path:
                if not cutils.extract_tarfile(app_path, app_tarfile):
                    _handle_upload_failure(
                        "failed to extract tar file {}.".format(os.path.basename(app_tarfile)))

                # If checksum file is included in the tarball, verify its contents.
                if not cutils.verify_checksum(app_path):
                    _handle_upload_failure("checksum validation failed.")

                app_helper = KubeAppHelper(pecan.request.dbapi)
                try:
                    name, version, patches = app_helper._verify_metadata_file(
                        app_path, app_name, app_version)
                    mname, mfile = app_helper._find_manifest_file(app_path)
                    app_helper._extract_helm_charts(app_path)
                    LOG.info("Tar file of application %s verified." % name)
                except exception.SysinvException as e:
                    _handle_upload_failure(str(e))

                return name, version, mname, mfile

        else:
            raise ValueError(_(
                "Application-upload rejected: tar file must be specified."))

    def _get_one(self, app_name):
        # can result in KubeAppNotFound
        kube_app = objects.kube_app.get_by_name(
            pecan.request.context, app_name)
        return KubeApp.convert_with_links(kube_app)

    @wsme_pecan.wsexpose(KubeAppCollection)
    def get_all(self):
        self._check_environment()
        apps = pecan.request.dbapi.kube_app_get_all()
        return KubeAppCollection.convert_with_links(apps)

    @wsme_pecan.wsexpose(KubeApp, wtypes.text)
    def get_one(self, app_name):
        """Retrieve a single application."""
        self._check_environment()
        return self._get_one(app_name)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(KubeApp, body=types.apidict)
    def post(self, body):
        """Uploading an application to be deployed by Armada"""

        self._check_environment()

        tarfile = body.get('tarfile')
        name = body.get('name', '')
        version = body.get('app_version', '')

        if not cutils.is_url(tarfile):
            name, version, mname, mfile = self._check_tarfile(tarfile, name, version)
        else:
            # For tarfile that is downloaded remotely, defer the checksum, manifest
            # and tarfile content validations to sysinv-conductor as download can
            # take some time depending on network traffic, target server and file
            # size.
            mname = constants.APP_MANIFEST_NAME_PLACEHOLDER
            mfile = constants.APP_TARFILE_NAME_PLACEHOLDER
            if not name:
                name = constants.APP_NAME_PLACEHOLDER
            if not version:
                version = constants.APP_VERSION_PLACEHOLDER

        try:
            objects.kube_app.get_by_name(pecan.request.context, name)
            raise wsme.exc.ClientSideError(_(
                "Application-upload rejected: application {} already exists.".format(
                    name)))
        except exception.KubeAppNotFound:
            pass

        # Create a database entry and make an rpc async request to upload
        # the application
        app_data = {'name': name,
                    'app_version': version,
                    'manifest_name': mname,
                    'manifest_file': os.path.basename(mfile),
                    'status': constants.APP_UPLOAD_IN_PROGRESS}
        try:
            new_app = pecan.request.dbapi.kube_app_create(app_data)
        except exception.SysinvException as e:
            LOG.exception(e)
            raise

        pecan.request.rpcapi.perform_app_upload(pecan.request.context,
                                                new_app, tarfile)
        return KubeApp.convert_with_links(new_app)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(KubeApp, wtypes.text, wtypes.text, wtypes.text)
    def patch(self, name, directive, values):
        """Install/update the specified application

        :param name: application name
        :param directive: either 'apply' (fresh install/update) or 'remove'
        """

        self._check_environment()
        if directive not in ['apply', 'remove']:
            raise exception.OperationNotPermitted

        try:
            db_app = objects.kube_app.get_by_name(pecan.request.context, name)
        except exception.KubeAppNotFound:
            LOG.error("Received a request to %s app %s which does not exist." %
                      (directive, name))
            raise wsme.exc.ClientSideError(_(
                "Application-{} rejected: application not found.".format(directive)))

        if directive == 'apply':
            if not values:
                mode = None
            elif name not in constants.HELM_APP_APPLY_MODES.keys():
                raise wsme.exc.ClientSideError(_(
                    "Application-apply rejected: Mode is not supported "
                    "for app {}.".format(name)))
            elif (values['mode'] and
                    values['mode'] not in constants.HELM_APP_APPLY_MODES[name]):
                raise wsme.exc.ClientSideError(_(
                    "Application-apply rejected: Mode {} for app {} is not "
                    "valid. Valid modes are {}.".format(
                        values['mode'], name,
                        constants.HELM_APP_APPLY_MODES[name])))
            else:
                mode = values['mode']

            if db_app.status == constants.APP_APPLY_IN_PROGRESS:
                raise wsme.exc.ClientSideError(_(
                    "Application-apply rejected: install/update is already "
                    "in progress."))
            elif db_app.status not in [constants.APP_UPLOAD_SUCCESS,
                                       constants.APP_APPLY_FAILURE,
                                       constants.APP_APPLY_SUCCESS]:
                raise wsme.exc.ClientSideError(_(
                    "Application-apply rejected: operation is not allowed "
                    "while the current status is {}.".format(db_app.status)))
            app_not_already_applied = (db_app.status != constants.APP_APPLY_SUCCESS)
            db_app.status = constants.APP_APPLY_IN_PROGRESS
            db_app.progress = None
            db_app.save()
            pecan.request.rpcapi.perform_app_apply(pecan.request.context,
                                                   db_app, app_not_already_applied,
                                                   mode=mode)
            return KubeApp.convert_with_links(db_app)
        else:
            if db_app.status not in [constants.APP_APPLY_SUCCESS,
                                     constants.APP_APPLY_FAILURE,
                                     constants.APP_REMOVE_FAILURE]:
                raise wsme.exc.ClientSideError(_(
                    "Application-remove rejected: operation is not allowed while "
                    "the current status is {}.".format(db_app.status)))
            db_app.status = constants.APP_REMOVE_IN_PROGRESS
            db_app.progress = None
            db_app.save()
            pecan.request.rpcapi.perform_app_remove(pecan.request.context,
                                                    db_app)
            return KubeApp.convert_with_links(db_app)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, wtypes.text, status_code=204)
    def delete(self, name):
        """Delete the application with the given name

        :param name: application name
        """

        self._check_environment()
        try:
            db_app = objects.kube_app.get_by_name(pecan.request.context, name)
        except exception.KubeAppNotFound:
            LOG.error("Received a request to delete app %s which does not "
                      "exist." % name)
            raise

        response = pecan.request.rpcapi.perform_app_delete(
            pecan.request.context, db_app)
        if response:
            raise wsme.exc.ClientSideError(_(
                "%s." % response))


class KubeAppHelper(object):

    def __init__(self, dbapi):
        self._dbapi = dbapi

    def _check_patching_operation(self):
        try:
            system = self._dbapi.isystem_get_one()
            response = patch_api.patch_query(
                token=None,
                timeout=constants.PATCH_DEFAULT_TIMEOUT_IN_SECS,
                region_name=system.region_name
            )
            query_patches = response['pd']
        except Exception as e:
            # Assume that a patching operation is underway, raise an exception.
            LOG.error(_("No response from patch api: %s" % e))
            raise

        for patch in query_patches:
            patch_state = query_patches[patch].get('patchstate', None)
            if (patch_state == patch_constants.PARTIAL_APPLY or
                    patch_state == patch_constants.PARTIAL_REMOVE):
                raise exception.SysinvException(_(
                    "Patching operation is in progress."))

    def _check_patch_is_applied(self, patches):
        try:
            system = self._dbapi.isystem_get_one()
            response = patch_api.patch_is_applied(
                token=None,
                timeout=constants.PATCH_DEFAULT_TIMEOUT_IN_SECS,
                region_name=system.region_name,
                patches=patches
            )
        except Exception as e:
            LOG.error(e)
            raise exception.SysinvException(_(
                "Error while querying patch-controller for the "
                "state of the patch(es)."))
        return response

    def _patch_report_app_dependencies(self, name, patches=[]):
        try:
            system = self._dbapi.isystem_get_one()
            patch_api.patch_report_app_dependencies(
                token=None,
                timeout=constants.PATCH_DEFAULT_TIMEOUT_IN_SECS,
                region_name=system.region_name,
                patches=patches,
                app_name=name
            )
        except Exception as e:
            LOG.error(e)
            raise exception.SysinvException(
                "Error while reporting the patch dependencies "
                "to patch-controller.")

    def _find_manifest_file(self, app_path):
        # It is expected that there is only one manifest file
        # per application and the file exists at top level of
        # the application path.
        mfiles = cutils.find_manifest_file(app_path)

        if mfiles is None:
            raise exception.SysinvException(_(
                "manifest file is corrupted."))

        if mfiles:
            if len(mfiles) == 1:
                return mfiles[0]
            else:
                raise exception.SysinvException(_(
                    "Application-upload rejected: tar file contains more "
                    "than one manifest file."))
        else:
            raise exception.SysinvException(_(
                "Application-upload rejected: manifest file is missing."))

    def _verify_metadata_file(self, app_path, app_name, app_version):
        try:
            name, version, patches = cutils.find_metadata_file(
                app_path, constants.APP_METADATA_FILE)
        except exception.SysinvException as e:
            raise exception.SysinvException(_(
                "metadata validation failed. {}".format(e)))

        if not name:
            name = app_name
        if not version:
            version = app_version

        if (not name or not version or
                name == constants.APP_VERSION_PLACEHOLDER or
                version == constants.APP_VERSION_PLACEHOLDER):
            raise exception.SysinvException(_(
                "application name or/and version is/are not included "
                "in the tar file. Please specify the application name "
                "via --app-name or/and version via --app-version."))

        if patches:
            try:
                self._check_patching_operation()
            except exception.SysinvException as e:
                raise exception.SysinvException(_(
                    "{}. Please upload after the patching operation "
                    "is completed.".format(e)))
            except Exception as e:
                raise exception.SysinvException(_(
                    "{}. Communication Error with patching subsytem. "
                    "Preventing application upload.".format(e)))

            applied = self._check_patch_is_applied(patches)
            if not applied:
                raise exception.SysinvException(_(
                    "the required patch(es) for application {} ({}) "
                    "must be applied".format(name, version)))

            LOG.info("The required patch(es) for application {} ({}) "
                     "has/have applied.".format(name, version))
        else:
            LOG.info("No patch required for application {} ({}).".format(name, version))

        return name, version, patches

    def _extract_helm_charts(self, app_path, demote_user=False):
        charts_dir = os.path.join(app_path, 'charts')
        if os.path.isdir(charts_dir):
            tar_filelist = cutils.get_files_matching(app_path, '.tgz')
            if len(os.listdir(charts_dir)) == 0:
                raise exception.SysinvException(_(
                    "tar file contains no Helm charts."))
            if not tar_filelist:
                raise exception.SysinvException(_(
                    "tar file contains no Helm charts of "
                    "expected file extension (.tgz)."))
            for p, f in tar_filelist:
                if not cutils.extract_tarfile(
                        p, os.path.join(p, f), demote_user):
                    raise exception.SysinvException(_(
                        "failed to extract tar file {}.".format(os.path.basename(f))))
