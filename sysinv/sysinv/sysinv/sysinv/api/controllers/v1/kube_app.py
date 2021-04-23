#
# Copyright (c) 2018-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import base64
import os
import hashlib
import pecan
import pwd
from pecan import rest
import time
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv import objects
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import patch_api
from sysinv.api.controllers.v1 import types
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.common import kubernetes
from sysinv.helm.lifecycle_hook import LifecycleHookInfo
from sysinv.openstack.common.rpc import common as rpc_common
import cgcs_patch.constants as patch_constants

LOG = log.getLogger(__name__)


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

    active = bool
    "Represents the application is active"

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
                                     'manifest_file', 'status', 'progress',
                                     'active'])

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

    _custom_actions = {
        'update': ['POST'],
    }

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    @staticmethod
    def _make_db_placeholder(prefix, url):
        url_hash = hashlib.sha256()
        url_hash.update(bytes(str(url).encode('utf-8')))
        return "{}-{}".format(prefix, url_hash.hexdigest()[:16])

    def _check_tarfile(self, app_tarfile, app_name, app_version, operation):
        def _handle_upload_failure(reason):
            raise wsme.exc.ClientSideError(_(
                "Application-{} rejected: ".format(operation) + reason))

        if app_tarfile:
            if cutils.is_url(app_tarfile):
                # For tarfile that is downloaded remotely, defer the checksum, manifest
                # and tarfile content validations to sysinv-conductor as download can
                # take some time depending on network traffic, target server and file
                # size.
                if not app_name:
                    app_name = self._make_db_placeholder(
                                    constants.APP_NAME_PLACEHOLDER, app_tarfile)
                if not app_version:
                    app_version = self._make_db_placeholder(
                                  constants.APP_VERSION_PLACEHOLDER, app_tarfile)
                mname = constants.APP_MANIFEST_NAME_PLACEHOLDER
                mfile = constants.APP_TARFILE_NAME_PLACEHOLDER
                return app_name, app_version, mname, mfile

            if not os.path.isfile(app_tarfile):
                _handle_upload_failure(
                    "application tar file {} does not exist.".format(app_tarfile))
            if (not app_tarfile.endswith('.tgz') and
                    not app_tarfile.endswith('.tar.gz')):
                _handle_upload_failure(
                    "{} has unrecognizable tar file extension. Supported "
                    "extensions are: .tgz and .tar.gz.".format(app_tarfile))

            with cutils.TempDirectory() as app_path:
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
                    return name, version, mname, mfile
                except exception.SysinvException as e:
                    _handle_upload_failure(str(e))
        else:
            raise ValueError(_(
                "Application-{} rejected: tar file must be specified.".format(operation)))

    def _get_one(self, app_name):
        # can result in KubeAppNotFound
        kube_app = objects.kube_app.get_by_name(
            pecan.request.context, app_name)
        return KubeApp.convert_with_links(kube_app)

    @wsme_pecan.wsexpose(KubeAppCollection)
    def get_all(self):
        apps = pecan.request.dbapi.kube_app_get_all()
        return KubeAppCollection.convert_with_links(apps)

    @wsme_pecan.wsexpose(KubeApp, wtypes.text)
    def get_one(self, app_name):
        """Retrieve a single application."""
        return self._get_one(app_name)

    def _app_lifecycle_actions(self, db_app, hook_info):
        """Perform lifecycle actions for application
        """
        pecan.request.rpcapi.app_lifecycle_actions(
            pecan.request.context, db_app, hook_info)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(KubeApp, body=types.apidict)
    def post(self, body):
        """Uploading an application to be deployed by Armada"""
        tarfile_path = body.get('tarfile')
        tarfile_binary = body.get('binary_data', '')
        name = body.get('name', '')
        version = body.get('app_version', '')

        if not cutils.is_url(tarfile_path) and not os.path.exists(tarfile_path):
            path_tarballs = '/tmp/tarball_uploads'
            if not os.path.exists(path_tarballs):
                os.makedirs(path_tarballs)
                uid, gid = pwd.getpwnam('sysinv').pw_uid, pwd.getpwnam('sysinv').pw_uid
                os.chown(path_tarballs, uid, gid)

            # Keep unique tarball name to avoid conflicts
            tarball_name = '{}-{}'.format(time.time(), os.path.basename(tarfile_path))
            tarfile_path = os.path.join(path_tarballs, tarball_name)
            try:
                with open(tarfile_path, 'wb') as f:
                    f.write(base64.urlsafe_b64decode(tarfile_binary))
            except Exception as e:
                LOG.exception('Error: writing the tarfile: {}'.format(e))
                raise wsme.exc.ClientSideError(_(
                    "Could not save the application on path {}".format(tarfile_path)))

        name, version, mname, mfile = self._check_tarfile(tarfile_path, name, version,
                                                          constants.APP_UPLOAD_OP)

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

        lifecycle_hook_info = LifecycleHookInfo()
        lifecycle_hook_info.mode = constants.APP_LIFECYCLE_MODE_MANUAL

        pecan.request.rpcapi.perform_app_upload(pecan.request.context,
                                                new_app, tarfile_path,
                                                lifecycle_hook_info=lifecycle_hook_info)
        return KubeApp.convert_with_links(new_app)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(KubeApp, wtypes.text, wtypes.text, wtypes.text, wtypes.text)
    def patch(self, name, directive, values, force=None):
        """Install/update the specified application

        :param name: application name
        :param directive: either 'apply' (fresh install/update), 'remove' or 'abort'
        """
        if directive not in ['apply', 'remove', 'abort']:
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

            try:
                app_helper = KubeAppHelper(pecan.request.dbapi)
                app_helper._check_app_compatibility(db_app.name,
                                                    db_app.app_version)
            except exception.IncompatibleKubeVersion as e:
                raise wsme.exc.ClientSideError(_(
                    "Application-apply rejected: " + str(e)))

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

            try:
                lifecycle_hook_info = LifecycleHookInfo()
                lifecycle_hook_info.init(constants.APP_LIFECYCLE_MODE_MANUAL,
                                         constants.APP_LIFECYCLE_TYPE_SEMANTIC_CHECK,
                                         constants.APP_LIFECYCLE_TIMING_PRE,
                                         constants.APP_APPLY_OP)
                self._app_lifecycle_actions(db_app,
                                            lifecycle_hook_info)
            except Exception as e:
                raise wsme.exc.ClientSideError(_(
                    "Application-apply rejected: " + str(e.message)))

            db_app.status = constants.APP_APPLY_IN_PROGRESS
            db_app.progress = None
            db_app.recovery_attempts = 0
            db_app.mode = mode
            db_app.save()

            lifecycle_hook_info = LifecycleHookInfo()
            lifecycle_hook_info.mode = constants.APP_LIFECYCLE_MODE_MANUAL

            pecan.request.rpcapi.perform_app_apply(pecan.request.context, db_app,
                                                   mode=mode, lifecycle_hook_info=lifecycle_hook_info)
        elif directive == 'remove':
            if db_app.status not in [constants.APP_APPLY_SUCCESS,
                                     constants.APP_APPLY_FAILURE,
                                     constants.APP_REMOVE_FAILURE]:
                raise wsme.exc.ClientSideError(_(
                    "Application-remove rejected: operation is not allowed while "
                    "the current status is {}.".format(db_app.status)))

            try:
                lifecycle_hook_info = LifecycleHookInfo()
                lifecycle_hook_info.init(constants.APP_LIFECYCLE_MODE_MANUAL,
                                         constants.APP_LIFECYCLE_TYPE_SEMANTIC_CHECK,
                                         constants.APP_LIFECYCLE_TIMING_PRE,
                                         constants.APP_REMOVE_OP)
                # Converting string to boolean
                if force == 'True':
                    force = True
                else:
                    force = False

                lifecycle_hook_info.extra = {constants.APP_LIFECYCLE_FORCE_OPERATION: force}
                self._app_lifecycle_actions(db_app,
                                            lifecycle_hook_info)
            except rpc_common.RemoteError as e:
                raise wsme.exc.ClientSideError(_(
                    "Application-remove rejected: " + str(e.value)))
            except Exception as e:
                raise wsme.exc.ClientSideError(_(
                    "Application-remove rejected: " + str(e.message)))

            db_app.status = constants.APP_REMOVE_IN_PROGRESS
            db_app.progress = None
            db_app.save()

            lifecycle_hook_info = LifecycleHookInfo()
            lifecycle_hook_info.mode = constants.APP_LIFECYCLE_MODE_MANUAL

            pecan.request.rpcapi.perform_app_remove(pecan.request.context,
                                                    db_app, lifecycle_hook_info=lifecycle_hook_info)
        else:
            if db_app.status not in [constants.APP_APPLY_IN_PROGRESS,
                                     constants.APP_UPDATE_IN_PROGRESS,
                                     constants.APP_REMOVE_IN_PROGRESS]:
                raise wsme.exc.ClientSideError(_(
                    "Application-abort rejected: operation is not allowed while "
                    "the current status is {}.".format(db_app.status)))

            try:
                lifecycle_hook_info = LifecycleHookInfo()
                lifecycle_hook_info.init(constants.APP_LIFECYCLE_MODE_MANUAL,
                                         constants.APP_LIFECYCLE_TYPE_SEMANTIC_CHECK,
                                         constants.APP_LIFECYCLE_TIMING_PRE,
                                         constants.APP_ABORT_OP)
                self._app_lifecycle_actions(db_app,
                                            lifecycle_hook_info)
            except Exception as e:
                raise wsme.exc.ClientSideError(_(
                    "Application-abort rejected: " + str(e.message)))

            lifecycle_hook_info = LifecycleHookInfo()
            lifecycle_hook_info.mode = constants.APP_LIFECYCLE_MODE_MANUAL

            pecan.request.rpcapi.perform_app_abort(pecan.request.context,
                                                   db_app, lifecycle_hook_info=lifecycle_hook_info)
        return KubeApp.convert_with_links(db_app)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(KubeApp, body=types.apidict)
    def update(self, body):
        """Update the applied application to a different version"""
        tarfile = body.get('tarfile')
        name = body.get('name', '')
        version = body.get('app_version', '')
        name, version, mname, mfile = self._check_tarfile(tarfile, name, version,
                                                          constants.APP_UPDATE_OP)

        reuse_overrides_flag = body.get('reuse_user_overrides', None)
        if reuse_overrides_flag is None:
            # None means let the application decide
            reuse_overrides = None
        elif reuse_overrides_flag in ['true', 'True']:
            reuse_overrides = True
        elif reuse_overrides_flag in ['false', 'False']:
            reuse_overrides = False
        else:
            raise wsme.exc.ClientSideError(_(
                "Application-update rejected: "
                "invalid reuse_user_overrides setting."))

        try:
            applied_app = objects.kube_app.get_by_name(pecan.request.context, name)
        except exception.KubeAppNotFound:
            LOG.error("Received a request to update app %s which does not exist." %
                      name)
            raise wsme.exc.ClientSideError(_(
                "Application-update rejected: application not found."))

        try:
            lifecycle_hook_info = LifecycleHookInfo()
            lifecycle_hook_info.init(constants.APP_LIFECYCLE_MODE_MANUAL,
                                     constants.APP_LIFECYCLE_TYPE_SEMANTIC_CHECK,
                                     constants.APP_LIFECYCLE_TIMING_PRE,
                                     constants.APP_UPDATE_OP)
            self._app_lifecycle_actions(applied_app,
                                        lifecycle_hook_info)
        except Exception as e:
            raise wsme.exc.ClientSideError(_(
                "Application-update rejected: " + str(e.message)))

        if applied_app.status == constants.APP_UPDATE_IN_PROGRESS:
            raise wsme.exc.ClientSideError(_(
                "Application-update rejected: update is already "
                "in progress."))
        elif applied_app.status != constants.APP_APPLY_SUCCESS:
            raise wsme.exc.ClientSideError(_(
                "Application-update rejected: operation is not allowed "
                "while the current status is {}.".format(applied_app.status)))

        if applied_app.app_version == version:
            raise wsme.exc.ClientSideError(_(
                "Application-update rejected: the version %s is already "
                "applied." % version))
        # Set the status for the current applied app to inactive
        applied_app.status = constants.APP_INACTIVE_STATE
        applied_app.progress = None
        applied_app.save()

        # If the version has ever applied before(inactive app found),
        # use armada rollback to apply application later, otherwise,
        # use armada apply.
        # On the AIO-SX, always use armada apply even it was applied
        # before, issue on AIO-SX(replicas is 1) to leverage rollback,
        # armada/helm rollback --wait does not wait for pods to be
        # ready before it returns.
        # related to helm issue,
        # https://github.com/helm/helm/issues/4210
        # https://github.com/helm/helm/issues/2006
        try:
            target_app = objects.kube_app.get_inactive_app_by_name_version(
                pecan.request.context, name, version)
            target_app.status = constants.APP_UPDATE_IN_PROGRESS
            target_app.save()
            if cutils.is_aio_simplex_system(pecan.request.dbapi):
                operation = constants.APP_APPLY_OP
            else:
                operation = constants.APP_ROLLBACK_OP
        except exception.KubeAppInactiveNotFound:
            target_app_data = {
                'name': name,
                'app_version': version,
                'manifest_name': mname,
                'manifest_file': os.path.basename(mfile),
                'status': constants.APP_UPDATE_IN_PROGRESS,
                'active': True
            }
            operation = constants.APP_APPLY_OP

            try:
                target_app = pecan.request.dbapi.kube_app_create(target_app_data)
            except exception.KubeAppAlreadyExists as e:
                applied_app.status = constants.APP_APPLY_SUCCESS
                applied_app.progress = constants.APP_PROGRESS_COMPLETED
                applied_app.save()
                LOG.exception(e)
                raise wsme.exc.ClientSideError(_(
                    "Application-update failed: Unable to start application update, "
                    "application info update failed."))

        lifecycle_hook_info = LifecycleHookInfo()
        lifecycle_hook_info.mode = constants.APP_LIFECYCLE_MODE_MANUAL

        pecan.request.rpcapi.perform_app_update(pecan.request.context,
                                                applied_app, target_app,
                                                tarfile, operation,
                                                lifecycle_hook_info, reuse_overrides)

        return KubeApp.convert_with_links(target_app)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, wtypes.text, wtypes.text, status_code=204)
    def delete(self, name, force=None):
        """Delete the application with the given name

        :param name: application name
        """
        try:
            db_app = objects.kube_app.get_by_name(pecan.request.context, name)
        except exception.KubeAppNotFound:
            LOG.error("Received a request to delete app %s which does not "
                      "exist." % name)
            raise wsme.exc.ClientSideError(_(
                "Application-delete rejected: application not found."))

        if db_app.status not in [constants.APP_UPLOAD_SUCCESS,
                                 constants.APP_UPLOAD_FAILURE]:
            raise wsme.exc.ClientSideError(_(
                "Application-delete rejected: operation is not allowed "
                "while the current status is {}.".format(db_app.status)))

        try:
            lifecycle_hook_info = LifecycleHookInfo()
            lifecycle_hook_info.init(constants.APP_LIFECYCLE_MODE_MANUAL,
                                     constants.APP_LIFECYCLE_TYPE_SEMANTIC_CHECK,
                                     constants.APP_LIFECYCLE_TIMING_PRE,
                                     constants.APP_DELETE_OP)
            # Converting string to boolean
            if force == 'True':
                force = True
            else:
                force = False

            lifecycle_hook_info.extra = {constants.APP_LIFECYCLE_FORCE_OPERATION: force}
            self._app_lifecycle_actions(db_app,
                                        lifecycle_hook_info)
        except rpc_common.RemoteError as e:
            raise wsme.exc.ClientSideError(_(
                "Application-delete rejected: " + str(e.value)))
        except Exception as e:
            raise wsme.exc.ClientSideError(_(
                "Application-delete rejected: " + str(e.message)))

        lifecycle_hook_info = LifecycleHookInfo()
        lifecycle_hook_info.mode = constants.APP_LIFECYCLE_MODE_MANUAL

        response = pecan.request.rpcapi.perform_app_delete(
            pecan.request.context, db_app, lifecycle_hook_info=lifecycle_hook_info)
        if response:
            raise wsme.exc.ClientSideError(_(
                "%s." % response))


class KubeAppHelper(object):

    def __init__(self, dbapi):
        self._dbapi = dbapi
        self._kube_operator = kubernetes.KubeOperator()

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

    def _check_required_patches_are_applied(self, patches=None):
        """Validates that each patch provided is applied on the system"""
        if patches is None:
            patches = []
        try:
            system = self._dbapi.isystem_get_one()
            response = patch_api.patch_query(
                token=None,
                timeout=constants.PATCH_DEFAULT_TIMEOUT_IN_SECS,
                region_name=system.region_name
            )
        except Exception as e:
            LOG.error(e)
            raise exception.SysinvException(_(
                "Error while querying patch-controller for the "
                "state of the patch(es)."))
        query_patches = response['pd']
        applied_patches = []
        for patch_key in query_patches:
            patch = query_patches[patch_key]
            patchstate = patch.get('patchstate', None)
            if patchstate == patch_constants.APPLIED or \
                    patchstate == patch_constants.COMMITTED:
                applied_patches.append(patch_key)

        missing_patches = []
        for required_patch in patches:
            if required_patch not in applied_patches:
                missing_patches.append(required_patch)

        success = not missing_patches
        return success, missing_patches

    def _patch_report_app_dependencies(self, name, patches=None):
        if patches is None:
            patches = []
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

    def _check_app_compatibility(self, app_name, app_version):
        """Checks whether the application is compatible
           with the current k8s version"""

        kube_min_version, kube_max_version = \
            cutils.get_app_supported_kube_version(app_name, app_version)

        if not kube_min_version and not kube_max_version:
            return

        version_states = self._kube_operator.kube_get_version_states()
        for kube_version, state in version_states.items():
            if state in [kubernetes.KUBE_STATE_ACTIVE,
                         kubernetes.KUBE_STATE_PARTIAL]:
                if not kubernetes.is_kube_version_supported(
                        kube_version, kube_min_version, kube_max_version):
                    raise exception.IncompatibleKubeVersion(
                        name=app_name, version=app_version, kube_version=kube_version)

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

    def _verify_metadata_file(self, app_path, app_name, app_version,
                              upgrade_from_release=None):
        try:
            name, version, patches = cutils.find_metadata_file(
                app_path, constants.APP_METADATA_FILE,
                upgrade_from_release=upgrade_from_release)
        except exception.SysinvException as e:
            raise exception.SysinvException(_(
                "metadata validation failed. {}".format(e)))

        if not name:
            name = app_name
        if not version:
            version = app_version

        if (not name or not version or
                name.startswith(constants.APP_VERSION_PLACEHOLDER) or
                version.startswith(constants.APP_VERSION_PLACEHOLDER)):
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

            applied, missing_patches = \
                self._check_required_patches_are_applied(patches)
            if not applied:
                raise exception.SysinvException(_(
                    "the required patch(es) ({}) for application {} ({}) "
                    "must be applied".format(', '.join(missing_patches),
                                             name, version)))

            LOG.info("The required patch(es) for application {} ({}) "
                     "has/have applied.".format(name, version))
        else:
            LOG.info("No patch required for application {} ({})."
                     "".format(name, version))

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
