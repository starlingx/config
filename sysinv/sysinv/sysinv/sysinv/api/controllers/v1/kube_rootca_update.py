#
# Copyright (c) 2021-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


import datetime
import os
import pecan
import re
import six
import wsme
import wsmeext.pecan as wsme_pecan

from fm_api import fm_api
from fm_api import constants as fm_constants
from oslo_log import log
from pecan import expose
from pecan import rest
from sysinv import objects
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import dc_api
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import usm_service as usm_service
from sysinv.common import utils as cutils
from sysinv._i18n import _
from wsme import types as wtypes


LOG = log.getLogger(__name__)

LOCK_KUBE_ROOTCA_CONTROLLER = 'KubeRootCAController'


class KubeRootCAUpdatePatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return ['/state']


class KubeRootCAGenerateController(rest.RestController):
    """ API representation of a Kubernetes Generate Root CA Certificate"""

    def get_subject(self, subject):
        """ Takes a subject formatted string and convert it to a
        dictionary corresponding to the respective parameter to be
        added in the certificate and its value added.

        :params subject: a formatted string corresponding to subject
        data
        :returns: a dictionary with the key-value pair of each
        parameter. In the case where a not supported parameter is
        added to the string the method will throw an exception
        indicating the error.
        """
        params_supported = ['C', 'OU', 'O', 'ST', 'CN', 'L']
        if subject is None:
            return {}
        subject_pairs = re.findall(r"([^=]+=[^=]+)(?:\s|$)", subject)
        subject_dict = {}
        for pair_value in subject_pairs:
            key, value = pair_value.split("=")
            subject_dict[key] = value

        if not all([param in params_supported for param in subject_dict.keys()]):
            raise wsme.exc.ClientSideError(_("There are parameters not supported "
                                            "for the certificate subject specification. "
                                            "The subject parameter has to be in the "
                                            "format of 'C=<Country> ST=<State/Province> "
                                            "L=<Locality> O=<Organization> OU=<OrganizationUnit> "
                                            "CN=<commonName>"))
        if 'CN' not in list(subject_dict.keys()):
            raise wsme.exc.ClientSideError(_("The CN=<commonName> parameter is required to be "
                                            "specified in subject argument"))
        return subject_dict

    def _calculate_duration(self, expiry_date):
        if expiry_date is None:
            return None
        try:
            date = datetime.datetime.strptime(expiry_date, "%Y-%m-%d")
        except ValueError:
            raise wsme.exc.ClientSideError(_(
                "expiry_date %s doesn't match format YYYY-MM-DD" % expiry_date))
        delta = date - datetime.datetime.now()

        # we sum one day (24 hours) to accomplish the certificate expiry
        # during the day specified by the user
        duration = (delta.days * 24 + 24)

        # Cert-manager manages certificates and renew them some time
        # before it expires. Along this procedure we set renewBefore
        # parameter for 24h, so we are checking if the duration sent
        # has at least this amount of time. This is needed to avoid
        # cert-manager to block the creation of the resources.
        if duration <= 24:
            raise wsme.exc.ClientSideError(_(
                "New k8s rootCA should have at least 24 hours of "
                "validation before expiry."))
        return duration

    @cutils.synchronized(LOCK_KUBE_ROOTCA_CONTROLLER)
    @wsme_pecan.wsexpose(wtypes.text, wtypes.text, wtypes.text)
    def post(self, expiry_date, subject):
        duration = self._calculate_duration(expiry_date)
        subject_params = self.get_subject(subject)
        output = pecan.request.rpcapi.generate_kubernetes_rootca_cert(
            pecan.request.context, subject_params, duration)
        return output


class KubeRootCAUploadController(rest.RestController):
    """ API representation of a Kubernetes Upload Root CA Certificate"""

    @cutils.synchronized(LOCK_KUBE_ROOTCA_CONTROLLER)
    @expose('json')
    def post(self):
        fileitem = pecan.request.POST['file']

        if not fileitem.filename:
            raise wsme.exc.ClientSideError(_("Error: No file uploaded"))

        try:
            fileitem.file.seek(0, os.SEEK_SET)
            pem_contents = fileitem.file.read()
        except Exception:
            return dict(
                success="",
                error=("No kube rootca certificate have been added, invalid PEM document"))

        try:
            output = pecan.request.rpcapi.save_kubernetes_rootca_cert(
                pecan.request.context,
                pem_contents
            )
        except Exception:
            msg = "Conductor call for new kube rootca upload failed"
            return dict(success="", error=msg)
        return output


class KubeRootCAUpdate(base.APIBase):
    """API representation of a Kubernetes RootCA Update."""

    id = int
    "Unique ID for this entry"

    uuid = types.uuid
    "Unique UUID for this entry"

    from_rootca_cert = wtypes.text
    "The from certificate for the kubernetes rootCA update"

    to_rootca_cert = wtypes.text
    "The to certificate for the kubernetes rootCA update"

    state = wtypes.text
    "Kubernetes rootCA update state"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                                                  six.integer_types)}
    "Additional properties to be used in kube_rootca_update operations"

    links = [link.Link]
    "A list containing a self link and associated kubernetes rootca update links"

    def __init__(self, **kwargs):
        self.fields = list(objects.kube_rootca_update.fields.keys())
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    @classmethod
    def convert_with_links(cls, rpc_kube_rootca_update, expand=True):
        kube_rootca_update = KubeRootCAUpdate(**rpc_kube_rootca_update.as_dict())
        if not expand:
            kube_rootca_update.unset_fields_except(['uuid', 'from_rootca_cert',
                                                    'to_rootca_cert', 'state'])

        kube_rootca_update.links = [
            link.Link.make_link('self', pecan.request.host_url,
                                'kube_rootca_update', kube_rootca_update.uuid),
            link.Link.make_link('bookmark',
                                pecan.request.host_url,
                                'kube_rootca_update', kube_rootca_update.uuid,
                                bookmark=True)
                         ]
        return kube_rootca_update


class KubeRootCAHostUpdate(base.APIBase):
    """API representation of a Kubernetes RootCA Host Update."""

    id = int
    "Unique ID for this entry"

    uuid = types.uuid
    "Unique UUID for this entry"

    target_rootca_cert = wtypes.text
    "The target certificate for the kubernetes rootCA host update"

    effective_rootca_cert = wtypes.text
    "The current certificate of the kubernetes rootCA on this host"

    state = wtypes.text
    "Kubernetes rootCA host update state"

    hostname = wtypes.text
    "Represent the hostname of the host"

    personality = wtypes.text
    "Represent the personality of the host"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                                                  six.integer_types)}
    "Additional properties to be used in kube_rootca_host_update operations"

    links = [link.Link]
    "A list containing a self link and associated kubernetes rootca host "
    "update links"

    def __init__(self, **kwargs):
        self.fields = list(objects.kube_rootca_host_update.fields.keys())
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    @classmethod
    def convert_with_links(cls, kube_rootca_host_update, expand=True):
        kube_rootca_host_update = KubeRootCAHostUpdate(
            **kube_rootca_host_update.as_dict())
        if not expand:
            kube_rootca_host_update.unset_fields_except(['uuid',
                'target_rootca_cert', 'effective_rootca_cert', 'state'])

        kube_rootca_host_update.links = [
            link.Link.make_link('self', pecan.request.host_url,
                                'kube_rootca_host_update',
                                kube_rootca_host_update.uuid),
            link.Link.make_link('bookmark',
                                pecan.request.host_url,
                                'kube_rootca_host_update',
                                kube_rootca_host_update.uuid,
                                bookmark=True)
                        ]
        return kube_rootca_host_update


class KubeRootCAHostUpdateCollection(collection.Collection):
    kube_host_updates = [KubeRootCAHostUpdate]
    "A list containing kubernetes rootCA update hosts"

    def __init__(self):
        self._type = 'kube_host_updates'

    @classmethod
    def convert_with_links(cls, kube_host_update_objs, limit=None, url=None,
                           expand=True, **kwargs):
        update_collection = KubeRootCAHostUpdateCollection()
        update_collection.kube_host_updates = [
            KubeRootCAHostUpdate.convert_with_links(p, expand)
            for p in kube_host_update_objs]
        update_collection.next = update_collection.get_next(
            limit, url=url, **kwargs)
        return update_collection


class KubeRootCAUpdateCollection(collection.Collection):
    kube_rootca_updates = [KubeRootCAUpdate]
    "A list containing kubernetes rootCA updates"

    def __init__(self):
        self._type = 'kube_rootca_updates'

    @classmethod
    def convert_with_links(cls, kube_host_update_objs, limit=None, url=None,
                           expand=True, **kwargs):
        update_collection = KubeRootCAUpdateCollection()
        update_collection.kube_rootca_updates = [
            KubeRootCAUpdate.convert_with_links(p, expand)
            for p in kube_host_update_objs]
        update_collection.next = update_collection.get_next(
            limit, url=url, **kwargs)
        return update_collection


class KubeRootCAPodsUpdateController(rest.RestController):

    def _precheck_trustbothcas(self, cluster_update):
        # Pre checking if conditions met for phase trustBothCAs
        if cluster_update.state not in \
                [kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTBOTHCAS,
                 kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTBOTHCAS_FAILED]:
            raise wsme.exc.ClientSideError(_(
                "kube-rootca-pods-update phase trust-both-cas rejected: "
                "not allowed when cluster update is in state: %s. "
                "(only allowed when in state: %s or %s)"
                % (cluster_update.state,
                kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTBOTHCAS,
                kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTBOTHCAS_FAILED)))

    def _precheck_trustnewca(self, cluster_update):
        # Pre checking if conditions met for phase trustNewCA
        if cluster_update.state not in \
                [kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTNEWCA,
                 kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTNEWCA_FAILED]:
            raise wsme.exc.ClientSideError(_(
                "kube-rootca-pods-update phase trust-new-ca rejected: "
                "not allowed when cluster update is in state: %s. "
                "(only allowed when in state: %s or %s)"
                % (cluster_update.state,
                kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTNEWCA,
                kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTNEWCA_FAILED)))

    @cutils.synchronized(LOCK_KUBE_ROOTCA_CONTROLLER)
    @wsme_pecan.wsexpose(KubeRootCAUpdate, body=six.text_type)
    def post(self, body):
        # Check cluster update status
        try:
            update = pecan.request.dbapi.kube_rootca_update_get_one()
        except exception.NotFound:
            raise wsme.exc.ClientSideError(_(
                "kube-rootca-pods-update rejected: No update in progress."))

        phase = body['phase'].lower()

        if phase == constants.KUBE_CERT_UPDATE_TRUSTBOTHCAS:
            # kube root CA update for pods phase trustBothCAs
            self._precheck_trustbothcas(update)
            update_state = kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTBOTHCAS
        elif phase == constants.KUBE_CERT_UPDATE_TRUSTNEWCA:
            # kube root CA update for pods phase trustNewCA
            self._precheck_trustnewca(update)
            update_state = kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTNEWCA
        else:
            raise wsme.exc.ClientSideError(_(
                "kube-rootca-pods-update rejected: phase %s not supported."
                % (phase)))

        # Update the cluster update state
        values = dict()
        values['state'] = update_state
        update = \
            pecan.request.dbapi.kube_rootca_update_update(update.id, values)

        # perform rpc to conductor to perform config apply
        pecan.request.rpcapi.kube_certificate_update_for_pods(
            pecan.request.context, phase)

        return KubeRootCAUpdate.convert_with_links(update)


class KubeRootCAHostUpdateListController(rest.RestController):

    @wsme_pecan.wsexpose(KubeRootCAHostUpdateCollection)
    def get(self):
        """Retrieves a list of kubernetes rootca update status by host"""

        try:
            pecan.request.dbapi.kube_rootca_update_get_one()
        except exception.NotFound:
            raise wsme.exc.ClientSideError(_(
                "kube-rootca-update-list rejected: No kubernetes root CA update in progress."))

        rpc_host_update_status_list = pecan.request.dbapi.kube_rootca_host_update_get_list()
        return KubeRootCAHostUpdateCollection.convert_with_links(rpc_host_update_status_list)


class KubeRootCACetCertIDController(rest.RestController):

    @wsme_pecan.wsexpose(wtypes.text)
    def get(self):
        """Retrieves existing kubernetes rootca ID"""

        try:
            rootca_cert = pecan.request.rpcapi.get_current_kube_rootca_cert_id(
                context=pecan.request.context)
            return dict(cert_id=rootca_cert, error="")
        except Exception as e:
            msg = ("Failed to find the current Kubernetes root CA certificate "
                   "from file system")
            LOG.exception(e)
            return dict(cert_id="", error=msg)


class KubeRootCAUpdateController(rest.RestController):
    """REST controller for kubernetes rootCA updates."""

    # Controller for /kube_rootca_update/upload_cert, upload new root CA
    # certificate.
    upload_cert = KubeRootCAUploadController()
    # Controller for /kube_rootca_update/generate_cert, generates a new root CA
    generate_cert = KubeRootCAGenerateController()
    # Controller for /kube_rootca_update/pods, update pods certificates.
    pods = KubeRootCAPodsUpdateController()
    # Controller for /kube_rootca_update/hosts, list updates by hosts.
    hosts = KubeRootCAHostUpdateListController()
    # Controller for /kube_rootca_update/get_cert_id, check existing root CA ID
    get_cert_id = KubeRootCACetCertIDController()

    def __init__(self):
        self.fm_api = fm_api.FaultAPIs()
        self.alarm_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                            constants.CONTROLLER_HOSTNAME)

    def _get_updates(self, patch):
        """Retrieve the updated attributes from the patch request."""
        updates = {}
        for p in patch:
            attribute = p['path'] if p['path'][0] != '/' else p['path'][1:]
            updates[attribute] = p['value']
        return updates

    def _check_cluster_health(self, command_name, alarm_ignore_list=None, force=False):
        healthy, output = pecan.request.rpcapi.get_system_health(
            pecan.request.context,
            force=force,
            kube_rootca_update=True,
            alarm_ignore_list=alarm_ignore_list)
        if not healthy:
            LOG.info("Health query failure for %s:\n%s"
                     % (command_name, output))
            if os.path.exists(constants.SYSINV_RUNNING_IN_LAB):
                LOG.info("Running in lab, ignoring health errors.")
            else:
                raise wsme.exc.ClientSideError(_(
                    "System is not healthy. Run 'system health-query-kube-upgrade "
                    "--rootca' for more details."))

    def _clear_kubernetes_resources(self, hostnames):
        """Clears secrets and issuers created during the update process
        If a resource is not found a warning is logged and the operation continues"""

        secret_list = [
            constants.KUBE_ADMIN_CERT,
            constants.KUBE_SUPER_ADMIN_CERT,
            constants.KUBE_ROOTCA_SECRET,
        ]

        for hostname in hostnames:
            secret_list.append(constants.KUBE_APISERVER_CERT.format(hostname))
            secret_list.append(constants.KUBE_APISERVER_KUBELET_CERT.format(hostname))
            secret_list.append(constants.KUBE_SCHEDULER_CERT.format(hostname))
            secret_list.append(constants.KUBE_CONTROLLER_MANAGER_CERT.format(hostname))
            secret_list.append(constants.KUBE_KUBELET_CERT.format(hostname))

        certificate_list = []
        # Certificates and secrets share the same name
        certificate_list.extend(secret_list)

        issuers_list = [
            constants.KUBE_SELFSIGNED_ISSUER,
            constants.KUBE_ROOTCA_ISSUER,
        ]

        pecan.request.rpcapi.clear_kubernetes_rootca_update_resources(
            context=pecan.request.context,
            certificate_list=certificate_list,
            issuers_list=issuers_list,
            secret_list=secret_list)

    @cutils.synchronized(LOCK_KUBE_ROOTCA_CONTROLLER)
    @wsme_pecan.wsexpose(KubeRootCAUpdate, wtypes.text, body=six.text_type)
    def post(self, force, body):
        """Create a new Kubernetes RootCA Update and start update."""

        force = force == 'True'
        alarm_ignore_list = body.get('alarm_ignore_list', [])
        alarm_ignore_list.extend([
            fm_constants.FM_ALARM_ID_KUBE_ROOTCA_UPDATE_ABORTED,
            fm_constants.FM_ALARM_ID_CERT_EXPIRING_SOON])

        try:
            update = pecan.request.dbapi.kube_rootca_update_get_one()
        except exception.NotFound:
            pass
        else:
            if update.state == kubernetes.KUBE_ROOTCA_UPDATE_ABORTED:
                pecan.request.dbapi.kube_rootca_update_destroy(update.id)
            else:
                raise wsme.exc.ClientSideError((
                    "A kubernetes rootca update is already in progress"))

        # There must not be a platform upgrade in progress
        try:
            usm_service.get_platform_upgrade(pecan.request.dbapi)
        except exception.NotFound:
            pass
        else:
            raise wsme.exc.ClientSideError(_(
                "A kubernetes rootca update cannot be done while a platform upgrade is in progress"))

        # There must not be a kubernetes upgrade in progress
        try:
            pecan.request.dbapi.kube_upgrade_get_one()
        except exception.NotFound:
            pass
        else:
            raise wsme.exc.ClientSideError(_(
                "A kubernetes rootca update cannot be done while a kube upgrade "
                "is in progress"))

        # The system must be healthy
        self._check_cluster_health(
            "kube-rootca-update-start",
            alarm_ignore_list=alarm_ignore_list,
            force=force,
        )

        # Get current kubernetes root CA certificate ID
        try:
            from_rootca_cert = \
                pecan.request.rpcapi.get_current_kube_rootca_cert_id(
                    context=pecan.request.context)
        except Exception:
            raise wsme.exc.ClientSideError(
                "Failed to get the current kubernetes root CA certificate ID")

        create_obj = {'state': kubernetes.KUBE_ROOTCA_UPDATE_STARTED,
                      'from_rootca_cert': from_rootca_cert
                      }
        new_update = pecan.request.dbapi.kube_rootca_update_create(create_obj)

        # create update entries for each of the nodes
        hosts = pecan.request.dbapi.ihost_get_list()
        for host in hosts:
            if host.personality in [constants.CONTROLLER,
                                    constants.WORKER]:
                pecan.request.dbapi.kube_rootca_host_update_create(host.id,
                                                                   {'effective_rootca_cert': from_rootca_cert})

        # clear update aborted alarm if there is one
        if self.fm_api.get_fault(fm_constants.FM_ALARM_ID_KUBE_ROOTCA_UPDATE_ABORTED,
                                self.alarm_instance_id):
            self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_KUBE_ROOTCA_UPDATE_ABORTED,
                                    self.alarm_instance_id)

        # raise update in progess alarm
        fault = fm_api.Fault(
                alarm_id=fm_constants.FM_ALARM_ID_KUBE_ROOTCA_UPDATE_IN_PROGRESS,
                alarm_state=fm_constants.FM_ALARM_STATE_SET,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                entity_instance_id=self.alarm_instance_id,
                severity=fm_constants.FM_ALARM_SEVERITY_MINOR,
                reason_text="Kubernetes rootca update in progress",
                # environmental
                alarm_type=fm_constants.FM_ALARM_TYPE_5,
                # unspecified-reason
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_65,
                proposed_repair_action="Wait for kubernetes rootca procedure to complete",
                service_affecting=False)
        self.fm_api.set_fault(fault)

        LOG.info("Started kubernetes rootca update")
        return KubeRootCAUpdate.convert_with_links(new_update)

    @wsme_pecan.wsexpose(KubeRootCAUpdate, types.uuid)
    def get_one(self, uuid=None):
        """Retrieve information about the given kubernetes rootca update."""

        rpc_kube_rootca_update = objects.kube_rootca_update.get_by_uuid(
            pecan.request.context, uuid)
        return KubeRootCAUpdate.convert_with_links(rpc_kube_rootca_update)

    @wsme_pecan.wsexpose(KubeRootCAUpdateCollection)
    def get(self):
        """Retrieve kubernetes rootca update status."""
        rpc_kube_rootca_update = pecan.request.dbapi.kube_rootca_update_get_list()
        return KubeRootCAUpdateCollection.convert_with_links(rpc_kube_rootca_update)

    # TODO (aning): move DB state update to conductor and synchronize with
    # state updating resulting from puppet apply status report using a LOCK.
    # (eg, sync with report_kube_rootca_update_success())
    @cutils.synchronized(LOCK_KUBE_ROOTCA_CONTROLLER)
    @wsme.validate([KubeRootCAUpdatePatchType])
    @wsme_pecan.wsexpose(KubeRootCAUpdate, wtypes.text, body=[KubeRootCAUpdatePatchType])
    def patch(self, patch):
        """Completes the kubernetes rootca, clearing both tables and alarm"""
        updates = self._get_updates(patch)
        update_state = updates['state']

        if update_state not in [kubernetes.KUBE_ROOTCA_UPDATE_COMPLETED,
                                    kubernetes.KUBE_ROOTCA_UPDATE_ABORTED]:
            raise wsme.exc.ClientSideError(_(
                "Invalid state %s supplied" % update_state))

        # Check if there is an update in progress and the current state
        try:
            rpc_kube_rootca_update = pecan.request.dbapi.kube_rootca_update_get_one()
            if update_state == kubernetes.KUBE_ROOTCA_UPDATE_COMPLETED \
                    and rpc_kube_rootca_update.state != kubernetes.KUBE_ROOTCA_UPDATED_PODS_TRUSTNEWCA:
                raise wsme.exc.ClientSideError(_(
                    "kube-rootca-update-complete rejected: Expect to find cluster update state %s, "
                    "not allowed when cluster update state is %s."
                    % (kubernetes.KUBE_ROOTCA_UPDATED_PODS_TRUSTNEWCA, rpc_kube_rootca_update.state)))
            elif update_state == kubernetes.KUBE_ROOTCA_UPDATE_ABORTED \
                    and rpc_kube_rootca_update.state == kubernetes.KUBE_ROOTCA_UPDATE_ABORTED:
                raise wsme.exc.ClientSideError(_(
                    "kube-rootca-update-complete rejected: The update has already been aborted."))

        except exception.NotFound:
            raise wsme.exc.ClientSideError(_(
                "kube-rootca-update-complete rejected: No kubernetes root CA update in progress."))

        rpc_host_update_list = pecan.request.dbapi.kube_rootca_host_update_get_list()
        hostnames = [host.hostname for host in rpc_host_update_list]

        LOG.debug("Starting cleanup procedure")

        self._clear_kubernetes_resources(hostnames)

        # cleanup kube_rootca_host_update table
        pecan.request.dbapi.kube_rootca_host_update_destroy_all()

        # if update is in the list of states, abort will be the same as complete
        if update_state == kubernetes.KUBE_ROOTCA_UPDATE_ABORTED \
                and rpc_kube_rootca_update.state in [kubernetes.KUBE_ROOTCA_UPDATED_PODS_TRUSTNEWCA]:
            update_state = kubernetes.KUBE_ROOTCA_UPDATE_COMPLETED

        values = dict()
        values['state'] = update_state
        update = \
            pecan.request.dbapi.kube_rootca_update_update(rpc_kube_rootca_update.id, values)

        # cleanup kube_rootca_update table for completion
        if update_state == kubernetes.KUBE_ROOTCA_UPDATE_COMPLETED:
            pecan.request.dbapi.kube_rootca_update_destroy(rpc_kube_rootca_update.id)
            LOG.debug("Removed procedure entry on kube_rootca_update table")

            # If applicable, notify dcmanager that the update is completed
            system = pecan.request.dbapi.isystem_get_one()
            role = system.get('distributed_cloud_role')
            if role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
                dc_api.notify_dcmanager_kube_rootca_update_completed()
            LOG.info("Kubernetes rootca update completed")

        # clear update in progess alarm
        if self.fm_api.get_fault(fm_constants.FM_ALARM_ID_KUBE_ROOTCA_UPDATE_IN_PROGRESS,
                                self.alarm_instance_id):
            LOG.debug("Removing KUBE ROOTCA UPDATE IN PROGRESS alarm")
            self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_KUBE_ROOTCA_UPDATE_IN_PROGRESS,
                                    self.alarm_instance_id)

        # raise update aborted alarm if this is an abort
        if update_state == kubernetes.KUBE_ROOTCA_UPDATE_ABORTED:
            LOG.debug("Raising KUBE ROOTCA PROCEDURE ABORTED alarm")
            fault = fm_api.Fault(
                    alarm_id=fm_constants.FM_ALARM_ID_KUBE_ROOTCA_UPDATE_ABORTED,
                    alarm_state=fm_constants.FM_ALARM_STATE_SET,
                    entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                    entity_instance_id=self.alarm_instance_id,
                    severity=fm_constants.FM_ALARM_SEVERITY_MINOR,
                    reason_text="Kubernetes root CA update aborted, certificates may not be fully updated.",
                    # environmental
                    alarm_type=fm_constants.FM_ALARM_TYPE_5,
                    # unspecified-reason
                    probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_65,
                    proposed_repair_action="Fully update certificates by a new root CA update.",
                    service_affecting=False)
            self.fm_api.set_fault(fault)
            LOG.info("Kubernetes rootca update aborted")

        return KubeRootCAUpdate.convert_with_links(update)


class KubeRootCAHostUpdateController(rest.RestController):
    """REST controller for kube host root CA certificate."""

    def __init__(self, from_ihosts=False):
        self._from_ihosts = from_ihosts

    def _precheck_updatecerts(self, cluster_update, ihost):

        # Get all the host update states and ensure this phase of the
        # procedure is allowed to be executed.
        host_updates = pecan.request.dbapi.kube_rootca_host_update_get_list()
        if len(host_updates) == 0:
            raise wsme.exc.ClientSideError(_(
                    "kube-rootca-host-update phase update-certs rejected: "
                    "host update not started yet"))

        if cluster_update.state in [
                kubernetes.KUBE_ROOTCA_UPDATED_HOST_UPDATECERTS,
                kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS,
                kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS_FAILED]:
            if cluster_update.state == kubernetes.KUBE_ROOTCA_UPDATED_HOST_UPDATECERTS:
                # updatecerts phase completed
                raise wsme.exc.ClientSideError(_(
                        "kube-rootca-host-update phase update-certs rejected: "
                        "procedure phase already completed on cluster"))
            for host_update in host_updates:
                if host_update.state == kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS_FAILED:
                    # other host is on FAILED state
                    if host_update.host_id != ihost.id:
                        host_name = pecan.request.dbapi.ihost_get(
                            host_update.host_id).hostname
                        raise wsme.exc.ClientSideError(_(
                            "kube-rootca-host-update phase update-certs rejected: "
                            "procedure phase failed on host %s" % host_name))
                elif host_update.state == kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS:
                    # procedure already in progress in some host
                    host_name = pecan.request.dbapi.ihost_get(
                            host_update.host_id).hostname
                    raise wsme.exc.ClientSideError(_(
                        "kube-rootca-host-update phase update-certs rejected: "
                        "procedure phase in progress on host %s" % host_name))
                elif host_update.state == kubernetes.KUBE_ROOTCA_UPDATED_HOST_UPDATECERTS:
                    if host_update.host_id == ihost.id:
                        raise wsme.exc.ClientSideError(_(
                            "kube-rootca-host-update phase update-certs rejected: "
                            "procedure phase already completed on host %s"
                            % ihost.hostname))

        # if is the first host to be update on this phase we need
        # to assure that cluster_update state is what we expect
        # that is the state where all pods were restarted and running successfully
        else:
            if cluster_update.state != kubernetes.KUBE_ROOTCA_UPDATED_PODS_TRUSTBOTHCAS:
                raise wsme.exc.ClientSideError(_(
                        "kube-rootca-host-update phase update-certs rejected: "
                        "procedure phase not allowed when cluster update is "
                        "in state: %s (only allowed when in state: %s)."
                        % (cluster_update.state,
                        kubernetes.KUBE_ROOTCA_UPDATED_PODS_TRUSTBOTHCAS)))

    def _precheck_trustbothcas(self, cluster_update, ihost):
        """ Pre checking if conditions met for phase trust-both-cas """

        # Get all the host update state
        host_updates_temp = []
        host_updates_temp = \
            pecan.request.dbapi.kube_rootca_host_update_get_list()
        host_updates = [host_update for host_update in host_updates_temp
                        if host_update.state is not None]

        if len(host_updates) == 0:
            # No hosts start update yet
            if cluster_update.state not in \
                    [kubernetes.KUBE_ROOTCA_UPDATE_CERT_UPLOADED,
                     kubernetes.KUBE_ROOTCA_UPDATE_CERT_GENERATED]:
                raise wsme.exc.ClientSideError(_(
                    "kube-rootca-host-update phase trust-both-cas rejected: "
                    "No new certificate available."))
        else:
            # Not allowed if any host updates are in progress
            for host_update in host_updates:
                if host_update.state == \
                        kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS:
                    host_name = pecan.request.dbapi.ihost_get(
                                host_update.host_id).hostname
                    raise wsme.exc.ClientSideError(_(
                        "kube-rootca-host-update phase trust-both-cas rejected: "
                        "procedure phase in progress on host %s" % host_name))

            # Check if this host update ever started
            for host_update in host_updates:
                if ihost.id == host_update.host_id:
                    update_ever_started = host_update
                    break
            else:
                update_ever_started = None

            if update_ever_started is None:
                # Update never started on this host.
                # Allow start only if overall update state is correct.
                if cluster_update.state not in \
                        [kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS]:
                    raise wsme.exc.ClientSideError(_(
                        "kube-rootca-host-update phase trust-both-cas rejected: "
                        "procedure phase not allowed when cluster update is in "
                        "state: %s (only allowed when in state: %s)."
                        % (cluster_update.state,
                           kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)))
            else:
                # Update ever started on this host.
                if update_ever_started.state in \
                        [kubernetes.
                        KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS_FAILED]:
                    # Allowed retry only if update on this host ever failed
                    pass
                elif update_ever_started.state in \
                        [kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTBOTHCAS]:
                    # Return error indicating update on this host already
                    # completed.
                    raise wsme.exc.ClientSideError(_(
                        "kube-rootca-host-update phase trust-both-cas rejected: "
                        "procedure phase already completed on host %s"
                        % ihost.hostname))
                else:
                    # This could be the case where the cluster update already
                    # passes trust-both-cas (eg. in updateCerts phase), but
                    # client tries to make an update call of phase
                    # trust-both-cas.
                    raise wsme.exc.ClientSideError(_(
                        "kube-rootca-host-update phase trust-both-cas rejected: "
                        "procedure phase not allowed when cluster update is in "
                        "state: %s (only allowed when in state: %s)."
                        % (cluster_update.state,
                           kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)))

    def _precheck_trustnewca(self, cluster_update, ihost):

        # Get all the host update state
        host_updates = pecan.request.dbapi.kube_rootca_host_update_get_list()
        if len(host_updates) == 0:
            raise wsme.exc.ClientSideError(_(
                    "kube-rootca-host-update phase trust-new-ca "
                    "rejected: host update not started yet"))

        if cluster_update.state in [
                kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTNEWCA,
                kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTNEWCA,
                kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTNEWCA_FAILED]:
            if cluster_update.state == \
                    kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTNEWCA:
                # trustNewCA phase completed
                raise wsme.exc.ClientSideError(_(
                        "kube-rootca-host-update phase trust-new-ca "
                        "rejected: procedure phase already completed "
                        "on cluster"))
            for host_update in host_updates:
                if host_update.state == kubernetes.\
                        KUBE_ROOTCA_UPDATING_HOST_TRUSTNEWCA_FAILED:
                    # other host is on FAILED state
                    if host_update.host_id != ihost.id:
                        host_name = pecan.request.dbapi.ihost_get(
                            host_update.host_id).hostname
                        raise wsme.exc.ClientSideError(_(
                            "kube-rootca-host-update phase trust-new-ca "
                            "rejected: procedure phase failed on host %s"
                            % host_name))
                elif host_update.state == \
                        kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTNEWCA:
                    # procedure already in progress in some host
                    host_name = pecan.request.dbapi.ihost_get(
                            host_update.host_id).hostname
                    raise wsme.exc.ClientSideError(_(
                        "kube-rootca-host-update phase trust-new-ca "
                        "rejected: procedure phase in progress on "
                        "host %s" % host_name))
                elif host_update.state == \
                        kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTNEWCA:
                    if host_update.host_id == ihost.id:
                        raise wsme.exc.ClientSideError(_(
                            "kube-rootca-host-update phase trust-new-ca "
                            "rejected: procedure phase already "
                            "completed on host %s" % ihost.hostname))

        # If this is the first host to be update on this phase we need to ensure
        # that cluster_update state is what we expect, which is updateCerts
        # phase has completed successfully on all hosts.
        else:
            if cluster_update.state != \
                    kubernetes.KUBE_ROOTCA_UPDATED_HOST_UPDATECERTS:
                raise wsme.exc.ClientSideError(_(
                        "kube-rootca-host-update phase trust-new-ca "
                        "rejected: not allowed when cluster update "
                        "is in state: %s (only allowed when "
                        "in state: %s)." % (cluster_update.state,
                                            kubernetes.KUBE_ROOTCA_UPDATED_HOST_UPDATECERTS)))

    @cutils.synchronized(LOCK_KUBE_ROOTCA_CONTROLLER)
    @wsme_pecan.wsexpose(KubeRootCAHostUpdate, types.uuid, body=six.text_type)
    def post(self, host_uuid, body):
        """Update the kubernetes root CA certificate on this host"""

        phase = body['phase'].lower()

        # Check cluster update status
        try:
            update = pecan.request.dbapi.kube_rootca_update_get_one()
        except exception.NotFound:
            raise wsme.exc.ClientSideError(_(
                "kube-rootca-host-update phase %s rejected: "
                "No update in progress." % phase))

        # Check if the new root CA cert secret exists, in case the secret
        # is deleted unexpectly.
        kube_operator = kubernetes.KubeOperator()
        try:
            cert_secret = kube_operator.kube_get_secret(
                constants.KUBE_ROOTCA_SECRET,
                kubernetes.NAMESPACE_DEPLOYMENT,
            )
        except Exception:
            raise wsme.exc.ClientSideError(_(
                "kube-rootca-host-update phase %s rejected: failed "
                "to get new root CA cert secret from kubernetes."
                % phase))

        if cert_secret is None:
            raise wsme.exc.ClientSideError(_(
                "kube-rootca-host-update phase %s rejected: no new "
                "root CA cert found." % phase))

        try:
            ihost = pecan.request.dbapi.ihost_get(host_uuid)
        except exception.ServerNotFound:
            raise exception.SysinvException(_(
                "Invalid host_uuid %s" % host_uuid))

        if ihost.personality not in [constants.CONTROLLER, constants.WORKER]:
            raise exception.SysinvException(_(
                "Invalid personality %s to update kube certificate." %
                ihost.personality))

        if phase == constants.KUBE_CERT_UPDATE_TRUSTBOTHCAS:
            # kube root CA update on host phase trust-both-cas
            self._precheck_trustbothcas(update, ihost)
            update_state = kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS
        elif phase == constants.KUBE_CERT_UPDATE_UPDATECERTS:
            # kube root CA update on host phase updateCerts
            self._precheck_updatecerts(update, ihost)
            update_state = kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS
        elif phase == constants.KUBE_CERT_UPDATE_TRUSTNEWCA:
            # kube root CA update on host phase trustNewCA
            self._precheck_trustnewca(update, ihost)
            update_state = kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTNEWCA
        else:
            raise wsme.exc.ClientSideError(_(
                "kube-rootca-host-update rejected: not supported phase."))

        # Update the cluster update state
        c_values = dict()
        c_values['state'] = update_state
        c_update = pecan.request.dbapi.kube_rootca_update_get_one()
        pecan.request.dbapi.kube_rootca_update_update(c_update.id, c_values)

        # Create or update "update state" on this host
        h_values = dict()
        h_values['state'] = update_state
        h_values['effective_rootca_cert'] = c_update.from_rootca_cert
        h_values['target_rootca_cert'] = c_update.to_rootca_cert
        try:
            h_update = pecan.request.dbapi.kube_rootca_host_update_get_by_host(
                ihost.id)
            h_update = pecan.request.dbapi.kube_rootca_host_update_update(
                h_update.id, h_values)
        except exception.NotFound:
            h_update = pecan.request.dbapi.kube_rootca_host_update_create(
                ihost.id, h_values)

        if phase not in [constants.KUBE_CERT_UPDATE_TRUSTBOTHCAS,
                         constants.KUBE_CERT_UPDATE_UPDATECERTS,
                         constants.KUBE_CERT_UPDATE_TRUSTNEWCA]:
            raise exception.SysinvException(_(
                "Invalid phase %s to update kube certificate." %
                phase))

        # perform rpc to conductor to perform config apply
        pecan.request.rpcapi.kube_certificate_update_by_host(
            pecan.request.context, ihost, body['phase'])

        LOG.info("Kubernetes rootca update started on host: %s"
                 % ihost.hostname)

        return KubeRootCAHostUpdate.convert_with_links(h_update)
