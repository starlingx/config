# Copyright (c) 2020-2024 Wind River Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
import os
import re

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from dateutil.parser import parse
from kubernetes import __version__ as K8S_MODULE_VERSION
from kubernetes import client
from kubernetes import config
from kubernetes import watch
from kubernetes.client import Configuration
from kubernetes.client.rest import ApiException
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import base64
from oslo_utils import encodeutils
from six.moves.urllib.error import URLError

from sysinv.cert_mon import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import kubernetes as sys_kube

K8S_MODULE_MAJOR_VERSION = int(K8S_MODULE_VERSION.split('.')[0])
KUBE_CONFIG_PATH = '/etc/kubernetes/admin.conf'
LOG = log.getLogger(__name__)

SECRET_ACTION_TYPE_ADDED = 'ADDED'
SECRET_ACTION_TYPE_DELETED = 'DELETED'
SECRET_ACTION_TYPE_EXISTING = 'EXISTING'
SECRET_ACTION_TYPE_MODIFIED = 'MODIFIED'

CONF = cfg.CONF


class MonitorContext(object):
    """Context data for watches"""
    def __init__(self):
        self.dc_role = None
        self.kubernetes_namespace = None

    def initialize(self):
        self.dc_role = utils.get_dc_role()

    # Reuse cached tokens across all contexts
    # (i.e. all watches reuse these caches)

    @staticmethod
    def get_token():
        """Uses the cached local access token"""
        return utils.get_cached_token()

    @staticmethod
    def get_dc_token():
        """Uses the cached DC token for subcloud"""
        return utils.get_cached_dc_token()


class CertUpdateEventData(object):
    def __init__(self, event_data):
        raw_obj = event_data['raw_object']
        metadata = raw_obj['metadata']
        data = raw_obj['data']
        managed_fields = metadata['managedFields']
        self.action = event_data['type']
        self.secret_name = metadata['name']

        self.last_operation = ''
        self.last_operation_time = None
        if len(managed_fields) > 0:
            managed_field = managed_fields[0]
            self.last_operation = managed_field['operation']
            self.last_operation_time = parse(managed_field['time']).replace(tzinfo=None)

        creation_timestamp = metadata['creationTimestamp']
        self.creation_time = parse(creation_timestamp).replace(tzinfo=None)
        self.ca_crt = None
        self.tls_crt = None
        self.tls_key = None
        try:
            self.ca_crt = base64.decode_as_text(data['ca.crt']).strip() \
                if 'ca.crt' in data else ''
            self.tls_crt = base64.decode_as_text(data['tls.crt']).strip() \
                if 'tls.crt' in data else ''
            self.tls_key = base64.decode_as_text(data['tls.key']).strip() \
                if 'tls.key' in data else ''
        except TypeError:
            LOG.error('Invalid secret data.')
            if self.ca_crt is None:
                LOG.error('ca.crt = %s' % data['ca.crt'])
            elif self.tls_crt is None:
                LOG.error('tls.crt = %s' % data['tls.crt'])
            else:
                LOG.error('tls.key = %s' % data['tls.key'])

    def equal(self, obj):
        return self.action == obj.action and \
               self.secret_name == obj.secret_name and \
               self.ca_crt == obj.ca_crt and \
               self.tls_crt == obj.tls_crt and \
               self.tls_key == obj.tls_key and \
               self.creation_time == obj.creation_time and \
               self.last_operation == obj.last_operation and \
               self.last_operation_time == obj.last_operation_time

    def __str__(self):
        format = 'action %s (%s)\nhash: ca_crt: %s tls_crt %s tls_key %s\n' \
                 'created at %s last operation %s last update at %s'
        return format % (
            self.action, self.secret_name, self.hash(self.ca_crt),
            self.hash(self.tls_crt), self.hash(self.tls_key),
            self.creation_time, self.last_operation,
            self.last_operation_time)

    @staticmethod
    def hash(data):
        m = hashlib.md5()
        m.update(encodeutils.safe_encode(data))
        return m.hexdigest()


class CertUpdateEvent(object):
    def __init__(self, listener, event_data):
        self.listener = listener
        self.event_data = event_data
        self.number_of_reattempt = 0

    def run(self):
        try:
            self.listener.notify_changed(self.event_data)
        except Exception as e:
            LOG.error('%s update failed [attempt #%s]: %s, event: %s' %
                      (self.__class__.__name__, self.number_of_reattempt, e,
                       self.event_data))
            if not isinstance(e, URLError):
                LOG.exception(e)
            self.number_of_reattempt = self.number_of_reattempt + 1
            return False
        else:
            return True

    def get_id(self):
        """
        Return the key id for the task.
        A task will be replaced with a newer task with the same id
        when it is in a queue (for reattempting)
        """
        return 'cert-update: %s' % self.event_data.secret_name

    def failed(self):
        self.listener.action_failed(self.event_data)


class CertWatcherListener(object):
    def __init__(self, context):
        self.context = context

    def notify_changed(self, event_data):
        if self.check_filter(event_data):
            self.do_action(event_data)
            return True
        else:
            return False

    def check_filter(self, event_data):
        return False

    def do_action(self, event_data):
        """
        event with event_data will be refired up to max reattempt
        times if do_action fails (raise any exception).
        do_action routine needs to be able to reattempt
        Note that a listener servers multiple events (with
        different event signatures) at the same time. do_action must
        be stateless.
        """
        pass

    def action_failed(self, event_data):
        """
        fired when the action failed after max reattempt or
        reattempt aborting (service stops)
        Note that the action could be replaced with a newer
        action with the same signature which means action_failed
        is not fired while do_action has not succeed.
        """
        LOG.warn('Operation %s has failed' % event_data)


class CertWatcher(object):
    def __init__(self):
        self.listeners = []
        self.namespace = None
        self.context = MonitorContext()
        self.last_resource_version = None
        self.is_check_existing_certificates = True

    def register_listener(self, listener):
        return self.listeners.append(listener)

    def _update_latest_resource_version(self, cc_api):
        """Retrieve current resource_version for use in watch (re-)registration

        Note from the API:
        >  The ResourceVersion of the top-level list is what should
        >  be used when starting a watch to observe events occurring
        >  after that list was populated.

        This method retrieves this top-level resource version.
        """
        try:
            response = cc_api.list_namespaced_secret(self.namespace)
            self.last_resource_version = \
                response.metadata.resource_version
            LOG.debug(
                ("%s: update last_resource_version: %s "
                 "for namespace: %s")
                % (self.__class__.__name__, self.last_resource_version, self.namespace))
        except Exception:
            self.last_resource_version = None
            LOG.exception(
                "Failed to retrieve resource_version, namespace: %s"
                % self.namespace)

    def handle_secret_event(self, event, on_success, on_error):
        """Handles an individual secret event and calls appropriate CertWatcherListener
        to take action on that event e.g. install the certificate
        :param event: an event object wrapping a kubernetes secret
        :param on_success: function to be called on successful execution
        :param on_error: function to be called on failed execution
        """
        LOG.debug('%s watch received new event: %s, %s'
                  % (self.__class__.__name__, type(event.get('object')), event))
        event_type = event.get('type')
        if not event_type:
            LOG.error(("%s: received unexpected event on watch, "
                       "restarting it: %s")
                      % (self.__class__.__name__, event))
            self.last_resource_version = None
            raise exception.UnexpectedEvent(event=event)
        # Note: we should no longer receive event_type == 'ERROR'
        # (see client code - it now raises an ApiException):
        if event_type == 'ERROR':
            # Unexpected error. Restart without resourceVersion.
            self.last_resource_version = None
            LOG.error(
                ("%s: received unexpected type=ERROR event on watch, "
                 "restarting it: %s") % (self.__class__.__name__, event))
            raise exception.UnexpectedEvent(event=event)

        event_data = CertUpdateEventData(event)

        for listener in self.listeners:
            update_event = CertUpdateEvent(listener, event_data)

            try:
                if listener.notify_changed(event_data):
                    on_success(update_event.get_id())
            except Exception as e:
                LOG.error("%s: monitor action in namespace=%s failed: %s,  %s"
                          % (self.__class__.__name__, self.namespace, event_data, e))
                if not isinstance(e, URLError):
                    LOG.exception(e)
                on_error(update_event)

    def _get_kubernetes_core_client(self):
        """Returns the kubernetes CoreV1Api according to k8s version"""
        config.load_kube_config(KUBE_CONFIG_PATH)
        if K8S_MODULE_MAJOR_VERSION < 12:
            c = Configuration()
        else:
            c = Configuration().get_default_copy()
        c.verify_ssl = True
        Configuration.set_default(c)
        return client.CoreV1Api()

    def start_watch(self, on_success, on_error):
        """Monitors events on secrets in the watched namespaces (CertWatcher.namespace)
        and calls handle_secret_event to process each new event.
        :param on_success: function to be called on successful execution
        :param on_error: function to be called on failed execution
        """
        ccApi = self._get_kubernetes_core_client()
        kube_watch = watch.Watch()

        # First Checks for existing certificates in the watched namespace.
        # This allows for certificates existing before cert-mon startup to get detected
        if self.is_check_existing_certificates:
            try:
                response = ccApi.list_namespaced_secret(self.namespace, _preload_content=False)
                secrets = json.loads(response.read())
                for secret in secrets['items']:
                    secret_event = {
                        "type": SECRET_ACTION_TYPE_EXISTING,
                        "object": secret,
                        "raw_object": secret
                    }
                    self.handle_secret_event(secret_event, on_success, on_error)
                self.is_check_existing_certificates = False
            except Exception as e:
                LOG.exception(
                    ("%s: Unexpected error occurred during the initial check for existing certificates: %s"
                     % (self.__class__.__name__, e)))
                raise

        kwargs = {'namespace': self.namespace}
        self._update_latest_resource_version(ccApi)
        if self.last_resource_version is not None:
            # Include resource version in call to watch. Ensures we start watch
            # from same point of expiry. Reference:
            # https://github.com/kubernetes-client/python-base/blob/
            # b4d3aad42dc23e7a6c0e5c032691f8dc385a786c/watch/watch.py#L119
            kwargs['resource_version'] = self.last_resource_version

        LOG.info("%s: watching secrets in '%s' using resource version: %s"
                 % (self.__class__.__name__,
                    self.namespace,
                    self.last_resource_version))

        try:
            for secret_event in kube_watch.stream(ccApi.list_namespaced_secret, **kwargs):
                try:
                    self.handle_secret_event(secret_event, on_success, on_error)
                except exception.UnexpectedEvent:
                    kube_watch.stop()
                    return
        except ApiException as ex:
            if ex.status == 410:
                # Expired watch. Retrieve current resource_version for use
                # in watch re-registration, as per client API instructions
                self._update_latest_resource_version(ccApi)

                LOG.info(("%s: watch expired in '%s', "
                          "restarting with resource_version: %s")
                         % (self.__class__.__name__, self.namespace,
                            self.last_resource_version))
            else:
                # Unexpected error. Restart without resourceVersion.
                self.last_resource_version = None
                LOG.exception(
                    ("%s: received unexpected ApiException on watch, "
                     "restarting it") % (self.__class__.__name__))
            kube_watch.stop()
            return
        except Exception as e:
            kube_watch.stop()
            LOG.exception(
                "%s: Unexpected error occurred: %s" % (self.__class__.__name__, e))
            raise


class DC_CertWatcher(CertWatcher):
    def __init__(self):
        super(DC_CertWatcher, self).__init__()

    def initialize(self, audit_subcloud, invalid_deploy_states):
        self.context.initialize()
        dc_role = self.context.dc_role
        LOG.info('DC role: %s' % dc_role)

        if dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            ns = utils.CERT_NAMESPACE_SUBCLOUD_CONTROLLER
        elif dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            ns = utils.CERT_NAMESPACE_SYS_CONTROLLER
        else:
            ns = ''
        self.namespace = ns
        self.context.kubernetes_namespace = ns
        self.register_listener(AdminEndpointRenew(self.context))
        if dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            self.register_listener(
                DCIntermediateCertRenew(
                    self.context, audit_subcloud, invalid_deploy_states
                )
            )
            self.register_listener(RootCARenew(self.context))


class SystemLocalCACert_CertWatcher(CertWatcher):
    def __init__(self):
        super(SystemLocalCACert_CertWatcher, self).__init__()

    def initialize(self):
        self.context.initialize()

        platcert_ca_ns = constants.CERT_NAMESPACE_PLATFORM_CA_CERTS
        LOG.info('setting ns for system-local-ca RCA cert : %s & registering listener'
                 % platcert_ca_ns)
        self.namespace = constants.CERT_NAMESPACE_PLATFORM_CA_CERTS
        self.context.kubernetes_namespace = platcert_ca_ns
        self.register_listener(SystemLocalCACertRenew(self.context))


class RestApiCert_CertWatcher(CertWatcher):
    def __init__(self):
        super(RestApiCert_CertWatcher, self).__init__()

    def initialize(self):
        self.context.initialize()

        platcert_ns = constants.CERT_NAMESPACE_PLATFORM_CERTS
        LOG.info('setting ns for restapi cert : %s & registering listener' % platcert_ns)
        self.namespace = platcert_ns
        self.context.kubernetes_namespace = platcert_ns
        self.register_listener(RestApiCertRenew(self.context))


class RegistryCert_CertWatcher(CertWatcher):
    def __init__(self):
        super(RegistryCert_CertWatcher, self).__init__()

    def initialize(self):
        self.context.initialize()

        platcert_ns = constants.CERT_NAMESPACE_PLATFORM_CERTS
        LOG.info('setting ns for registry cert : %s & registering listener' % platcert_ns)
        self.namespace = platcert_ns
        self.context.kubernetes_namespace = platcert_ns
        self.register_listener(RegistryCertRenew(self.context))


class OpenldapCert_CertWatcher(CertWatcher):
    def __init__(self):
        super(OpenldapCert_CertWatcher, self).__init__()

    def initialize(self):
        self.context.initialize()

        platcert_ns = constants.CERT_NAMESPACE_PLATFORM_CERTS
        LOG.info('setting ns for Openldap cert : %s & registering listener' % platcert_ns)
        self.namespace = platcert_ns
        self.context.kubernetes_namespace = platcert_ns
        self.register_listener(OpenldapCertRenew(self.context))


class CertificateRenew(CertWatcherListener):
    def __init__(self, context):
        super(CertificateRenew, self).__init__(context)

    def certificate_is_ready(self, event_data):
        supported_actions = \
            (SECRET_ACTION_TYPE_ADDED, SECRET_ACTION_TYPE_MODIFIED, SECRET_ACTION_TYPE_EXISTING)
        if event_data.action in supported_actions and event_data.ca_crt \
                and event_data.tls_crt and event_data.tls_key:
            return True
        else:
            return False

    def recreate_secret(self, event_data):
        """
        It is a workaround, delete the secret for cert-manager to recreate it with
        new private key
        """
        kube_op = sys_kube.KubeOperator()
        kube_op.kube_delete_secret(event_data.secret_name, self.context.kubernetes_namespace)
        LOG.info('Recreate secret %s:%s'
                 % (self.context.kubernetes_namespace, event_data.secret_name))

    def update_certificate(self, event_data):
        pass

    def do_action(self, event_data):
        LOG.info('%s do_action: %s' % (self.__class__.__name__, event_data))
        # here is a workaround for replacing private key when renewing certficate.
        # when secret is deleted, the cert-manager will recreate the secret with
        # new private key.
        # a normal renewing scenario is
        #      secret updated -> delete secret -> secret added -> secret updated
        # the first secret updated is triggered by the cert-manager renewing the cert
        # the operation does not include rekey. Then the secret is deleted so that a new
        # certificate is created with new key. Given the fact that cert-manager
        # creates new certificate secret reasonably quickly, we assume the secret update
        # on a recently created secret has new key. (normal scenario certificate renew
        # interval is far longer than 1 hour (in days). cert-manager typically completes
        # processing certificate signing request far less than 1 sec (in ms) when process
        # a single CSR. When DC root CA certificate is renewed, a large number of CSRs
        # are triggered to renew all intermediate CA certificates, cert-manager is
        # observed to have significant delay of processing CSRs. Setting the delay
        # threshold to 1 hour can support very large number (1000s) of concurrent CSR
        # requests with proper hardware and software configuration.
        reasonable_delay = 3600  # 1 hour
        delta = (event_data.last_operation_time - event_data.creation_time).total_seconds()
        if event_data.action == SECRET_ACTION_TYPE_MODIFIED and delta > reasonable_delay:
            self.recreate_secret(event_data)
        else:
            self.update_certificate(event_data)


class AdminEndpointRenew(CertificateRenew):
    def __init__(self, context):
        super(AdminEndpointRenew, self).__init__(context)
        role = self.context.dc_role
        if role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            self.secret_name = constants.DC_ADMIN_ENDPOINT_SECRET_NAME
        elif role == constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            self.secret_name = constants.SC_ADMIN_ENDPOINT_SECRET_NAME
        else:
            self.secret_name = None

    def check_filter(self, event_data):
        if self.secret_name == event_data.secret_name:
            return self.certificate_is_ready(event_data)
        else:
            return False

    def update_certificate(self, event_data):
        token = self.context.get_token()

        role = self.context.dc_role
        utils.update_admin_ep_cert(token, event_data.ca_crt, event_data.tls_crt,
                                   event_data.tls_key)

        # In subclouds, it was observed that sometimes old ICA was used
        # to sign adminep-cert. Here we run a verification to confirm that
        # the chain is valid & delete secret if chain fails
        if role == constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            utils.verify_adminep_cert_chain()


class DCIntermediateCertRenew(CertificateRenew):
    def __init__(self, context, audit_subcloud, invalid_deploy_states):
        super(DCIntermediateCertRenew, self).__init__(context)
        self.invalid_deploy_states = invalid_deploy_states
        self.secret_pattern = re.compile('-adminep-ca-certificate$')
        self.audit_subcloud = audit_subcloud

    def check_filter(self, event_data):
        search_result = self.secret_pattern.search(event_data.secret_name)
        if search_result and search_result.start() > 0:
            # Ensure subcloud is in a valid deploy-status and online (watch
            # events can fire for secrets before the subcloud first comes online)
            subcloud_name = self._get_subcloud_name(event_data)
            try:
                (
                    subcloud_valid_state,
                    availability_status,
                    deploy_status,
                ) = utils.query_subcloud_online_with_deploy_state(
                    subcloud_name,
                    invalid_deploy_states=self.invalid_deploy_states,
                    token=self.context.get_token(),
                )
                if not subcloud_valid_state:
                    LOG.info(
                        "%s check_filter: subcloud %s is ignored, "
                        "availability=%s, deploy_status: %s",
                        self.__class__.__name__,
                        subcloud_name,
                        availability_status,
                        deploy_status,
                    )
                    return False
            except Exception:
                LOG.exception(
                    "Failed to check subcloud availability: %s" % subcloud_name
                )
                return False
            return self.certificate_is_ready(event_data)
        else:
            return False

    def _get_subcloud_name(self, event_data):
        m = self.secret_pattern.search(event_data.secret_name)
        return event_data.secret_name[0:m.start()]

    def update_certificate(self, event_data):
        subcloud_name = self._get_subcloud_name(event_data)
        LOG.info('update_certificate: subcloud %s %s', subcloud_name,
                 event_data)

        token = self.context.get_dc_token()

        subcloud_sysinv_url = utils.SubcloudSysinvEndpointCache.get_endpoint(
            subcloud_name, token
        )

        utils.update_subcloud_ca_cert(token,
                                      subcloud_name,
                                      subcloud_sysinv_url,
                                      event_data.ca_crt,
                                      event_data.tls_crt,
                                      event_data.tls_key)

        self.audit_subcloud(subcloud_name)

    def action_failed(self, event_data):
        sc_name = self._get_subcloud_name(event_data)
        LOG.info('Attempt to update intermediate CA cert for %s has failed' %
                 sc_name)

        # verify subcloud is under managed and online
        token = self.context.get_token()
        sc = utils.get_subcloud(token, sc_name)
        if not sc:
            LOG.error('Cannot find subcloud %s' % sc_name)
        else:
            LOG.info('%s is %s %s. Software version %s' %
                     (sc_name,
                      sc['management-state'],
                      sc['availability-status'],
                      sc['software-version']))

            if sc['management-state'] == utils.MANAGEMENT_MANAGED:
                # don't do anything until subcloud managed
                for status in sc['endpoint_sync_status']:
                    if status['endpoint_type'] == utils.ENDPOINT_TYPE_DC_CERT and \
                            status['sync_status'] != utils.SYNC_STATUS_OUT_OF_SYNC:
                        LOG.info('Updating %s intermediate CA has failed. Mark %s '
                                 'as dc-cert %s' % (sc_name, sc_name,
                                                    utils.SYNC_STATUS_OUT_OF_SYNC))
                        # update subcloud to dc-cert out-of-sync b/c last intermediate
                        # CA cert was not updated successfully
                        # an audit (default within 24 hours) will pick up and reattempt
                        dc_token = self.context.get_dc_token()
                        utils.update_subcloud_status(dc_token, sc_name,
                                                     utils.SYNC_STATUS_OUT_OF_SYNC)
                        break


class RootCARenew(CertificateRenew):
    def __init__(self, context):
        super(RootCARenew, self).__init__(context)
        self.secrets_to_recreate = []

    def notify_changed(self, event_data):
        if self.check_filter(event_data):
            self.do_action(event_data)
        else:
            return False

    def check_filter(self, event_data):
        if self.context.dc_role != \
            constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER or \
                event_data.secret_name != constants.DC_ADMIN_ROOT_CA_SECRET_NAME or \
                not self.certificate_is_ready(event_data):
            return False

        # check against current root CA cert to see if it is updated
        if not os.path.isfile(constants.DC_ROOT_CA_CERT_PATH):
            return True

        with open(constants.DC_ROOT_CA_CERT_PATH, 'r') as f:
            crt = f.read()

        m = hashlib.md5()
        m.update(encodeutils.safe_encode(event_data.ca_crt))
        md5sum = m.hexdigest()

        if crt.strip() != event_data.ca_crt:
            LOG.info('%s check_filter[%s]: root ca certificate has changed. md5sum %s'
                     % (self.__class__.__name__, event_data.secret_name, md5sum))
            # a root CA update, all required secrets needs to be recreated
            self.secrets_to_recreate = []
            return True
        else:
            LOG.info('%s check_filter[%s]: root ca certificate remains the same. md5sum %s'
                     % (self.__class__.__name__, event_data.secret_name, md5sum))
            return False

    def do_action(self, event_data):
        LOG.info('%s do_action: %s' % (self.__class__.__name__, event_data))
        if len(self.secrets_to_recreate) == 0:
            self.update_certificate(event_data)

        self.recreate_secrets()

    def action_failed(self, event_data):
        LOG.Error('Updating root CA certificate has failed.')
        if len(self.secrets_to_recreate) > 0:
            LOG.Error('%s are not refreshed' % self.secrets_to_recreate)
            self.secrets_to_recreate = []

    def update_certificate(self, event_data):
        # currently the root CA cert renewal does not replace private key
        # This is not ideal it is caused by a cert-manager issue.
        # The root CA cert is to be updated by when the admin endpoint
        # certification is updated
        # https://github.com/jetstack/cert-manager/issues/2978
        self.secrets_to_recreate = self.get_secrets_to_recreate()
        LOG.info('Secrets to be recreated %s' % self.secrets_to_recreate)

    @staticmethod
    def get_secrets_to_recreate():
        secret_names = list(utils.get_subcloud_secrets().values())
        secret_names.insert(0, constants.DC_ADMIN_ENDPOINT_SECRET_NAME)
        return secret_names

    def recreate_secrets(self):
        kube_op = sys_kube.KubeOperator()
        secret_list = self.secrets_to_recreate[:]
        for secret in secret_list:
            try:
                LOG.info('Recreate %s:%s' % (utils.CERT_NAMESPACE_SYS_CONTROLLER, secret))
                kube_op.kube_delete_secret(secret, utils.CERT_NAMESPACE_SYS_CONTROLLER)
            except Exception as e:
                LOG.error('Deleting secret %s:%s. Error %s' %
                          (utils.CERT_NAMESPACE_SYS_CONTROLLER, secret, e))
            else:
                self.secrets_to_recreate.remove(secret)

        if len(self.secrets_to_recreate) > 0:
            # raise exception to keep reattempting
            raise Exception('Some secrets were not recreated successfully')


class TrustedCARenew(CertificateRenew):
    """Handles a renew event for a certificate that must be installed as a trusted platform cert.
    """

    def __init__(self, context, secret_name):
        super(TrustedCARenew, self).__init__(context)
        self.secret_name = secret_name
        LOG.info('%s init with secretname: %s' % (self.__class__.__name__, self.secret_name))

    def check_filter(self, event_data):
        LOG.debug('%s: Received event_data %s' % (self.secret_name, event_data))
        if self.secret_name == event_data.secret_name:
            LOG.info('%s check_filter[%s], proceed on event_data: %s'
                     % (self.__class__.__name__, self.secret_name, event_data))
            return self.certificate_is_ready(event_data)
        else:
            return False

    def do_action(self, event_data):
        LOG.info('%s do_action: %s' % (self.__class__.__name__, event_data))
        self.update_certificate(event_data)

    def install_ca_certificate(self,
                               event_data,
                               cert_type,
                               force=False):
        """Install CA certificate stored in a secret

        Save the CA certificate from the secret into a PEM file and send it to the
        platform to be installed. If force=True, the platform semantic checks will be
        skipped.

        :param event_data: the event_data that triggered this renew
        :param cert_type: the type of the certificate that is being updated
        :param force: whether to bypass semantic checks and force the update,
            defaults to False
        """
        token = self.context.get_token()
        try:
            cert_to_be_installed = x509.load_pem_x509_certificate(event_data.ca_crt.encode(),
                                                                  default_backend())
            installed_certificates = utils.list_platform_certificates(token)

            for certificate in installed_certificates['certificates']:
                if certificate['certtype'] != cert_type:
                    continue

                if str(cert_to_be_installed.serial_number) in certificate['signature']:
                    LOG.info('Certificate %s is already installed. Skipping installation.' %
                             certificate['signature'])
                    return

            pem_file_path = utils.update_pemfile(event_data.ca_crt, "")
            utils.update_platform_cert(token, cert_type, pem_file_path, force)

        except Exception as e:
            LOG.error("Error when updating certificates: %s" % e)
            raise


class PlatformCertRenew(CertificateRenew):
    """Handles a renew event for a certificate that must be installed as a platform cert.
    """

    def __init__(self, context, secret_name):
        super(PlatformCertRenew, self).__init__(context)
        self.secret_name = secret_name
        LOG.info('%s init with secretname: %s' % (self.__class__.__name__, self.secret_name))

    def check_filter(self, event_data):
        LOG.debug('%s: Received event_data %s' % (self.secret_name, event_data))
        if self.secret_name == event_data.secret_name:
            LOG.info('%s check_filter[%s], proceed on event_data: %s'
                     % (self.__class__.__name__, self.secret_name, event_data))
            return self.certificate_is_ready(event_data)
        else:
            return False

    @utils.lockutils.synchronized(utils.CERT_INSTALL_LOCK_NAME)
    def update_platform_certificate(self, event_data, cert_type, force=False):
        """Update a platform certificate

        Save the certificate and key from the secret into a PEM file and send it to the
        platform to be installed. If force=True, the platform semantic checks will be
        skipped.

        :param event_data: the event_data that triggered this renew
        :param cert_type: the type of the certificate that is being updated
        :param force: whether to bypass semantic checks and force the update,
            defaults to False
        """
        token = self.context.get_token()
        try:
            cert_to_be_installed = x509.load_pem_x509_certificate(event_data.tls_crt.encode(),
                                                                  default_backend())

            installed_certificates = utils.list_platform_certificates(token)

            for certificate in installed_certificates['certificates']:
                if str(cert_to_be_installed.serial_number) in certificate['signature']:
                    LOG.info('Certificate %s is already installed. Skipping installation.' %
                             certificate['signature'])
                    return

            pem_file_path = utils.update_pemfile(event_data.tls_crt, event_data.tls_key)
            utils.update_platform_cert(token, cert_type, pem_file_path, force)

        except Exception as e:
            LOG.error("Error when updating certificates: %s" % e)
            raise


class SystemLocalCACertRenew(TrustedCARenew):
    def __init__(self, context):
        super(SystemLocalCACertRenew, self).__init__(context, constants.LOCAL_CA_SECRET_NAME)

    def update_certificate(self, event_data):
        LOG.info('SystemLocalCACertRenew: Secret changes detected. Initiating CA certificate install')
        self.install_ca_certificate(event_data,
                                    constants.CERT_MODE_SSL_CA,
                                    force=True)


class RestApiCertRenew(PlatformCertRenew):
    def __init__(self, context):
        super(RestApiCertRenew, self).__init__(context, constants.RESTAPI_CERT_SECRET_NAME)

    def update_certificate(self, event_data):
        LOG.info('RestApiCertRenew: Secret changes detected. Initiating certificate update')
        self.update_platform_certificate(event_data, constants.CERT_MODE_SSL, force=True)


class RegistryCertRenew(PlatformCertRenew):
    def __init__(self, context):
        super(RegistryCertRenew, self).__init__(context, constants.REGISTRY_CERT_SECRET_NAME)

    def update_certificate(self, event_data):
        LOG.info('RegistryCertRenew: Secret changes detected. Initiating certificate update')

        self.update_platform_certificate(event_data, constants.CERT_MODE_DOCKER_REGISTRY, force=True)


class OpenldapCertRenew(PlatformCertRenew):
    def __init__(self, context):
        super(OpenldapCertRenew, self).__init__(context, constants.OPENLDAP_CERT_SECRET_NAME)

    def update_certificate(self, event_data):
        LOG.info('OpenldapCertRenew: Secret changes detected. Initiating certificate update')

        self.update_platform_certificate(event_data, constants.CERT_MODE_OPENLDAP, force=True)
