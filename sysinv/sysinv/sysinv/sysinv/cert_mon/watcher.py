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
# Copyright (c) 2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
from datetime import datetime
from dateutil.parser import parse
from kubernetes import client
from kubernetes import watch
from kubernetes.client import Configuration
from kubernetes import config
from oslo_config import cfg
from oslo_log import log

from sysinv.cert_mon import utils
from sysinv.common import constants
from sysinv.common import kubernetes as sys_kube

KUBE_CONFIG_PATH = '/etc/kubernetes/admin.conf'
LOG = log.getLogger(__name__)

CERT_NAMESPACE_SYS_CONTROLLER = 'dc-cert'
CERT_NAMESPACE_SUBCLOUD_CONTROLLER = 'sc-cert'

SECRET_ACTION_TYPE_ADDED = 'ADDED'
SECRET_ACTION_TYPE_DELETED = 'DELETED'
SECRET_ACTION_TYPE_MODIFIED = 'MODIFIED'
CONF = cfg.CONF


class MonitorContext(object):
    def __init__(self):
        self.system = None
        self.dc_role = None
        self._token = None
        self.kubernete_namespace = None

    def initialize(self):
        utils.init_keystone_auth_opts()
        token = self.get_token()
        service_type = 'platform'
        service_name = 'sysinv'
        sysinv_url = token.get_service_internal_url(service_type,
                                                    service_name)
        api_cmd = sysinv_url + '/isystems'
        res = utils.rest_api_request(token, "GET", api_cmd)['isystems']
        if len(res) == 1:
            self.system = res[0]
            self.dc_role = self.system['distributed_cloud_role']
            LOG.info('Result %s' % self.system)
        else:
            raise Exception('Failed to access system data')

    def get_token(self):
        if not self._token or self._token.is_expired():
            self._token = utils.get_token()
        return self._token


class CertUpdateEventData(object):
    def __init__(self, event_data):
        raw_obj = event_data['raw_object']
        metadata = raw_obj['metadata']
        data = raw_obj['data']
        managed_fields = metadata['managedFields']
        self.action = event_data['type']
        self.cert_name = metadata['name']

        self.last_operation = ''
        self.last_operation_time = None
        if len(managed_fields) > 0:
            managed_field = managed_fields[0]
            self.last_operation = managed_field['operation']
            self.last_operation_time = parse(managed_field['time']).replace(tzinfo=None)

        creation_timestamp = metadata['creationTimestamp']
        self.creation_time = parse(creation_timestamp).replace(tzinfo=None)
        self.ca_crt = data['ca.crt'] if 'ca.crt' in data else ''
        self.tls_crt = data['tls.crt'] if 'tls.crt' in data else ''
        self.tls_key = data['tls.key'] if 'tls.key' in data else ''

    def equal(self, obj):
        return self.action == obj.action and \
               self.cert_name == obj.cert_name and \
               self.ca_crt == obj.ca_crt and \
               self.tls_crt == obj.tls_crt and \
               self.creation_time == obj.creation_time and \
               self.last_operation == obj.last_operation and \
               self.last_operation_time == obj.last_operation_time

    def __str__(self):
        format = 'action %s (%s)\nhash: ca_crt: %s tls_crt %s tls_key %s\n' \
                 'created at %s last operation %s last update at %s'
        return format % \
               (
                   self.action, self.cert_name, self.hash(self.ca_crt),
                   self.hash(self.tls_crt), self.hash(self.tls_key),
                   self.creation_time, self.last_operation,
                   self.last_operation_time)

    @staticmethod
    def hash(data):
        import hashlib
        m = hashlib.md5()
        m.update(data)
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
            LOG.error('%s Reattempt %s %s failed. %s' %
                      (self.number_of_reattempt, self.event_data.action,
                       self.event_data.cert_name, e))
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
        return 'cert-update: %s' % self.event_data.cert_name


class CertWatcherListener(object):
    def __init__(self, context):
        self.context = context

    def notify_changed(self, event_data):
        if self.check_filter(event_data):
            self.do_action(event_data)

    def check_filter(self, event_data):
        return False

    def do_action(self, event_data):
        pass


class CertWatcher(object):
    def __init__(self):
        self.listeners = []
        self.namespace = None
        self.context = MonitorContext()

    def register_listener(self, listener):
        return self.listeners.append(listener)

    def start_watch(self, func):
        config.load_kube_config(KUBE_CONFIG_PATH)
        c = Configuration()
        c.verify_ssl = True
        Configuration.set_default(c)
        ccApi = client.CoreV1Api()
        w = watch.Watch()

        LOG.debug('Monitor secrets in %s' % self.namespace)
        for item in w.stream(ccApi.list_namespaced_secret, namespace=self.namespace):
            event_data = CertUpdateEventData(item)
            for listener in self.listeners:
                try:
                    listener.notify_changed(event_data)
                except Exception as e:
                    LOG.error(e)
                    reattempt = CertUpdateEvent(event_data, listener)
                    func(reattempt)

    def initialize(self):
        self.context.initialize()
        role = self.context.dc_role
        LOG.info('dc role: %s' % role)
        if role == constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            ns = CERT_NAMESPACE_SUBCLOUD_CONTROLLER
        elif role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            ns = CERT_NAMESPACE_SYS_CONTROLLER
        else:
            ns = ''
        self.namespace = ns
        self.context.kubernete_namespace = ns
        self.register_listener(AdminEndpointRenew(self.context))


class AdminEndpointRenew(CertWatcherListener):
    def __init__(self, context):
        super(AdminEndpointRenew, self).__init__(context)
        role = self.context.dc_role
        if role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            self.cert_name = "dc-adminep-certificate"
        elif role == constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            self.cert_name = "sc-adminep-certificate"
        else:
            self.cert_name = None

        self.monitor_start = datetime.now()

    def check_filter(self, event_data):
        if self.cert_name != event_data.cert_name:
            return False

        if event_data.action in (SECRET_ACTION_TYPE_ADDED, SECRET_ACTION_TYPE_MODIFIED)\
                and event_data.ca_crt and event_data.tls_crt and \
                event_data.tls_key:
            return True
        else:
            return False

    def do_action(self, event_data):
        LOG.info('%s' % event_data)
        # here is a workaround for replacing private key when renewing certficate.
        # when secret is deleted, the cert-manager will recreate the secret with
        # new private key.
        # a normal renewing scenario is
        #      secret updated -> delete secret -> secret added -> secret updated
        # the first secret updated is triggered by the cert-manager renewing the cert
        # the operation does not include rekey. Then the secret is deleted so that a new
        # certificate is created with new key. Giving the fact that cert-manager
        # creates new certificate secret reasonably quickly, we assume the secret update
        # on a recently created secret has new key. (normal scenario certificate renew
        # interval is far longer than 1 minute (in days or at least hours).
        # In the very rare event if cert-manager creates new secret really slowly for a
        # short period of time (takes more than 1 minutes to update the secret)
        # the secret will be recreated again. This is going to be recovered when
        # cert-manager normal behave is restored.
        reasonable_dalay = 60  # assuming recreating secret takes less then 60 seconds
        delta = (event_data.last_operation_time - event_data.creation_time).total_seconds()
        if event_data.action == SECRET_ACTION_TYPE_MODIFIED and delta > reasonable_dalay:
            kube_op = sys_kube.KubeOperator()
            kube_op.kube_delete_secret(event_data.cert_name, self.context.kubernete_namespace)
            LOG.info('Delete secret %s:%s' % (self.context.kubernete_namespace, event_data.cert_name))
        else:
            token = self.context.get_token()
            utils.update_admin_ep_cert(token, event_data.ca_crt, event_data.tls_crt,
                                       event_data.tls_key)
