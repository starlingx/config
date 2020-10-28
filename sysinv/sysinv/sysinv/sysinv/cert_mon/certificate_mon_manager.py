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
import base64
from eventlet import greenthread
import greenlet
from oslo_config import cfg
from oslo_log import log
from oslo_service import periodic_task
import time

from sysinv.cert_mon import watcher
from sysinv.cert_mon import utils
from sysinv.common import constants
from sysinv.common import utils as cutils

LOG = log.getLogger(__name__)
TASK_NAME_PAUSE_AUDIT = 'pause'

cert_mon_opts = [
    cfg.IntOpt('audit_interval',
               default=86400,  # 24 hours
               help='Interval to run certificate audit'),
    cfg.IntOpt('retry_interval',
               default=10 * 60,  # retry every 10 minutes
               help='interval to reattempt accessing external system '
                    'if failure occurred'),
    cfg.IntOpt('max_retry',
               default=14,  # retry 14 times to give at least 2 hours to recover
               help='interval to reattempt accessing external system '
                    'if failure occurred'),
]

CONF = cfg.CONF
CONF.register_opts(cert_mon_opts, 'certmon')


class CertificateMonManager(periodic_task.PeriodicTasks):
    def __init__(self):
        super(CertificateMonManager, self).__init__(CONF)
        self.dc_mon_thread = None
        self.platcert_mon_thread = None
        self.audit_thread = None
        self.dc_monitor = None
        self.platcert_monitor = None
        self.reattempt_tasks = []
        self.subclouds_to_audit = []

    def periodic_tasks(self, context, raise_on_error=False):
        """Tasks to be run at a periodic interval."""
        return self.run_periodic_tasks(context, raise_on_error=raise_on_error)

    @periodic_task.periodic_task(spacing=CONF.certmon.audit_interval)
    def audit_sc_cert_start(self, context):
        # auditing subcloud certificate
        # this task runs every very long period of time, such as 24 hours
        dc_role = utils.get_dc_role()
        if dc_role != constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            # Do nothing if it is not systemcontroller
            return

        self.subclouds_to_audit = utils.get_subclouds()[:]

    def on_start_audit(self):
        """
        On service start audit
        Audit all subclouds that are out-of-sync
        """
        dc_role = utils.get_dc_role()
        if dc_role != constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            # Do nothing if it is not systemcontroller
            return

        number_of_sc_to_audit = 0
        token = utils.get_token()
        subclouds = utils.get_subclouds_from_dcmanager(token)
        for sc in subclouds:
            if sc[utils.ENDPOINT_TYPE_DC_CERT] == utils.SYNC_STATUS_OUT_OF_SYNC:
                self.subclouds_to_audit.append(sc['name'])
                LOG.info('%s is out-of-sync, adding it to audit.' % sc['name'])
                number_of_sc_to_audit = number_of_sc_to_audit + 1

        if number_of_sc_to_audit > 0:
            LOG.info('%d subcloud(s) found out-of-sync to be audited' %
                     number_of_sc_to_audit)
        else:
            LOG.info('All subclouds are in-sync. No startup audit is required')

    @periodic_task.periodic_task(spacing=5)
    def audit_sc_cert_task(self, context):
        if len(self.subclouds_to_audit) > 0:
            subcloud_name = self.subclouds_to_audit[0]
            if subcloud_name == TASK_NAME_PAUSE_AUDIT:
                LOG.info('Pause audit for ongoing update to complete')
                self.subclouds_to_audit.pop(0)
                return

            LOG.info('Auditing %s' % subcloud_name)

            try:
                subcloud_sysinv_url = utils.dc_get_subcloud_sysinv_url(subcloud_name)
                sc_ssl_cert = utils.get_endpoint_certificate(subcloud_sysinv_url)

                secret = utils.get_sc_intermediate_ca_secret(subcloud_name)
                check_list = ['ca.crt', 'tls.crt', 'tls.key']
                for item in check_list:
                    if item not in secret.data:
                        raise Exception('%s certificate data missing %s'
                                        % (subcloud_name, item))

                txt_ssl_cert = base64.b64decode(secret.data['tls.crt'])
                txt_ssl_key = base64.b64decode(secret.data['tls.key'])
                txt_ca_cert = base64.b64decode(secret.data['ca.crt'])
            except Exception as e:
                LOG.error('Cannot audit ssl certificate on %s' % subcloud_name)
                LOG.exception(e)
                # certificate is not ready, no reaudit. Will be picked up
                # by certificate MODIFIED event if it comes back
                self.subclouds_to_audit.pop(0)
                return

            cert_chain = txt_ssl_cert + txt_ca_cert
            dc_token = utils.get_dc_token(subcloud_name)
            if not cutils.verify_intermediate_ca_cert(cert_chain, sc_ssl_cert):
                # The subcloud needs renewal.
                LOG.info('Updating {} intermediate CA as it is out-of-sync'.format(subcloud_name))
                # move the subcloud to the end of the queue for reauditing
                self.requeue_audit(subcloud_name)

                utils.update_subcloud_status(dc_token, subcloud_name,
                                             utils.SYNC_STATUS_OUT_OF_SYNC)
                try:
                    utils.update_subcloud_ca_cert(dc_token,
                                                  subcloud_name,
                                                  subcloud_sysinv_url,
                                                  txt_ca_cert,
                                                  txt_ssl_cert,
                                                  txt_ssl_key)
                except Exception:
                    LOG.exception('Failed to update intermediate CA on %s' % subcloud_name)
            else:
                LOG.info('%s intermediate CA cert is in-sync' % subcloud_name)
                utils.update_subcloud_status(dc_token, subcloud_name,
                                             utils.SYNC_STATUS_IN_SYNC)

                self.subclouds_to_audit.remove(subcloud_name)

    @periodic_task.periodic_task(spacing=CONF.certmon.retry_interval)
    def retry_task(self, context):
        # Failed tasks that need to be reattempted will be taken care here
        max_attempts = CONF.certmon.max_retry
        tasks = self.reattempt_tasks[:]
        for task in tasks:
            if task.run():
                self.reattempt_tasks.remove(task)
                LOG.info('Reattempt has succeeded')
            elif task.number_of_reattempt >= max_attempts:
                LOG.error('Maximum attempts (%s) has been reached. Give up' %
                          max_attempts)
                if task in self.reattempt_tasks:
                    self.reattempt_tasks.remove(task)

                # task has failed
                task.failed()

    def start_audit(self):
        LOG.info('Auditing interval %s' % CONF.certmon.audit_interval)
        utils.init_keystone_auth_opts()
        self.audit_thread = greenthread.spawn(self.audit_cert)
        self.on_start_audit()

    def init_dc_monitor(self):
        self.dc_monitor = watcher.DC_CertWatcher()
        self.dc_monitor.initialize(
            audit_subcloud=lambda subcloud_name: self.requeue_audit(subcloud_name))

    def init_platformcert_monitor(self):
        self.platcert_monitor = watcher.PlatCert_CertWatcher()
        self.platcert_monitor.initialize()

    def start_monitor(self):
        utils.init_keystone_auth_opts()
        dc_role = utils.get_dc_role()
        while True:
            try:
                # init platformcert monitor
                self.init_platformcert_monitor()

                # init dc monitor only if running in DC role
                if (dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER or
                        dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
                    self.init_dc_monitor()
            except Exception as e:
                LOG.exception(e)
                time.sleep(5)
            else:
                break

        # spawn threads (DC thread spawned only if running in DC role)
        self.platcert_mon_thread = greenthread.spawn(self.platcert_monitor_cert)

        if (dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER or
                dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
            self.dc_mon_thread = greenthread.spawn(self.dc_monitor_cert)

    def stop_monitor(self):
        if self.dc_mon_thread:
            self.dc_mon_thread.kill()
            self.dc_mon_thread.wait()

        if self.platcert_mon_thread:
            self.platcert_mon_thread.kill()
            self.platcert_mon_thread.wait()

    def stop_audit(self):
        if self.audit_thread:
            self.audit_thread.kill()
            self.audit_thread.wait()

    def audit_cert(self):
        while True:
            try:
                self.run_periodic_tasks(context=None)
                time.sleep(1)
            except greenlet.GreenletExit:
                break
            except Exception as e:
                LOG.exception(e)

    def dc_monitor_cert(self):
        while True:
            # never exit until exit signal received
            try:
                self.dc_monitor.start_watch(
                    on_success=lambda task_id: self._purge_reattempt_task(task_id),
                    on_error=lambda task: self._add_reattempt_task(task),
                )
            except greenlet.GreenletExit:
                break
            except Exception as e:
                # A bug somewhere?
                # It shouldn't fall to here, but log and restart if it did
                LOG.exception(e)

    def platcert_monitor_cert(self):
        while True:
            # never exit until exit signal received
            try:
                self.platcert_monitor.start_watch(
                    on_success=lambda task_id: self._purge_reattempt_task(task_id),
                    on_error=lambda task: self._add_reattempt_task(task),
                )
            except greenlet.GreenletExit:
                break
            except Exception as e:
                # A bug somewhere?
                # It shouldn't fall to here, but log and restart if it did
                LOG.exception(e)

    def _add_reattempt_task(self, task):
        id = task.get_id()
        self._purge_reattempt_task(id)
        self.reattempt_tasks.append(task)

    def _purge_reattempt_task(self, id):
        for t in self.reattempt_tasks:
            if t.get_id() == id:
                self.reattempt_tasks.remove(t)
                LOG.info('Older task %s is removed for new operation' % id)
                break

    def requeue_audit(self, subcloud_name):
        # move the subcloud to the end of the queue for auditing
        # adding enough spaces so that the renewal would complete by
        # next audit
        if subcloud_name in self.subclouds_to_audit:
            self.subclouds_to_audit.remove(subcloud_name)
        for i in range(12, self.subclouds_to_audit.count(TASK_NAME_PAUSE_AUDIT), -1):
            self.subclouds_to_audit.append(TASK_NAME_PAUSE_AUDIT)
        self.subclouds_to_audit.append(subcloud_name)

    def audit_subcloud(self, subcloud_name):
        if subcloud_name not in self.subclouds_to_audit:
            self.subclouds_to_audit.append(subcloud_name)
