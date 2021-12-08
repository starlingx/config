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
import time

import eventlet
import greenlet
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import base64
from oslo_service import periodic_task

from sysinv.cert_mon import subcloud_audit_queue
from sysinv.cert_mon import utils
from sysinv.cert_mon import watcher
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
               help='Interval to reattempt accessing external system '
                    'if failure occurred'),
    cfg.IntOpt('max_retry',
               default=14,  # retry 14 times to give at least 2 hours to recover
               help='Max number of reattempts accessing external system '
                    'if failure occurred'),
    cfg.BoolOpt('startup_audit_all',
                default=False,
                help='Audit all subclouds on startup'),
    cfg.IntOpt('network_retry_interval',
               default=180,  # every 3 minutes
               help='Max times to reattempt accessing external system '
                    'if network failure occurred'),
    cfg.IntOpt('network_max_retry',
               default=5,
               help='Interval to reattempt accessing external system '
                    'if network failure occurred'),
    cfg.IntOpt('audit_batch_size',
               default=10,
               help='Batch size of subcloud audits per audit_interval'),
    cfg.IntOpt('audit_greenpool_size',
               default=4,
               help='Size of subcloud audit greenpool.'
                    'Set to 0 to disable use of greenpool '
                    '(force serial audit).'),
    cfg.IntOpt('certificate_timeout_secs',
               default=10,
               help='Connection timeout for certificate check (in seconds)'),
]

CONF = cfg.CONF
CONF.register_opts(cert_mon_opts, 'certmon')


class CertificateMonManager(periodic_task.PeriodicTasks):
    def __init__(self):
        super(CertificateMonManager, self).__init__(CONF)
        self.mon_threads = []
        self.audit_thread = None
        self.token_cache = utils.TokenCache('internal')
        self.dc_token_cache = utils.TokenCache('dc')
        self.dc_monitor = None
        self.restapicert_monitor = None
        self.registrycert_monitor = None
        self.reattempt_monitor_tasks = []
        self.sc_audit_queue = subcloud_audit_queue.SubcloudAuditPriorityQueue()
        if CONF.certmon.audit_greenpool_size > 0:
            self.sc_audit_pool = eventlet.greenpool.GreenPool(
                size=CONF.certmon.audit_greenpool_size)
        else:
            self.sc_audit_pool = None

    def periodic_tasks(self, context, raise_on_error=False):
        """Tasks to be run at a periodic interval."""
        return self.run_periodic_tasks(context, raise_on_error=raise_on_error)

    @periodic_task.periodic_task(spacing=CONF.certmon.audit_interval)
    def audit_sc_cert_start(self, context):
        """Kicks an audit of all subclouds.
        By default this task runs once every 24 hours.
        """
        # auditing subcloud certificate
        dc_role = utils.get_dc_role()
        if dc_role != constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            # Do nothing if it is not systemcontroller
            return

        all_subclouds = utils.get_subclouds()[:]
        LOG.info("Periodic: begin subcloud certificate audit: %d subclouds"
                 % len(all_subclouds))
        for subcloud_name in all_subclouds:
            self.sc_audit_queue.enqueue(
                subcloud_audit_queue.SubcloudAuditData(subcloud_name))

    def on_start_audit(self):
        """
        On service start audit
        Audit all subclouds that are out-of-sync
        """
        dc_role = utils.get_dc_role()
        if dc_role != constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            # Do nothing if it is not systemcontroller
            return

        if CONF.certmon.startup_audit_all:
            LOG.info("Service start: audit all subclouds")
            self.audit_sc_cert_start(None)
            return

        LOG.info("Service start: begin subcloud certificate audit [batch: %s]"
                 % CONF.certmon.audit_batch_size)
        all_subclouds = utils.get_subclouds_from_dcmanager(
            self.token_cache.get_token())
        for subcloud in all_subclouds:
            if subcloud[utils.ENDPOINT_TYPE_DC_CERT] != utils.SYNC_STATUS_IN_SYNC:
                subcloud_name = subcloud['name']
                if self.sc_audit_queue.contains(subcloud_name):
                    LOG.info("%s is not in-sync but already under audit"
                             % subcloud_name)
                else:
                    LOG.info("%s is not in-sync, adding it to audit"
                             % subcloud_name)
                    self.sc_audit_queue.enqueue(
                        subcloud_audit_queue.SubcloudAuditData(subcloud_name))

        if self.sc_audit_queue.qsize() > 0:
            LOG.info("Startup audit: %d subcloud(s) to be audited" %
                     self.sc_audit_queue.qsize())
        else:
            LOG.info("Startup audit: all subclouds are in-sync")

    @periodic_task.periodic_task(spacing=5)
    def audit_sc_cert_task(self, context):
        """This task runs every N seconds, and is responsible for running
        a single subcloud through its next step in the subcloud audit process.

        Pull up to <batch_count> number of ready-to-audit subcloud audit
        data items from the sc_audit_queue, and spawn each item to be
        executed via the GreenPool (or directly invoke the audit if the
        GreenPool is disabled).
        """
        for batch_count in range(CONF.certmon.audit_batch_size):
            if self.sc_audit_queue.qsize() < 1:
                # Nothing to do
                return

            # Only continue if the next in queue is ready to be audited
            # Peek into the timestamp of the next item in our priority queue
            next_audit_timestamp = self.sc_audit_queue.queue[0][0]
            if next_audit_timestamp > int(time.time()):
                LOG.debug("audit_sc_cert_task: no audits ready for "
                          "processing, qsize=%s"
                          % self.sc_audit_queue.qsize())
                return

            _, sc_audit_item = self.sc_audit_queue.get()
            LOG.debug(
                "audit_sc_cert_task: enqueue subcloud audit %s, "
                "qsize:%s, batch:%s" %
                (sc_audit_item, self.sc_audit_queue.qsize(), batch_count))

            # This item is ready for audit
            if self.sc_audit_pool is not None:
                self.sc_audit_pool.spawn_n(self.do_subcloud_audit,
                                           sc_audit_item)
            else:
                self.do_subcloud_audit(sc_audit_item)
            eventlet.sleep()

    def do_subcloud_audit(self, sc_audit_item):
        """A wrapper function to ensure the subcloud audit task is marked done
        within sc_audit_queue"""
        try:
            self._subcloud_audit(sc_audit_item)
        finally:
            self.sc_audit_queue.task_done()

    def _subcloud_audit(self, sc_audit_item):
        """Invoke a subcloud audit"""
        subcloud_name = sc_audit_item.name

        LOG.info("Auditing subcloud %s, attempt #%s [qsize: %s]"
                 % (subcloud_name,
                    sc_audit_item.audit_count,
                    self.sc_audit_queue.qsize()))

        def my_dc_token():
            """Ensure we always have a valid token"""
            return self.dc_token_cache.get_token()

        subcloud_sysinv_url = None
        try:
            subcloud_sysinv_url = utils.dc_get_subcloud_sysinv_url(
                subcloud_name, my_dc_token())
            sc_ssl_cert = utils.get_endpoint_certificate(
                subcloud_sysinv_url,
                timeout_secs=CONF.certmon.certificate_timeout_secs)

        except Exception:
            if not utils.is_subcloud_online(subcloud_name, my_dc_token()):
                LOG.warn("Subcloud is not online, aborting audit: %s"
                         % subcloud_name)
                return
            # Handle network-level issues
            # Re-enqueue the subcloud for reauditing
            max_attempts = CONF.certmon.network_max_retry
            if sc_audit_item.audit_count < max_attempts:
                LOG.exception("Cannot retrieve ssl certificate for %s "
                              "via: %s (requeuing audit)"
                              % (subcloud_name, subcloud_sysinv_url))
                self.requeue_audit_subcloud(sc_audit_item,
                                            CONF.certmon.network_retry_interval)
            else:
                LOG.exception("Cannot retrieve ssl certificate for %s via: %s; "
                              "maximum retry limit exceeded [%d], giving up"
                              % (subcloud_name, subcloud_sysinv_url, max_attempts))

                utils.update_subcloud_status(my_dc_token(), subcloud_name,
                                             utils.SYNC_STATUS_OUT_OF_SYNC)
            return
        try:
            secret = utils.get_sc_intermediate_ca_secret(subcloud_name)
            check_list = ['ca.crt', 'tls.crt', 'tls.key']
            for item in check_list:
                if item not in secret.data:
                    raise Exception('%s certificate data missing: %s'
                                    % (subcloud_name, item))

            txt_ssl_cert = base64.decode_as_text(secret.data['tls.crt'])
            txt_ssl_key = base64.decode_as_text(secret.data['tls.key'])
            txt_ca_cert = base64.decode_as_text(secret.data['ca.crt'])
        except Exception:
            # Handle certificate-level issues
            if not utils.is_subcloud_online(subcloud_name, my_dc_token()):
                LOG.exception("Error getting subcloud intermediate cert. "
                              "Subcloud is not online, aborting audit: %s"
                              % subcloud_name)
                return
            LOG.exception("Cannot audit ssl certificate on %s. "
                          "Certificate is not ready." % subcloud_name)
            # certificate is not ready, no reaudit. Will be picked up
            # by certificate MODIFIED event if it comes back
            return

        cert_chain = txt_ssl_cert + txt_ca_cert
        if not cutils.verify_intermediate_ca_cert(cert_chain, sc_ssl_cert):
            # The subcloud needs renewal.
            LOG.info("Updating %s intermediate CA as it is out-of-sync" %
                     subcloud_name)
            # reaudit this subcloud after delay
            self.requeue_audit_subcloud(sc_audit_item)
            try:
                utils.update_subcloud_ca_cert(my_dc_token(),
                                              subcloud_name,
                                              subcloud_sysinv_url,
                                              txt_ca_cert,
                                              txt_ssl_cert,
                                              txt_ssl_key)
            except Exception:
                LOG.exception("Failed to update intermediate CA on %s"
                              % subcloud_name)
                utils.update_subcloud_status(my_dc_token(), subcloud_name,
                                             utils.SYNC_STATUS_OUT_OF_SYNC)
        else:
            LOG.info("%s intermediate CA cert is in-sync" % subcloud_name)
            utils.update_subcloud_status(my_dc_token(), subcloud_name,
                                         utils.SYNC_STATUS_IN_SYNC)

    @periodic_task.periodic_task(spacing=CONF.certmon.retry_interval)
    def retry_monitor_task(self, context):
        # Failed tasks that need to be reattempted will be taken care here
        max_attempts = CONF.certmon.max_retry
        tasks = self.reattempt_monitor_tasks[:]

        num_tasks = len(tasks)
        if num_tasks > 0:
            LOG.info("Start retry_monitor_task: #tasks in queue: %s" %
                     num_tasks)

        # NOTE: this loop can potentially retry ALL subclouds, which
        # may be a resource concern.
        for task in tasks:
            task_id = task.get_id()
            LOG.info("retry_monitor_task: %s, attempt: %s"
                     % (task_id, task.number_of_reattempt))
            if task.run():
                self.reattempt_monitor_tasks.remove(task)
                LOG.info("retry_monitor_task: %s, reattempt has succeeded"
                         % task_id)
            elif task.number_of_reattempt >= max_attempts:
                LOG.error(("retry_monitor_task: %s, maximum attempts (%s) "
                           "has been reached. Give up")
                          % (task_id, max_attempts))
                if task in self.reattempt_monitor_tasks:
                    self.reattempt_monitor_tasks.remove(task)

                # task has failed
                task.failed()

            # Pause and allow other eventlets to run
            eventlet.sleep(0.1)
        LOG.debug("End retry_monitor_task")

    def start_audit(self):
        LOG.info("Auditing interval %s" % CONF.certmon.audit_interval)
        utils.init_keystone_auth_opts()
        self.audit_thread = eventlet.greenthread.spawn(self.audit_cert_loop)
        self.on_start_audit()

    def init_dc_monitor(self):
        self.dc_monitor = watcher.DC_CertWatcher()
        self.dc_monitor.initialize(
            audit_subcloud=lambda subcloud_name:
                self.audit_subcloud(subcloud_name, allow_requeue=True))

    def init_restapicert_monitor(self):
        self.restapicert_monitor = watcher.RestApiCert_CertWatcher()
        self.restapicert_monitor.initialize()

    def init_registrycert_monitor(self):
        self.registrycert_monitor = watcher.RegistryCert_CertWatcher()
        self.registrycert_monitor.initialize()

    def start_monitor(self):
        utils.init_keystone_auth_opts()
        dc_role = utils.get_dc_role()
        while True:
            try:
                # init platform cert monitors
                self.init_restapicert_monitor()
                self.init_registrycert_monitor()

                # init dc monitor only if running in DC role
                if dc_role in (constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER,
                               constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
                    self.init_dc_monitor()
            except Exception as e:
                LOG.exception(e)
                time.sleep(5)
            else:
                break

        # spawn threads (DC thread spawned only if running in DC role)
        self.mon_threads.append(
            eventlet.greenthread.spawn(self.monitor_cert,
                                       self.restapicert_monitor))
        self.mon_threads.append(
            eventlet.greenthread.spawn(self.monitor_cert,
                                       self.registrycert_monitor))

        if dc_role in (constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER,
                       constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
            self.mon_threads.append(
                eventlet.greenthread.spawn(self.monitor_cert, self.dc_monitor))

    def stop_monitor(self):
        for mon_thread in self.mon_threads:
            mon_thread.kill()
            mon_thread.wait()
        self.mon_threads = []

    def stop_audit(self):
        if self.audit_thread:
            self.audit_thread.kill()
            self.audit_thread.wait()
            self.audit_thread = None

    def audit_cert_loop(self):
        while True:
            try:
                self.run_periodic_tasks(context=None)
                time.sleep(1)
            except greenlet.GreenletExit:
                break
            except Exception as e:
                LOG.exception(e)

    def requeue_audit_subcloud(self, sc_audit_item, delay_secs=60):
        if not self.sc_audit_queue.contains(sc_audit_item.name):
            self.sc_audit_queue.enqueue(sc_audit_item, delay_secs)

    def audit_subcloud(self, subcloud_name, allow_requeue=False):
        """Enqueue a subcloud audit

        allow_requeue: This can come from a watch after a DC certificate renew.
                       i.e., outside of the periodic subcloud audit tasks.
                       We allow a re-enqueue here with a new delay.
        """
        if self.sc_audit_queue.contains(subcloud_name):
            if (allow_requeue
                    and self.sc_audit_queue.enqueued_subcloud_names.count(
                        subcloud_name) < 2):
                LOG.info("audit_subcloud: requeing %s" % subcloud_name)
            else:
                LOG.debug("audit_subcloud: ignoring %s, already in queue"
                          % subcloud_name)
                return
        self.sc_audit_queue.enqueue(
            subcloud_audit_queue.SubcloudAuditData(subcloud_name),
            allow_requeue=allow_requeue)

    def monitor_cert(self, monitor):
        while True:
            # never exit until exit signal received
            try:
                monitor.start_watch(
                    on_success=lambda task_id:
                        self._purge_reattempt_monitor_task(task_id,
                                                           'on success'),
                    on_error=lambda task:
                        self._add_reattempt_monitor_task(task))
            except greenlet.GreenletExit:
                break
            except Exception:
                # A bug somewhere?
                # It shouldn't fall to here, but log and restart if it did
                LOG.exception("Unexpected exception from start_watch")
                time.sleep(1)

    def _add_reattempt_monitor_task(self, task):
        id = task.get_id()
        self._purge_reattempt_monitor_task(id, 'for new reattempt')
        self.reattempt_monitor_tasks.append(task)

    def _purge_reattempt_monitor_task(self, id, reason_msg):
        for t in self.reattempt_monitor_tasks:
            if t.get_id() == id:
                self.reattempt_monitor_tasks.remove(t)
                LOG.info("Purging reattempt monitor task %s: %s"
                         % (reason_msg, id))
                break
