# Copyright (c) 2020-2025 Wind River Systems, Inc.
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

import time

import eventlet
import greenlet
from oslo_config import cfg
from oslo_log import log
from oslo_service import periodic_task

from sysinv.cert_mon import watcher
from sysinv.common import constants

LOG = log.getLogger(__name__)

cert_mon_opts = [
    cfg.IntOpt('retry_interval',
               default=10 * 60,  # retry every 10 minutes
               help='Interval to reattempt accessing external system '
                    'if failure occurred'),
    cfg.IntOpt('max_retry',
               default=14,  # retry 14 times to give at least 2 hours to recover
               help='Max number of reattempts accessing external system '
                    'if failure occurred'),
]

CONF = cfg.CONF
CONF.register_opts(cert_mon_opts, 'certmon')


class CertificateMonManager(periodic_task.PeriodicTasks):
    def __init__(self):
        super(CertificateMonManager, self).__init__(CONF)
        self.mon_threads = []
        self.task_thread = None
        self.dc_monitor = None
        self.systemlocalcacert_monitor = None
        self.restapicert_monitor = None
        self.registrycert_monitor = None
        self.openldapcert_monitor = None
        self.reattempt_monitor_tasks = []

    def periodic_tasks(self, context, raise_on_error=False):
        """Tasks to be run at a periodic interval."""
        return self.run_periodic_tasks(context, raise_on_error=raise_on_error)

    @periodic_task.periodic_task(spacing=CONF.certmon.retry_interval)
    def retry_monitor_task(self, context):
        # Failed tasks that need to be reattempted will be taken care here
        max_attempts = CONF.certmon.max_retry
        tasks = self.reattempt_monitor_tasks[:]

        num_tasks = len(tasks)
        if num_tasks > 0:
            LOG.info("Start retry_monitor_task: #tasks in queue: %s" %
                     num_tasks)

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

    def init_dc_monitor(self):
        self.dc_monitor = watcher.DC_CertWatcher()
        self.dc_monitor.initialize()

    def start_periodic_tasks(self):
        self.task_thread = eventlet.greenthread.spawn(self.periodic_tasks_loop)

    def init_systemlocalcacert_monitor(self):
        self.systemlocalcacert_monitor = watcher.SystemLocalCACert_CertWatcher()
        self.systemlocalcacert_monitor.initialize()

    def init_restapicert_monitor(self):
        self.restapicert_monitor = watcher.RestApiCert_CertWatcher()
        self.restapicert_monitor.initialize()

    def init_registrycert_monitor(self):
        self.registrycert_monitor = watcher.RegistryCert_CertWatcher()
        self.registrycert_monitor.initialize()

    def init_openldapcert_monitor(self):
        self.openldapcert_monitor = watcher.OpenldapCert_CertWatcher()
        self.openldapcert_monitor.initialize()

    def start_monitor(self, dc_role):
        while True:
            try:
                # init system-local-ca RCA cert monitor
                self.init_systemlocalcacert_monitor()
                # init platform cert monitors
                self.init_restapicert_monitor()
                self.init_registrycert_monitor()
                self.init_openldapcert_monitor()

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
                                       self.systemlocalcacert_monitor))

        self.mon_threads.append(
            eventlet.greenthread.spawn(self.monitor_cert,
                                       self.restapicert_monitor))
        self.mon_threads.append(
            eventlet.greenthread.spawn(self.monitor_cert,
                                       self.registrycert_monitor))
        self.mon_threads.append(
            eventlet.greenthread.spawn(self.monitor_cert,
                                       self.openldapcert_monitor))

        if dc_role in (constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER,
                       constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
            self.mon_threads.append(
                eventlet.greenthread.spawn(self.monitor_cert, self.dc_monitor))

    def stop_monitor(self):
        for mon_thread in self.mon_threads:
            mon_thread.kill()
            mon_thread.wait()
        self.mon_threads = []

    def stop_periodic_tasks(self):
        if self.task_thread:
            self.task_thread.kill()
            self.task_thread.wait()
            self.task_thread = None

    def periodic_tasks_loop(self):
        while True:
            try:
                self.run_periodic_tasks(context=None)
                time.sleep(60)
            except greenlet.GreenletExit:
                break
            except Exception as e:
                LOG.exception(e)

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
