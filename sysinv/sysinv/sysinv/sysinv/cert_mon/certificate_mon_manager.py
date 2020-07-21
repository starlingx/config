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
from oslo_config import cfg
import greenlet
from eventlet import greenthread
from oslo_log import log
from oslo_service import periodic_task
import time

from sysinv.openstack.common import context
from sysinv.cert_mon import watcher

LOG = log.getLogger(__name__)

cert_mon_opts = [
    cfg.IntOpt('audit_interval',
               default=86400,  # 24 hours
               help='Interval to run certificate audit'),
    cfg.IntOpt('retry_interval',
               default=10,
               help='interval to reattempt accessing external system '
                    'if failure occurred'),
    cfg.IntOpt('max_retry',
               default=5,
               help='interval to reattempt accessing external system '
                    'if failure occurred'),
]

CONF = cfg.CONF
CONF.register_opts(cert_mon_opts, 'certmon')


class CertificateMonManager(periodic_task.PeriodicTasks):
    def __init__(self):
        super(CertificateMonManager, self).__init__(CONF)
        self.mon_thread = None
        self.audit_thread = None
        self.monitor = None
        self.reattempt_tasks = []

    def periodic_tasks(self, context, raise_on_error=False):
        """Tasks to be run at a periodic interval."""
        return self.run_periodic_tasks(context, raise_on_error=raise_on_error)

    @periodic_task.periodic_task(spacing=CONF.certmon.audit_interval)
    def audit_cert_task(self, context):
        # [Place holder for] auditing subcloud certificate
        # this task runs every very long period of time, such as 24 hours
        LOG.info('Audit certificate')

    @periodic_task.periodic_task(spacing=CONF.certmon.retry_interval)
    def retry_task(self, context):
        # Failed tasks that need to be reattempted will be taken care here
        max_attempts = CONF.certmon.max_retry
        tasks = self.reattempt_tasks[:]
        for task in tasks:
            if task.run():
                self.reattempt_tasks.remove(task)
                LOG.info('Reattempt has succeeded')
            elif task.number_of_reattempt == max_attempts:
                LOG.error('Maximum attempts (%s) has been reached. Give up' %
                          max_attempts)
                if task in self.reattempt_tasks:
                    self.reattempt_tasks.remove(task)

    def start_audit(self):
        LOG.info('Auditing interval %s' % CONF.certmon.audit_interval)
        self.audit_thread = greenthread.spawn(self.audit_cert)

    def init_monitor(self):
        self.monitor = watcher.CertWatcher()
        self.monitor.initialize()

    def start_monitor(self):
        while True:
            try:
                self.init_monitor()
            except Exception as e:
                LOG.error(e)
                time.sleep(CONF.certmon.retry_interval)
            else:
                break
        self.mon_thread = greenthread.spawn(self.monitor_cert)

    def stop_monitor(self):
        if self.mon_thread:
            self.mon_thread.kill()
            self.mon_thread.wait()

    def stop_audit(self):
        if self.audit_thread:
            self.audit_thread.kill()
            self.audit_thread.wait()

    def audit_cert(self):
        admin_context = context.RequestContext('admin', 'admin', is_admin=True)
        while True:
            try:
                self.run_periodic_tasks(context=admin_context)
                time.sleep(1)
            except greenlet.GreenletExit:
                break
            except Exception as e:
                LOG.error(e)

    def monitor_cert(self):
        while True:
            # never exit until exit signal received
            try:
                self.monitor.start_watch(
                    func=lambda task: self._add_reattempt_task(task))
            except greenlet.GreenletExit:
                break
            except Exception as e:
                # A bug somewhere?
                # It shouldn't fall to here, but log and restart if it did
                LOG.error(e)

    def _add_reattempt_task(self, task):
        id = task.get_id()
        for t in self.reattempt_tasks:
            if t.get_id() == id:
                self.reattempt_tasks.remove(t)
                LOG.info('Older task %s is replaced with new task' % id)
                break

        self.reattempt_tasks.append(task)
