#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from eventlet import greenthread
import eventlet
import greenlet
from oslo_config import cfg
from oslo_log import log
from oslo_service import periodic_task

from sysinv.cert_alarm import audit as audit_mgr
from sysinv.cert_mon import utils as certmon_utils

LOG = log.getLogger(__name__)

cert_alarm_opts = [
    cfg.IntOpt('audit_interval',
               default=86400,  # 24 hours
               help='Interval to run cert-alarm audit'),
    cfg.IntOpt('active_alarm_audit_interval',
               default=3600,  # 1 hr
               help='Interval to run cert-alarm audit on active alarms'),
]

CONF = cfg.CONF
CONF.register_opts(cert_alarm_opts, 'certalarm')


class CertificateAlarmManager(periodic_task.PeriodicTasks):
    def __init__(self):
        super(CertificateAlarmManager, self).__init__(CONF)
        self.audit_thread = None
        self.active_alarm_audit_thread = None
        self.audit_obj = audit_mgr.CertAlarmAudit()

    def periodic_tasks(self, context, raise_on_error=False):
        """Tasks to be run at a periodic interval."""
        return self.run_periodic_tasks(context, raise_on_error=raise_on_error)

    @periodic_task.periodic_task(spacing=CONF.certalarm.audit_interval)
    def periodic_full_audit(self, context):
        # this task runs every CONF.certalarm.audit_interval (24 hours)
        self.audit_obj.run_full_audit()

    @periodic_task.periodic_task(spacing=CONF.certalarm.active_alarm_audit_interval)
    def periodic_active_alarm_audit(self, context):
        # this task runs every CONF.certalarm.active_alarm_audit_interval (1 hour)
        self.audit_obj.run_active_alarm_audit()

    def start_audits(self):
        certmon_utils.init_keystone_auth_opts()
        LOG.info('Cert-alarm auditing interval %s' % CONF.certalarm.audit_interval)
        self.audit_thread = greenthread.spawn(self.audit_certalarms)
        self.audit_obj.run_full_audit()

        LOG.info('Cert-alarm active alarms auditing interval %s' %
                 CONF.certalarm.active_alarm_audit_interval)
        self.active_alarm_audit_thread = greenthread.spawn(self.active_alarm_audits)

    def stop_audits(self):
        if self.audit_thread:
            self.audit_thread.kill()
            self.audit_thread.wait()
            self.audit_thread = None

        if self.active_alarm_audit_thread:
            self.active_alarm_audit_thread.kill()
            self.active_alarm_audit_thread.wait()
            self.active_alarm_audit_thread = None

    def audit_certalarms(self):
        while True:
            try:
                self.run_periodic_tasks(context=None)
                eventlet.sleep(1)
            except greenlet.GreenletExit:
                LOG.error('Stopping audit thread')
                break
            except Exception as e:
                LOG.exception(e)

    def active_alarm_audits(self):
        while True:
            try:
                self.run_periodic_tasks(context=None)
                eventlet.sleep(1)
            except greenlet.GreenletExit:
                LOG.error('Stopping active_alarm audit thread')
                break
            except Exception as e:
                LOG.exception(e)
