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

from sysinv.cert_alarm import utils
from sysinv.common import constants

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

    def periodic_tasks(self, context, raise_on_error=False):
        """Tasks to be run at a periodic interval."""
        return self.run_periodic_tasks(context, raise_on_error=raise_on_error)

    @periodic_task.periodic_task(spacing=CONF.certalarm.audit_interval)
    def periodic_full_audit(self):
        # this task runs every CONF.certalarm.audit_interval (24 hours)
        self.run_full_audit()

    def run_full_audit(self):
        """
        Run full audit
        """
        LOG.info('Running cert-alarm full audit')
        utils.reset_cert_snapshot()

        # 1. Process all k8s secrets/certificates
        LOG.info('Processing (1/3) k8s secret/certificates...')
        try:
            all_secrets = utils.get_tls_secrets_from_all_ns()

            if all_secrets:
                LOG.info('Number of TLS secrets to process=%d' % len(all_secrets))
                for item in all_secrets:
                    LOG.info('Processing item: %s' % item.metadata.name)
                    (certname_secret, exp_date_secret, anno_data_secret) = \
                            utils.collect_certificate_data_from_kube_secret(item)
                    # if cert not present, exp_date will be None
                    if exp_date_secret is not None:
                        utils.add_cert_snapshot(certname_secret, exp_date_secret, anno_data_secret)
        except Exception as e:
            LOG.error(e)

        # 2. Process platform certs stored as pem files
        LOG.info('Processing (2/3) platform certificate files...')
        for key, value in constants.CERT_LOCATION_MAP.items():
            LOG.info('Processing item: %s at location %s' % (key, value))
            if utils.is_certname_already_processed(key) is True:
                continue

            (certname_file, exp_date_file, anno_data_file) = utils.collect_certificate_data_from_file(key, value)
            # if cert not present, exp_date will be None
            if exp_date_file is not None:
                utils.add_cert_snapshot(certname_file, exp_date_file, anno_data_file)

        # 3. Process SSL_CA certificates (special case, since there can be multiple files)
        LOG.info('Processing (3/3) ssl_ca certificate files...')
        ssl_ca_data_list = utils.collect_certificate_data_for_ssl_cas()
        LOG.debug('ssl_ca_data_list=%s' % ssl_ca_data_list)
        for entry in ssl_ca_data_list:
            # if cert not present, exp_date will be None
            if entry[1] is not None:
                utils.add_cert_snapshot(entry[0], entry[1], entry[2])

        utils.print_cert_snapshot()

    @periodic_task.periodic_task(spacing=CONF.certalarm.active_alarm_audit_interval)
    def periodic_active_alarm_audit(self):
        # this task runs every CONF.certalarm.active_alarm_audit_interval (1 hour)
        self.run_active_alarm_audit()

    def run_active_alarm_audit(self):
        """
        Run audit only on active alarms
        """
        LOG.info('Running cert-alarm active_alarm_audit')
        # TODO()

    def start_audits(self):
        LOG.info('Cert-alarm auditing interval %s' % CONF.certalarm.audit_interval)
        self.audit_thread = greenthread.spawn(self.audit_certalarms)
        self.run_full_audit()

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
