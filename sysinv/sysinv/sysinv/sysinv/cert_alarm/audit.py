#
# Copyright (c) 2021-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from datetime import datetime
from datetime import timedelta
from distutils.version import LooseVersion
from fm_api import constants as fm_constants
from oslo_log import log
import re
from sysinv.cert_alarm.cdi_watch import CDIWatch
from sysinv.cert_alarm import fm as fm_mgr
from sysinv.cert_alarm import utils
from sysinv.common import constants
from sysinv.common import kubernetes as sys_kube

LOG = log.getLogger(__name__)

cdi_watch = CDIWatch()


class CertAlarmAudit(object):
    def __init__(self):
        LOG.info('Initializing CertAlarmAudit')
        self.fm_obj = fm_mgr.FaultApiMgr()

    # ============== Full audit ===================
    def run_full_audit(self):
        """
        Run full audit
        """
        LOG.info('Running cert-alarm full audit')

        # Reset both CERT_SNAPSHOT & ALARM_SNAPSHOT
        utils.reset_cert_snapshot()
        self.fm_obj.reset_alarms_snapshot()

        # Collect snapshots
        self.collect_cert_snapshot()
        self.fm_obj.collect_all_cert_alarms()

        # Auditing deleted certificates
        self.audit_for_deleted_certificates()

        utils.print_cert_snapshot()
        self.fm_obj.print_alarms_snapshot()

        self.apply_action_full_audit()

        LOG.info('cert-alarm full audit completed')

    def collect_cert_snapshot(self):
        """
        Collects snapshot of the certificates in the following order:
        1. K8s secret/certificates
        2. Platform certificate files
        3. SSL_CA certificate files
        """
        # 1. Process all k8s secrets/certificates
        LOG.debug('Processing k8s secret/certificates...')
        try:
            all_secrets = utils.get_tls_secrets_from_all_ns()

            if all_secrets:
                LOG.info('Number of TLS secrets to process=%d' % len(all_secrets))
                for item in all_secrets:
                    LOG.info('Processing item: %s' % item.metadata.name)
                    (certname_secret, exp_date_secret, anno_data_secret, mode_metadata) = \
                            utils.collect_certificate_data_from_kube_secret(item)
                    # if cert not present, exp_date will be None
                    if exp_date_secret is not None:
                        utils.add_cert_snapshot(certname_secret,
                                                exp_date_secret,
                                                anno_data_secret,
                                                mode_metadata)
        except Exception as e:
            LOG.error(e)

        # 2. Process platform certs stored as pem files
        LOG.debug('Processing platform certificate files...')
        for key, value in constants.CERT_LOCATION_MAP.items():
            LOG.info('Processing item: %s at location %s' % (key, value))
            if utils.is_certname_already_processed(key) is True:
                continue

            (certname_file, exp_date_file, anno_data_file, mode_metadata_file) = \
                    utils.collect_certificate_data_from_file(key, value)
            # if cert not present, exp_date will be None
            if exp_date_file is not None:
                utils.add_cert_snapshot(certname_file,
                                        exp_date_file,
                                        anno_data_file,
                                        mode_metadata_file)

        # 3. Process SSL_CA certificates (special case, since there can be multiple files)
        LOG.debug('Processing ssl_ca certificate files...')
        ssl_ca_data_list = utils.collect_certificate_data_for_ssl_cas()
        LOG.debug('ssl_ca_data_list=%s' % ssl_ca_data_list)
        for entry in ssl_ca_data_list:
            # if cert not present, exp_date will be None
            if entry[1] is not None:
                utils.add_cert_snapshot(entry[0], entry[1], entry[2], entry[3])

    def apply_action_full_audit(self):
        for cert_name in utils.CERT_SNAPSHOT:
            entity_id = utils.CERT_SNAPSHOT[cert_name].get(utils.ENTITY_ID,
                                utils.get_entity_instance_id(cert_name))
            self.apply_action(cert_name, entity_id)

    # ============== Active Alarm audit ===================
    def run_active_alarm_audit(self):
        """
        Run audit only on active alarms
        """
        LOG.info('Running cert-alarm active_alarm_audit')

        # Collect ALARM_SNAPSHOT
        self.fm_obj.reset_alarms_snapshot()
        self.fm_obj.collect_all_cert_alarms()

        self.audit_for_deleted_certificates()

        self.apply_action_active_alarms()

        utils.print_cert_snapshot()
        self.fm_obj.print_alarms_snapshot()

        LOG.info('cert-alarm active_alarm_audit completed')

    def apply_action_active_alarms(self):
        for alarm_instance in self.fm_obj.ALARMS_SNAPSHOT:
            entity_id = self.fm_obj.ALARMS_SNAPSHOT[alarm_instance]['ENTITY_ID']
            cert_name = utils.get_cert_name_with_entity_id(entity_id)
            if cert_name is not None:
                # 1. First refresh expiry date snapshot data
                self.refresh_expiry_data(cert_name)

                # 2. Now check dates and apply_action
                self.apply_action(cert_name, entity_id)

    def refresh_expiry_data(self, cert_name):
        if cert_name not in utils.CERT_SNAPSHOT:
            LOG.error('Could not find cert %s in snapshot to refresh expiry data' % cert_name)
        else:
            snapshot = utils.CERT_SNAPSHOT[cert_name]
            if snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_SECRET or \
                        snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_CERT_MGR:
                # mode is k8s secret
                kube_op = sys_kube.KubeOperator()
                try:
                    secret_object = kube_op.kube_get_secret(snapshot[utils.SNAPSHOT_KEY_k8s_secret],
                                                            snapshot[utils.SNAPSHOT_KEY_k8s_ns])
                    (certname_secret, exp_date_secret, anno_data_secret, mode_metadata) = \
                            utils.collect_certificate_data_from_kube_secret(secret_object)
                    if exp_date_secret is not None:
                        utils.add_cert_snapshot(certname_secret,
                                                exp_date_secret,
                                                anno_data_secret,
                                                mode_metadata)
                except Exception as e:
                    LOG.error("Failed to retrieve k8s_secret %s" % e)
            else:
                # mode is file
                (certname_file, exp_date_file, anno_data_file, mode_metadata_file) = \
                    utils.collect_certificate_data_from_file(cert_name,
                                                             snapshot[utils.SNAPSHOT_KEY_FILE_LOC])
                if exp_date_file is not None:
                    utils.add_cert_snapshot(certname_file,
                                            exp_date_file,
                                            anno_data_file,
                                            mode_metadata_file)

    # ============== Common ===================

    @staticmethod
    def parse_time(time_str):
        regex = re.compile(r'((?P<weeks>\d+?)w)?((?P<days>\d+?)d)?((?P<hours>\d+?)h)?((?P<minutes>\d+?)m)?')
        parts = regex.match(time_str).groupdict()
        time_params = {}
        for name, param in parts.items():
            if param:
                time_params[name] = int(param)
        return timedelta(**time_params)

    def apply_action(self, cert_name, entity_id):
        """
        Applies any action required based on parameters passed and calls FM API
        Input:  cert_name: Certificate name
        """
        if cert_name not in utils.CERT_SNAPSHOT:
            LOG.error('Could not find cert %s in snapshot' % cert_name)
            return

        snapshot = utils.CERT_SNAPSHOT[cert_name]
        expiry = snapshot[utils.SNAPSHOT_KEY_EXPDATE] - datetime.now()
        alarm_before = self.parse_time(snapshot.get(constants.CERT_ALARM_ANNOTATION_ALARM_BEFORE,
                                       constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_BEFORE))
        renew_before = None
        if utils.SNAPSHOT_KEY_RENEW_BEFORE in snapshot:
            renew_before = self.parse_time(snapshot[utils.SNAPSHOT_KEY_RENEW_BEFORE])
        LOG.debug('cert_name=%s, entity_id=%s, expiry=%s, alarm_before=%s, renew_before=%s'
            % (cert_name, entity_id, expiry, alarm_before, renew_before))

        # set threshold date to raise alarms
        if renew_before:
            # if renew_before valid, take latest (smaller timedelta) of two dates as threshold
            threshold = renew_before if renew_before < alarm_before else alarm_before
        else:
            threshold = alarm_before

        # TODO(boovan): Remove workaround to suppress 500.200 alarm for
        # cdi-uploadserver-client-cert certificate once we upgrade CDI version to 1.60.1.
        # Setting the threshold value to 12 hours, since the default
        # renewBefore value for cdi-uploadserver-client-cert is 12 hours.
        if cert_name == 'cdi-uploadserver-client-cert':
            if not cdi_watch.is_monitor_thread_started():
                # Start monitoring the cdi event in separate thread
                cdi_watch.start_watching()

            cdi_version = cdi_watch.get_version()
            if cdi_version is not None:
                if LooseVersion(cdi_version) < LooseVersion('v1.60.1'):
                    threshold = self.parse_time('12h')

        is_alarm_enabled = self.alarm_override_check_passed(cert_name)

        if is_alarm_enabled:
            if expiry > threshold:
                self.clear_expiring_soon(cert_name, entity_id)
                self.clear_expired(cert_name, entity_id)
            else:
                if expiry < timedelta():
                    # Expired. Clear expiring-soon & raise expired
                    self.clear_expiring_soon(cert_name, entity_id)
                    self.raise_expired(cert_name, entity_id)
                else:
                    self.clear_expired(cert_name, entity_id)
                    self.raise_expiring_soon(cert_name, entity_id)
        else:
            self.clear_expiring_soon(cert_name, entity_id)
            self.clear_expired(cert_name, entity_id)

    def raise_expiring_soon(self, cert_name, entity_id):
        self.fm_obj.set_fault(entity_id,
                              fm_constants.FM_ALARM_ID_CERT_EXPIRING_SOON,
                              fm_constants.FM_ALARM_STATE_SET)

    def clear_expiring_soon(self, cert_name, entity_id):
        self.fm_obj.set_fault(entity_id,
                              fm_constants.FM_ALARM_ID_CERT_EXPIRING_SOON,
                              fm_constants.FM_ALARM_STATE_CLEAR)

    def raise_expired(self, cert_name, entity_id):
        self.fm_obj.set_fault(entity_id,
                              fm_constants.FM_ALARM_ID_CERT_EXPIRED,
                              fm_constants.FM_ALARM_STATE_SET)

    def clear_expired(self, cert_name, entity_id):
        self.fm_obj.set_fault(entity_id,
                              fm_constants.FM_ALARM_ID_CERT_EXPIRED,
                              fm_constants.FM_ALARM_STATE_CLEAR)

    def alarm_override_check_passed(self, cert_name):
        '''
        Check for alarm overrides in annotation.
        Return: True for enabled, False for disabled alarms
        '''
        if cert_name in utils.CERT_SNAPSHOT:
            snapshot = utils.CERT_SNAPSHOT[cert_name]
            if snapshot.get(constants.CERT_ALARM_ANNOTATION_ALARM,
                            constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM) == 'disabled':
                LOG.info('Found annotation override, disabling alarm. Suppressing %s' %
                         cert_name)
                return False

        return True  # defaults to True (i.e., raise alarm)

    def audit_for_deleted_certificates(self):
        LOG.info('Auditing for deleted certificates')
        existing_ssl_ca_list = []
        for entry, _, _, _ in utils.collect_certificate_data_for_ssl_cas():
            existing_ssl_ca_list.append(entry)

        for alarm_instance in self.fm_obj.ALARMS_SNAPSHOT:
            entity_id = self.fm_obj.ALARMS_SNAPSHOT[alarm_instance][fm_mgr.ENTITY_ID]
            cert_name = utils.get_cert_name_with_entity_id(entity_id)
            k8_secret_deleted = False
            ssl_ca_deleted = False
            if cert_name is not None:
                snapshot = utils.CERT_SNAPSHOT[cert_name]
                kube_op = sys_kube.KubeOperator()
                # Some certificates which are saved as tls k8s secrets can be deleted by users or
                # other services in a running system. The below code block checks for those types
                # of certificates and saves its 'delete' status to var k8_secret_deleted
                if snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_SECRET or \
                        snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_CERT_MGR:
                    try:
                        k8_secret = kube_op.kube_get_secret(snapshot[utils.SNAPSHOT_KEY_k8s_secret],
                                                            snapshot[utils.SNAPSHOT_KEY_k8s_ns])
                        if not k8_secret:
                            k8_secret_deleted = True
                    except Exception as e:
                        LOG.error("Failed to retrieve k8s_secret %s" % e)

                if cert_name.startswith('ssl_ca') and (cert_name not in existing_ssl_ca_list):
                    ssl_ca_deleted = True

            if cert_name is None or k8_secret_deleted or ssl_ca_deleted:
                LOG.info('Found alarm for entity %s, but no related \
                         certificate resource' % entity_id)
                alarm_id = self.fm_obj.ALARMS_SNAPSHOT[alarm_instance][fm_mgr.ALARM_ID]
                # Clears the alarm
                self.fm_obj.set_fault(entity_id,
                                      alarm_id,
                                      fm_constants.FM_ALARM_STATE_CLEAR)
                # For certificates stored in tls secrets we need to completely delete their
                # snapshot information otherwise cert-alarm will attempt to re-create the alarm
                if k8_secret_deleted or ssl_ca_deleted:
                    del utils.CERT_SNAPSHOT[cert_name]
