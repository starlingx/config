#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from oslo_config import cfg
from oslo_log import log

from fm_api import constants as fm_constants
from fm_api import fm_api
from sysinv.cert_alarm import utils

LOG = log.getLogger(__name__)
CONF = cfg.CONF

SNAPSHOT_KEY_EXPIRING_SOON = 'EXPIRING_SOON'
SNAPSHOT_KEY_EXPIRED = 'EXPIRED'


class FaultApiMgr(object):
    def __init__(self):
        LOG.info('Initializing FaultApiMgr')
        self.fm_api = fm_api.FaultAPIs()
        self.ALARMS_SNAPSHOT = {}
        """
        After an audit is completed, ALARMS_SNAPSHOT stores all active alarms
        ALARMS_SNAPSHOT is a dict of list.
        {
            EXPIRING_SOON: [certname1, certname2,...]
            EXPIRED: [certname7, certname8,...]
        }
        """

    def get_entity_instance_id(self, cert_name):
        """
        Returns entity_instance_ids in format:
            system.certificate.mode=<mode>.uuid=<uuid>
            OR
            namespace=<namespace-name>.certificate=<certificate-name>
            OR
            namespace=<namespace-name>.secret=<secret-name>
            OR
            system.certificate.k8sRootCA
        """
        id = []
        if cert_name in utils.CERT_SNAPSHOT:
            snapshot = utils.CERT_SNAPSHOT[cert_name]
            if snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_UUID:
                id.append("system.certificate.mode=%s.uuid=%s" %
                    (cert_name, snapshot[utils.SNAPSHOT_KEY_uuid]))
            elif snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_CERT_MGR:
                id.append("namespace=%s.certificate=%s" %
                    (snapshot[utils.SNAPSHOT_KEY_k8s_ns], snapshot[utils.SNAPSHOT_KEY_k8s_cert]))
            elif snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_SECRET:
                id.append("namespace=%s.secret=%s" %
                    (snapshot[utils.SNAPSHOT_KEY_k8s_ns], snapshot[utils.SNAPSHOT_KEY_k8s_secret]))
            elif snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_OTHER:
                id.append("system.certificate.%s" % cert_name)

        id.append(" (%s=%s)" % (fm_constants.FM_ENTITY_TYPE_CERTIFICATE, cert_name))
        return ''.join(id)

    def get_cert_name_from_entity_instance_id(self, instance_id):
        start = "(" + fm_constants.FM_ENTITY_TYPE_CERTIFICATE
        return instance_id[instance_id.find(start) + 1:instance_id.find(")")]

    def get_reason_text(self, cert_name, expired_flag):
        txt = ["Certificate "]
        if cert_name in utils.CERT_SNAPSHOT:
            # Add entity related text
            snapshot = utils.CERT_SNAPSHOT[cert_name]
            if snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_UUID:
                txt.append("\'system certificate-show %s\' (mode=%s) " %
                    (snapshot[utils.SNAPSHOT_KEY_uuid], cert_name))
            elif snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_CERT_MGR:
                txt.append("namespace=%s, certificate=%s " %
                    (snapshot[utils.SNAPSHOT_KEY_k8s_ns], snapshot[utils.SNAPSHOT_KEY_k8s_cert]))
            elif snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_SECRET:
                txt.append("namespace=%s, secret=%s " %
                    (snapshot[utils.SNAPSHOT_KEY_k8s_ns], snapshot[utils.SNAPSHOT_KEY_k8s_secret]))
            elif snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_OTHER:
                txt.append(cert_name)

            # Add Expired or Expiring
            if expired_flag:
                txt.append(" expired.")
            else:
                expiry_date = snapshot[utils.SNAPSHOT_KEY_EXPDATE]
                txt.append(" is expiring soon on ")
                txt.append(expiry_date.strftime("%Y-%m-%d, %H:%M:%S"))

        else:
            LOG.error('Could not find certname %s in snapshot. Returning generic reason text' % cert_name)
            txt.append(cert_name)
            return ''.join(txt)

        txt_str = ''.join(txt)
        LOG.debug('Alarm text: %s' % txt_str)
        return txt_str

    def set_fault(self, cert_name, expired_flag, state):
        """
        Set Fault calls the FM API to raise or clear alarm
        Params: cert-name: certificate name
                expired_flag: True/False
                              Determines whether 'Expired' (True) or 'Expiring Soon' (False)
                              Also determines the severity Critical (True) or Major (False)
                state: will determine SET or CLEAR
        """

        LOG.info('set_fault called with cert_name=%s, expired_flag=%s, state=%s' %
                (cert_name, expired_flag, state))

        alrm_id = fm_constants.FM_ALARM_ID_CERT_EXPIRED if expired_flag \
                else fm_constants.FM_ALARM_ID_CERT_EXPIRING_SOON
        alrm_severity = fm_constants.FM_ALARM_SEVERITY_CRITICAL if expired_flag \
                else fm_constants.FM_ALARM_SEVERITY_MAJOR
        entity_inst_id = self.get_entity_instance_id(cert_name)

        if state == fm_constants.FM_ALARM_STATE_SET:
            # Raise alarm only if alarm does not already exist
            if not self.fm_api.get_fault(alrm_id, entity_inst_id):
                fault = fm_api.Fault(
                        alarm_id=alrm_id,
                        alarm_state=state,
                        entity_type_id=fm_constants.FM_ENTITY_TYPE_CERTIFICATE,
                        entity_instance_id=entity_inst_id,
                        severity=alrm_severity,
                        reason_text=self.get_reason_text(cert_name, expired_flag),
                        alarm_type=fm_constants.FM_ALARM_TYPE_9,  # security-service
                        probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_77,  # certificate-expiration
                        proposed_repair_action="Renew certificate for entity identified",
                        suppression=False,
                        service_affecting=False)

                self.fm_api.set_fault(fault)
        else:
            if self.fm_api.get_fault(alrm_id, entity_inst_id):
                self.fm_api.clear_fault(alrm_id, entity_inst_id)

    def get_faults(self, expired_flag):
        alrm_id = fm_constants.FM_ALARM_ID_CERT_EXPIRED if expired_flag \
                else fm_constants.FM_ALARM_ID_CERT_EXPIRING_SOON
        alarms = self.fm_api.get_faults_by_id(alrm_id)
        return alarms

    def collect_all_cert_alarms(self):
        LOG.debug('collect_all_cert_alarms called')

        # Expiring Soon alarms
        exp_soon_alarms = self.get_faults(False)
        self.add_alarms_snapshot(SNAPSHOT_KEY_EXPIRING_SOON, exp_soon_alarms)

        # Expired alarms
        exprd_alarms = self.get_faults(True)
        self.add_alarms_snapshot(SNAPSHOT_KEY_EXPIRED, exprd_alarms)

    def reset_alarms_snapshot(self):
        self.ALARMS_SNAPSHOT = {}

    def print_alarms_snapshot(self):
        LOG.info('Alarms snapshot = %s' % self.ALARMS_SNAPSHOT)

    def add_alarms_snapshot(self, key, alarms):
        cert_names = []
        if alarms:
            for item in alarms:
                cert_names.append(self.get_cert_name_from_entity_instance_id(item.entity_instance_id))

        self.ALARMS_SNAPSHOT[key] = cert_names
