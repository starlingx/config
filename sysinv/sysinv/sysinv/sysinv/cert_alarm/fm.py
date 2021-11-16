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
from sysinv.common import constants

LOG = log.getLogger(__name__)
CONF = cfg.CONF

ALARM_ID = 'ALARM_ID'
ENTITY_ID = 'ENTITY_ID'
EXPIRING_SOON = 'EXPIRING_SOON'
EXPIRED = 'EXPIRED'


class FaultApiMgr(object):
    def __init__(self):
        LOG.info('Initializing FaultApiMgr')
        self.fm_api = fm_api.FaultAPIs()
        """
        After an audit is completed, ALARMS_SNAPSHOT stores all active alarms
        ALARMS_SNAPSHOT is a dict of dict. Each entry is per certificate.
        {
            alarm_uuid_1: {
                ALARM_ID: FM_ALARM_ID_CERT_EXPIRED or FM_ALARM_ID_CERT_EXPIRING_SOON
                ENTITY_ID: entity_instance_id returned from FM API
            }
            alarm_uuid_2: {
                ...
            }
        }
        """
        self.ALARMS_SNAPSHOT = {}

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
        tmp_id = []
        if cert_name in utils.CERT_SNAPSHOT:
            snapshot = utils.CERT_SNAPSHOT[cert_name]
            if snapshot[utils.SNAPSHOT_KEY_MODE] is utils.UUID:
                tmp_id.append("system.certificate.mode=%s.uuid=%s" %
                    (self.get_mode(cert_name), snapshot[utils.UUID]))
            elif snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_CERT_MGR:
                tmp_id.append("namespace=%s.certificate=%s" %
                    (snapshot[utils.SNAPSHOT_KEY_k8s_ns], snapshot[utils.SNAPSHOT_KEY_k8s_cert]))
            elif snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_SECRET:
                tmp_id.append("namespace=%s.secret=%s" %
                    (snapshot[utils.SNAPSHOT_KEY_k8s_ns], snapshot[utils.SNAPSHOT_KEY_k8s_secret]))
            elif snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_OTHER:
                tmp_id.append("system.certificate.%s" % cert_name)

        entity_id = ''.join(tmp_id)
        return entity_id

    @staticmethod
    def get_mode(cert_name):
        return 'ssl_ca' if 'ssl_ca' in cert_name else cert_name

    def get_reason_text(self, entity_id, alrm_id):
        txt = []
        cert_name = utils.get_cert_name_with_entity_id(entity_id)
        if cert_name is None:
            LOG.eror('Error retrieving certificate from snapshot. Returning entity_id')
            txt.append(entity_id)
            return ''.join(txt)

        if cert_name in utils.CERT_SNAPSHOT:
            # Add entity related text
            snapshot = utils.CERT_SNAPSHOT[cert_name]

            # Append alarm_text from annotation as pre-text
            pretext = snapshot.get(constants.CERT_ALARM_ANNOTATION_ALARM_TEXT,
                                   constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_TEXT)
            if len(pretext) > 0:
                txt.append(pretext)
                txt.append(' ')

            txt.append("Certificate ")
            if snapshot[utils.SNAPSHOT_KEY_MODE] is utils.UUID:
                txt.append("\'system certificate-show %s\' (mode=%s) " %
                    (snapshot[utils.UUID], self.get_mode(cert_name)))
            elif snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_CERT_MGR:
                txt.append("namespace=%s, certificate=%s " %
                    (snapshot[utils.SNAPSHOT_KEY_k8s_ns], snapshot[utils.SNAPSHOT_KEY_k8s_cert]))
            elif snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_SECRET:
                txt.append("namespace=%s, secret=%s " %
                    (snapshot[utils.SNAPSHOT_KEY_k8s_ns], snapshot[utils.SNAPSHOT_KEY_k8s_secret]))
            elif snapshot[utils.SNAPSHOT_KEY_MODE] is utils.MODE_OTHER:
                txt.append(cert_name)
                txt.append(' ')

            # Add Expired or Expiring
            if alrm_id == fm_constants.FM_ALARM_ID_CERT_EXPIRED:
                txt.append("expired.")
            else:
                expiry_date = snapshot[utils.SNAPSHOT_KEY_EXPDATE]
                txt.append("is expiring soon on ")
                txt.append(expiry_date.strftime("%Y-%m-%d, %H:%M:%S"))

        else:
            LOG.error('Could not find certname %s in snapshot. Returning generic reason text' % cert_name)
            txt.append(cert_name)
            return ''.join(txt)

        txt_str = ''.join(txt)
        LOG.debug('Alarm text: %s' % txt_str)
        return txt_str

    def get_severity(self, entity_id, alrm_id):
        alarm_severity = fm_constants.FM_ALARM_SEVERITY_CRITICAL if \
                         alrm_id == fm_constants.FM_ALARM_ID_CERT_EXPIRED \
                         else fm_constants.FM_ALARM_SEVERITY_MAJOR

        cert_name = utils.get_cert_name_with_entity_id(entity_id)
        if cert_name is None:
            LOG.error('Error retrieving certificate from snapshot. Using default severity')
            return alarm_severity

        # Check for annotation overrides
        if cert_name in utils.CERT_SNAPSHOT:
            snapshot = utils.CERT_SNAPSHOT[cert_name]
            override = snapshot.get(constants.CERT_ALARM_ANNOTATION_ALARM_SEVERITY,
                                    alarm_severity)
            if override != "unknown":  # Cannot have "unknown" for fault severity
                alarm_severity = override

        return alarm_severity

    def set_fault(self, entity_inst_id, alrm_id, state):
        '''
        Set Fault calls the FM API to raise or clear alarm
        Params: entity_inst_id: entity id for alarm
                alrm_id: fm_constants.FM_ALARM_ID_CERT_EXPIRED or
                        fm_constant.FM_ALARM_ID_CERT_EXPIRING_SOON
                state: will determine SET or CLEAR
        '''

        # If case of api errors during data collection, we do not want to raise alarms with
        # "unknown" UUID (because we will need to clear such alarms manually). In such a case,
        # we log the error and skip the alarm raise. Subsequent audit runs will raise the alarms.
        if entity_inst_id is None or "uuid=unknown" in entity_inst_id:
            LOG.error('set_fault called for certificate %s with unknown UUID. Suppressing alarm' %
                      entity_inst_id)
            return

        try:
            if state == fm_constants.FM_ALARM_STATE_SET:
                # Raise alarm only if alarm does not already exist
                if not self.fm_api.get_fault(alrm_id, entity_inst_id):
                    fault = fm_api.Fault(
                            alarm_id=alrm_id,
                            alarm_state=state,
                            entity_type_id=fm_constants.FM_ENTITY_TYPE_CERTIFICATE,
                            entity_instance_id=entity_inst_id,
                            severity=self.get_severity(entity_inst_id, alrm_id),
                            reason_text=self.get_reason_text(entity_inst_id, alrm_id),
                            alarm_type=fm_constants.FM_ALARM_TYPE_9,
                            probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_77,
                            proposed_repair_action="Renew certificate for entity identified",
                            suppression=False,
                            service_affecting=False)

                    LOG.info('Setting fault for entity_id=%s, alarm_type=%s, state=%s' %
                            (entity_inst_id, alrm_id, state))
                    alarm_uuid = self.fm_api.set_fault(fault)
                    # Update CERT_SNAPSHOT
                    utils.update_cert_snapshot_field_with_entity_id(entity_inst_id,
                                                                    utils.ALARM_UUID,
                                                                    alarm_uuid)
            else:
                if self.fm_api.get_fault(alrm_id, entity_inst_id):
                    LOG.info('Setting fault for entity_id=%s, alarm_type=%s, state=%s' %
                            (entity_inst_id, alrm_id, state))
                    self.fm_api.clear_fault(alrm_id, entity_inst_id)
                    # Update CERT_SNAPSHOT
                    utils.update_cert_snapshot_field_with_entity_id(entity_inst_id,
                                                                    utils.ALARM_UUID,
                                                                    "")

        except Exception as e:
            LOG.exception(e)

    def get_faults(self, expired_flag):
        alrm_id = fm_constants.FM_ALARM_ID_CERT_EXPIRED if expired_flag \
                else fm_constants.FM_ALARM_ID_CERT_EXPIRING_SOON
        alarms = None
        try:
            alarms = self.fm_api.get_faults_by_id(alrm_id)
        except Exception as e:
            LOG.exception(e)
        return alarms

    def collect_all_cert_alarms(self):
        LOG.debug('collect_all_cert_alarms called')

        # Expiring Soon alarms
        exp_soon_alarms = self.get_faults(False)
        self.add_alarms_snapshot(fm_constants.FM_ALARM_ID_CERT_EXPIRING_SOON,
                                exp_soon_alarms)

        # Expired alarms
        exprd_alarms = self.get_faults(True)
        self.add_alarms_snapshot(fm_constants.FM_ALARM_ID_CERT_EXPIRED,
                                 exprd_alarms)

    def reset_alarms_snapshot(self):
        self.ALARMS_SNAPSHOT = {}

    def print_alarms_snapshot(self):
        LOG.info('Alarms snapshot = %s' % self.ALARMS_SNAPSHOT)

    def add_alarms_snapshot(self, alarm_type, alarms):
        if alarms:
            for item in alarms:
                self.ALARMS_SNAPSHOT[item.uuid] = {
                    ALARM_ID: alarm_type,
                    ENTITY_ID: item.entity_instance_id
                }
