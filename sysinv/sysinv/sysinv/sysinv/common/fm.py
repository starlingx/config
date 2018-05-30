#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


# FM Fault Management Handling

from fm_api import constants as fm_constants
from fm_api import fm_api
from sysinv.openstack.common import log

LOG = log.getLogger(__name__)


class FmCustomerLog(object):
    """
    Fault Management Customer Log
    """

    _fm_api = None

    def __init__(self):
        self._fm_api = fm_api.FaultAPIs()

    def customer_log(self, log_data):
        LOG.info("Generating FM Customer Log %s" % log_data)
        fm_event_id = log_data.get('event_id', None)
        if fm_event_id is not None:
            fm_event_state = fm_constants.FM_ALARM_STATE_MSG
            entity_type = log_data.get('entity_type', None)
            entity = log_data.get('entity', None)
            fm_severity = log_data.get('fm_severity', None)
            reason_text = log_data.get('reason_text', None)
            fm_event_type = log_data.get('fm_event_type', None)
            fm_probable_cause = fm_constants.ALARM_PROBABLE_CAUSE_UNKNOWN
            fm_uuid = None
            fault = fm_api.Fault(fm_event_id,
                                 fm_event_state,
                                 entity_type,
                                 entity,
                                 fm_severity,
                                 reason_text,
                                 fm_event_type,
                                 fm_probable_cause, "",
                                 False, True)

            response = self._fm_api.set_fault(fault)
            if response is None:
                LOG.error("Failed to generate customer log, fm_uuid=%s." %
                          fm_uuid)
            else:
                fm_uuid = response
                LOG.info("Generated customer log, fm_uuid=%s." % fm_uuid)
        else:
            LOG.error("Unknown event id (%s) given." % fm_event_id)
