#
# Copyright (c) 2016-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


# FM Fault Management Handling

from keystoneauth1.access import service_catalog as k_service_catalog
from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils

from fm_api import constants as fm_constants
import fmclient as fm_client

CONF = cfg.CONF

LOG = log.getLogger(__name__)


fm_group = cfg.OptGroup(
    'fm',
    title='FM Options',
    help="Configuration options for the fault management service")

fm_opts = [
    cfg.StrOpt('catalog_info',
               default='faultmanagement:fm:internalURL',
               help="Service catalog Look up info."),
    cfg.StrOpt('os_region_name',
               default='RegionOne',
               help="Region name of this node. It is used for catalog lookup")
]

CONF.register_group(fm_group)
CONF.register_opts(fm_opts, group=fm_group)


class FmCustomerLog(object):
    """
    Fault Management Customer Log
    """

    _fm_api = None

    def __init__(self):
        self._fm_api = _get_fm_api().FaultAPIs()

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
            fault = _get_fm_api().Fault(fm_event_id,
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


def fmclient(context, version=1, endpoint=None):
    """Constructs a fm client object for making API requests.

    :param context: The request context for auth.
    :param version: API endpoint version.
    :param endpoint: Optional If the endpoint is not available, it will be
                     retrieved from context
    """
    auth_token = context.auth_token
    if endpoint is None:
        sc = k_service_catalog.ServiceCatalogV2(context.service_catalog)
        service_type, service_name, interface = \
            CONF.fm.catalog_info.split(':')
        service_parameters = {'service_type': service_type,
                              'service_name': service_name,
                              'interface': interface,
                              'region_name': CONF.fm.os_region_name}
        endpoint = sc.url_for(**service_parameters)

    return fm_client.Client(version=version,
                            endpoint=endpoint,
                            auth_token=auth_token)


def get_fm_region():
    return CONF.fm.os_region_name


_FMAPI = None


def _get_fm_api():
    """Delay import of fm api for unit tests."""
    global _FMAPI
    if _FMAPI is None:
        _FMAPI = importutils.import_module('fm_api.fm_api')
    return _FMAPI
