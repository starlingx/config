# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan
from pecan import rest
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import types
from sysinv.common import constants
from sysinv.common import exception
from sysinv.api.controllers.v1 import vim_api

LOG = log.getLogger(__name__)


class VIMHostAudit(base.APIBase):
    """API representation of a host audit operation."""

    vim_event = wtypes.text
    "The VIM event"

    def __init__(self, **kwargs):
        self.fields = ['vim_event']
        for k in self.fields:
            setattr(self, k, kwargs.get(k))


class VIMHostAuditResponse(base.APIBase):
    """API representation of a host audit operation."""

    hostname = wtypes.text
    "The hostname of the host being audited"

    ihost_uuid = types.uuid
    "The UUID of the host being audited"

    vim_event = wtypes.text
    "The VIM event"

    def __init__(self, **kwargs):
        self.fields = ['hostname', 'ihost_uuid', 'vim_event']
        for k in self.fields:
            setattr(self, k, kwargs.get(k))


class VIMController(rest.RestController):
    """REST controller for VIM operations."""

    def __init__(self):
        self._api_token = None

    # POST ihosts/<uuid>/vim
    @wsme_pecan.wsexpose(VIMHostAuditResponse, types.uuid, body=VIMHostAudit)
    def post(self, host_uuid, event_request):
        """Perform host audit operation on specified hosts."""

        host = pecan.request.dbapi.ihost_get(host_uuid)

        if event_request.vim_event != constants.HOST_AUDIT_ACTION:
            raise exception.InvalidVIMAction(vim_event=event_request.vim_event)

        try:
            vim_api.vim_host_action(
                token=self._api_token,
                uuid=host_uuid,
                hostname=host.hostname,
                action=constants.HOST_AUDIT_ACTION,
                timeout=constants.VIM_DEFAULT_TIMEOUT_IN_SECS,
            )

        except Exception as e:
            raise exception.CannotTriggerVIMHostAudit(hostname=host.hostname) from e

        return VIMHostAuditResponse(
            hostname=host.hostname,
            ihost_uuid=host.uuid,
            vim_event=constants.HOST_AUDIT_ACTION,
        )
