# Copyright (c) 2016-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan
from pecan import rest
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import utils
from sysinv.common import kubernetes
from sysinv.common import utils as cutils

LOG = log.getLogger(__name__)


class HealthController(rest.RestController):
    """REST controller for System Health."""

    def __init__(self):
        self._api_token = None

    @wsme_pecan.wsexpose(wtypes.text)
    def get_all(self):
        """Provides information about the health of the system"""
        try:
            success, output = pecan.request.rpcapi.get_system_health(
                pecan.request.context)
        except Exception as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_(
                "Unable to perform health query."))
        return output

    @staticmethod
    def _get_kube_upgrade_alarm_ignore_list(alarm_ignore_list,
                                            use_default_ignore_list):
        """Builds the alarm ignore list for a kube upgrade health query.

        The caller-supplied list is normalized to a list of alarm ids so
        that the health check matches whole alarm ids instead of doing a
        substring search on the raw string.

        A value that is rejected by the parser is reported to the caller
        rather than discarded. parse_alarm_ignore_list cannot raise: it
        is shared with the kube-upgrade-start request body, where an
        existing client would break. So the loud failure lives here,
        where the parameter is new: if the caller supplied something and
        nothing came back, the list was dropped and the caller has to
        know, instead of reading a [Fail] verdict that silently ignored
        no alarm at all.

        When use_default_ignore_list is requested, the server-side
        default list is added to the caller-supplied one. The two lists
        are merged rather than replaced so that an orchestrator passing
        its own list does not lose the server-side defaults, which is the
        same behaviour as the kube-upgrade-start request.
        """
        ignore_list = cutils.parse_alarm_ignore_list(alarm_ignore_list)
        if not ignore_list and (alarm_ignore_list or '').strip():
            raise wsme.exc.ClientSideError(
                _("Invalid value '%(value)s' for parameter "
                  "'alarm_ignore_list'. Expected a comma separated list of "
                  "alarm ids, for example '900.007,900.401'.")
                % {'value': alarm_ignore_list})
        if use_default_ignore_list:
            ignore_list = sorted(
                set(kubernetes.get_kube_upgrade_alarm_ignore_list())
                | set(ignore_list))
        return ignore_list

    @wsme_pecan.wsexpose(wtypes.text, wtypes.text, wtypes.text, wtypes.text,
                         wtypes.text, wtypes.text)
    def get_one(self, upgrade, relaxed=None, rootca=None,
                alarm_ignore_list=None, use_default_ignore_list=None):
        """Validates the health of the system for an upgrade"""
        # relaxed is a path segment, not a query string parameter: the
        # request is /health/<type>/relaxed and the value that arrives is
        # the segment text. It is deliberately not run through
        # utils.boolean_param, which would reject it.
        force = False
        if relaxed:
            force = True
        if upgrade == 'upgrade':
            try:
                success, output = pecan.request.rpcapi.get_system_health(
                    pecan.request.context, upgrade=True, force=force)
            except Exception as e:
                LOG.exception(e)
                raise wsme.exc.ClientSideError(_(
                    "Unable to perform health upgrade query."))
            return output
        elif upgrade == 'kube-upgrade':
            # rootca is deliberately left uncoerced. It is forwarded as
            # the raw query string text, and the health check tests it
            # with a plain truthiness check, so '?rootca=false' enables
            # the rootca checks rather than skipping them. That is a
            # pre-existing defect: it predates this parameter, fixing it
            # changes the behaviour of an existing one, and it is left to
            # its own change rather than done as a side effect of adding
            # use_default_ignore_list. Do not read its absence from
            # boolean_param as a statement that it is correct.
            use_defaults = utils.boolean_param(
                'use_default_ignore_list', use_default_ignore_list)
            ignore_list = self._get_kube_upgrade_alarm_ignore_list(
                alarm_ignore_list, use_defaults)
            try:
                success, output = pecan.request.rpcapi.get_system_health(
                    pecan.request.context, kube_upgrade=True, force=force,
                    kube_rootca_update=rootca,
                    alarm_ignore_list=ignore_list)
            except Exception as e:
                LOG.exception(e)
                raise wsme.exc.ClientSideError(_(
                    "Unable to perform kubernetes health upgrade query."))
            return output
        else:
            raise wsme.exc.ClientSideError(
                _("Unsupported upgrade type %s.") % upgrade)
