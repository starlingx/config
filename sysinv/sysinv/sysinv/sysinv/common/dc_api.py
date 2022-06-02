#
# Copyright (c) 2022 Wind River Systems, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import json

from oslo_log import log as logging

from sysinv.common import constants
from sysinv.common.rest_api import get_token
from sysinv.common.rest_api import rest_api_request

# well-known dcmanager upgrade completed events
DC_EVENT_PLATFORM_UPGRADE_COMPLETED = 'platform-upgrade-completed'
DC_EVENT_K8S_UPGRADE_COMPLETED = 'k8s-upgrade-completed'
DC_EVENT_KUBE_ROOTCA_UPDATE_COMPLETED = 'kube-rootca-update-completed'


LOG = logging.getLogger(__name__)


def notify_dcmanager(events):
    """Send list of upgrade completion events to dcmanager."""
    try:
        token = get_token(constants.SYSTEM_CONTROLLER_REGION)
        api_url = token.get_service_url("dcmanager", "dcmanager")
        api_cmd_headers = {
            'Content-type': 'application/json',
            'User-Agent': 'sysinv/1.0',
        }
        api_cmd = api_url + '/notifications'
        api_cmd_payload = json.dumps({'events': events})
        rest_api_request(token, "POST", api_cmd, api_cmd_headers,
                         api_cmd_payload)
    except Exception:
        LOG.exception("Failed to notify dcmanager of events: %s" % events)


def notify_dcmanager_platform_upgrade_completed():
    """Send the platform-upgrade-completed event to dcmanager."""
    notify_dcmanager([DC_EVENT_PLATFORM_UPGRADE_COMPLETED])


def notify_dcmanager_kubernetes_upgrade_completed():
    """Send the k8s-upgrade-completed event to dcmanager."""
    notify_dcmanager([DC_EVENT_K8S_UPGRADE_COMPLETED])


def notify_dcmanager_kube_rootca_update_completed():
    """Send the kube-rootca-update-completed event to dcmanager."""
    notify_dcmanager([DC_EVENT_KUBE_ROOTCA_UPDATE_COMPLETED])
