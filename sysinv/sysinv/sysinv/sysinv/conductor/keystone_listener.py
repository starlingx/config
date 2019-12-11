#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2019 Intel Corporation
#
"""
Sysinv Keystone notification listener.
"""

import keyring
import oslo_messaging

from oslo_config import cfg
from oslo_log import log

from sysinv.common import constants
from sysinv.common import utils
from sysinv.db import api as dbapi

LOG = log.getLogger(__name__)

kube_app = None


class NotificationEndpoint(object):
    """Task which exposes the API for consuming priority based notifications.

    The Oslo notification framework delivers notifications based on priority to
    matching callback APIs as defined in its notification listener endpoint
    list.

    Currently from Keystone perspective, `info` API is sufficient as Keystone
    send notifications at `info` priority ONLY. Other priority level APIs
    (warn, error, critical, audit, debug) are not needed here.
    """
    filter_rule = oslo_messaging.NotificationFilter(
        event_type='identity.user.updated')

    def info(self, ctxt, publisher_id, event_type, payload, metadata):
        """Receives notification at info level."""
        global kube_app
        kube_app.audit_local_registry_secrets()
        return oslo_messaging.NotificationResult.HANDLED


def get_transport_url():
    try:
        db_api = dbapi.get_instance()
        address = db_api.address_get_by_name(
            utils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                      constants.NETWORK_TYPE_MGMT)
        )

    except Exception as e:
        LOG.error("Failed to get management IP address: %s" % str(e))
        return None

    auth_password = keyring.get_password('amqp', 'rabbit')

    transport_url = "rabbit://guest:%s@%s:5672" % (auth_password, address.address)
    return transport_url


def start_keystone_listener(app):

    global kube_app
    kube_app = app

    conf = cfg.ConfigOpts()
    conf.transport_url = get_transport_url()

    if conf.transport_url is None:
        return

    transport = oslo_messaging.get_rpc_transport(conf)
    targets = [
        oslo_messaging.Target(exchange='keystone', topic='notifications', fanout=True),
    ]
    endpoints = [
        NotificationEndpoint(),
    ]

    pool = "sysinv-keystone-listener-workers"
    server = oslo_messaging.get_notification_listener(transport, targets,
                                                      endpoints, pool=pool)
    LOG.info("Sysinv keystone listener started!")
    server.start()
    server.wait()
