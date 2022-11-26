#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2019 Intel Corporation
# Copyright (c) 2021-2022 Wind River Systems, Inc.
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
from sysinv.conductor import openstack
from sysinv.db import api as dbapi

LOG = log.getLogger(__name__)


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

    def __init__(self, endpoints):
        self.endpoints = endpoints
        self.dbapi = dbapi.get_instance()
        self._openstack = openstack.OpenStackOperator(self.dbapi)

    def info(self, ctxt, publisher_id, event_type, payload, metadata):
        """Receives notification at info level."""

        LOG.info("Received a notification: %s" % str(payload))

        if payload.get('eventType') == 'activity' and \
                payload.get('action') == 'updated.user' and \
                payload.get('outcome') == 'success':
            user_list = self._openstack.get_keystone_users()
            if user_list:
                for user in user_list:
                    if payload.get('resource_info') == user.id:
                        for endpoint in self.endpoints:
                            username = endpoint.get('user')
                            if username == user.name:
                                callback_func = endpoint.get('function')
                                context = endpoint.get('context')
                                LOG.info("Executing callback function for user: %s"
                                         % username)
                                callback_func(context, username)
                        break

        return oslo_messaging.NotificationResult.HANDLED


def get_transport_url():
    try:
        db_api = dbapi.get_instance()
        network_object = db_api.address_get_by_name(
            utils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                      constants.NETWORK_TYPE_MGMT)
        )

    except Exception as e:
        LOG.error("Failed to get management IP address: %s" % str(e))
        return None

    auth_password = keyring.get_password('amqp', 'rabbit')

    if utils.is_valid_ipv6(network_object.address):
        ip_address = "[%s]" % network_object.address
    else:
        ip_address = "%s" % network_object.address

    transport_url = "rabbit://guest:%s@%s:5672" % (auth_password, ip_address)
    return transport_url


def start_keystone_listener(callback_endpoints):
    conf = cfg.ConfigOpts()
    conf.transport_url = get_transport_url()

    if conf.transport_url is None:
        return

    transport = oslo_messaging.get_rpc_transport(conf)
    targets = [
        oslo_messaging.Target(exchange='keystone', topic='notifications', fanout=True),
    ]

    endpoints = [
        NotificationEndpoint(callback_endpoints)
    ]

    pool = "sysinv-keystone-listener-workers"
    server = oslo_messaging.get_notification_listener(transport, targets,
                                                      endpoints, pool=pool)
    LOG.info("Sysinv keystone listener started!")
    server.start()
    server.wait()
