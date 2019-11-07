#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright © 2012 eNovance <licensing@enovance.com>
#
# Author: Julien Danjou <julien@danjou.info>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import socket

from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service
from sysinv.openstack.common import context
from sysinv.openstack.common import periodic_task
from sysinv.openstack.common import rpc
from sysinv.openstack.common.rpc import service as rpc_service
from sysinv import version


cfg.CONF.register_opts([
    cfg.IntOpt('periodic_interval',
               default=60,
               help='seconds between running periodic tasks'),
    cfg.StrOpt('host',
               default=socket.getfqdn(),
               help='Name of this node.  This can be an opaque identifier.  '
               'It is not necessarily a hostname, FQDN, or IP address. '
               'However, the node name must be valid within '
               'an AMQP key, and if using ZeroMQ, a valid '
               'hostname, FQDN, or IP address'),
])

CONF = cfg.CONF


class PeriodicService(rpc_service.Service, periodic_task.PeriodicTasks):

    def start(self):
        super(PeriodicService, self).start()
        admin_context = context.RequestContext('admin', 'admin', is_admin=True)
        self.tg.add_timer(cfg.CONF.periodic_interval,
                          self.manager.periodic_tasks,
                          context=admin_context)


def prepare_service(argv=None):
    if argv is None:
        argv = []
    logging.register_options(cfg.CONF)

    extra_log_level_defaults = [
        'qpid.messaging=INFO',
        'keystoneclient=INFO',
        'eventlet.wsgi.server=WARN'
    ]
    logging.set_defaults(default_log_levels=logging.get_default_log_levels() +
                         extra_log_level_defaults)
    rpc.set_defaults(control_exchange='sysinv')
    cfg.CONF(argv[1:],
             project='sysinv',
             version=version.version_string())
    logging.setup(cfg.CONF, 'sysinv')


def process_launcher():
    return service.ProcessLauncher(CONF)
