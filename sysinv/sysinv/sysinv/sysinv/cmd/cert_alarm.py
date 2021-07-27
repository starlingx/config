#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service
# from sysinv.cert_alarm import messaging

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


def main():
    logging.register_options(CONF)
    CONF(project='sysinv', prog='certalarm')

    common_opts = [
        cfg.StrOpt('host',
                   default='localhost',
                   help='hostname of the machine')
    ]
    CONF.register_opts(common_opts)

    logging.set_defaults()
    logging.setup(cfg.CONF, 'certalarm')
    # messaging.setup()

    from sysinv.cert_alarm import service as cert_alarm
    LOG.info("Configuration:")
    cfg.CONF.log_opt_values(LOG, logging.INFO)

    srv = cert_alarm.CertificateAlarmService()
    launcher = service.launch(cfg.CONF, srv)

    launcher.wait()


if __name__ == '__main__':
    main()
