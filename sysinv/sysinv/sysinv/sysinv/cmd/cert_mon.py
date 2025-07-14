# Copyright (c) 2020, 2022, 2025 Wind River Systems, Inc.
#
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
# SPDX-License-Identifier: Apache-2.0

from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


def main():
    logging.register_options(CONF)
    CONF(project='sysinv', prog='certmon')

    logging.set_defaults()
    logging.setup(cfg.CONF, 'certmon')

    from sysinv.cert_mon import service as cert_mon
    LOG.info("Configuration:")
    cfg.CONF.log_opt_values(LOG, logging.INFO)

    srv = cert_mon.CertificateMonitorService()
    launcher = service.launch(cfg.CONF, srv)

    launcher.wait()


if __name__ == '__main__':
    main()
