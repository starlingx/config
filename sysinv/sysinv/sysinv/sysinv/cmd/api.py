# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
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
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#


"""The SysInv Service API."""

import six
import sys
from oslo_config import cfg
from oslo_log import log
from sysinv.common import exception
from sysinv.common import service as sysinv_service
from sysinv.common import wsgi_service
from sysinv import sanity_coverage

LOG = log.getLogger(__name__)
CONF = cfg.CONF


def sysinv_api():
    # Build and start the WSGI app
    launcher = sysinv_service.process_launcher()
    # server for API
    workers = CONF.sysinv_api_workers or 2

    server = None
    try:
        server = wsgi_service.WSGIService('sysinv_api',
                                          CONF.sysinv_api_bind_ip,
                                          CONF.sysinv_api_port,
                                          workers,
                                          False)
    except exception.ConfigInvalid as e:
        LOG.error(six.text_type(e))
        raise

    launcher.launch_service(server, workers=server.workers)
    return launcher


def sysinv_pxe():
    if not CONF.sysinv_api_pxeboot_ip:
        return None

    # Build and start the WSGI app
    launcher = sysinv_service.process_launcher()
    # server for API
    server = wsgi_service.WSGIService('sysinv_api_pxe',
                                      CONF.sysinv_api_pxeboot_ip,
                                      CONF.sysinv_api_port,
                                      1,
                                      False)
    launcher.launch_service(server, workers=server.workers)
    return launcher


def main():
    if sanity_coverage.flag_file_exists():
        sanity_coverage.start()
    # Parse config file and command line options
    sysinv_service.prepare_service(sys.argv)

    launcher_api = sysinv_api()
    launcher_pxe = sysinv_pxe()

    launcher_api.wait()
    if launcher_pxe:
        launcher_pxe.wait()


if __name__ == '__main__':
    sys.exit(main())
