#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
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

"""
The Sysinv Management Service
"""

import sys

from oslo_config import cfg

from oslo_service import service

from sysinv.common import service as sysinv_service
from sysinv.conductor import manager
from sysinv import sanity_coverage

CONF = cfg.CONF


def main():
    if sanity_coverage.flag_file_exists():
        sanity_coverage.start()
    # Pase config file and command line options, then start logging
    sysinv_service.prepare_service(sys.argv)

    mgr = manager.ConductorManager(CONF.host, manager.MANAGER_TOPIC)
    launcher = service.launch(CONF, mgr)
    launcher.wait()
