# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
# Copyright 2012 Red Hat, Inc.
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

from oslo_config import cfg

from sysinv.common import paths
from oslo_db import options as db_options
from sysinv.openstack.common import rpc
from sysinv import version

_DEFAULT_SQL_CONNECTION = 'sqlite:///' + paths.state_path_def('sysinv.sqlite')

db_options.set_defaults(cfg.CONF, connection=_DEFAULT_SQL_CONNECTION)


def parse_args(argv, default_config_files=None):
    rpc.set_defaults(control_exchange='sysinv')
    cfg.CONF(argv[1:],
             project='sysinv',
             version=version.version_string(),
             default_config_files=default_config_files)
