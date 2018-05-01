# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""Database setup and migration commands."""

from oslo_config import cfg

from sysinv.common import utils


INIT_VERSION = 0

_IMPL = None

db_opts = [
    cfg.StrOpt('backend',
               default='sqlalchemy',
               deprecated_name='db_backend',
               deprecated_group='DEFAULT',
               help='The backend to use for db'),
    cfg.BoolOpt('use_tpool',
                default=False,
                deprecated_name='dbapi_use_tpool',
                deprecated_group='DEFAULT',
                help='Enable the experimental use of thread pooling for '
                     'all DB API calls')
]

CONF = cfg.CONF


def get_backend():
    global _IMPL
    if not _IMPL:
        # if not hasattr(CONF, 'database_migrate'):
        CONF.register_opts(db_opts, 'database_migrate')

        cfg.CONF.import_opt('backend', 'oslo_db.options', group='database_migrate')
        _IMPL = utils.LazyPluggable(
                pivot='backend',
                config_group='database_migrate',
                sqlalchemy='sysinv.db.sqlalchemy.migration')

    return _IMPL


def db_sync(version=None):
    """Migrate the database to `version` or the most recent version."""
    # return IMPL.db_sync(version=version)
    return get_backend().db_sync(version=version)


def db_version():
    """Display the current database version."""
    # return IMPL.db_version()
    return get_backend().db_version()
