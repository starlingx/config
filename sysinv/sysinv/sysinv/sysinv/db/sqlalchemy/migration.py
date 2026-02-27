# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010-2026 United States Government as represented by the
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

import os
import sqlalchemy

from oslo_db.sqlalchemy import enginefacade
from sysinv._i18n import _
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common.utils import get_debian_codename

codename = get_debian_codename()

if codename == constants.OS_DEBIAN_BULLSEYE:
    from migrate import exceptions as versioning_exceptions
    from migrate.versioning import api as versioning_api
    from migrate.versioning.repository import Repository
else:
    from alembic import command
    from alembic.config import Config
    from alembic.runtime.migration import MigrationContext

# Maps legacy sqlalchemy-migrate versions to their equivalent Alembic revisions.
# 143 corresponds to stx11 (N-1) and 145 corresponds to stx12 (N-2),
# allowing upgrades from these supported versions to be bridged into Alembic control.
LEGACY_TO_ALEMBIC_REVISION = {
    143: "642ec4287884",
    145: "b5f3c9d2e1a7",
}

_REPOSITORY = None


def get_engine():
    return enginefacade.get_legacy_facade().get_engine()


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Bullseye: sqlalchemy-migrate based migration
# ---------------------------------------------------------------------------
if codename == constants.OS_DEBIAN_BULLSEYE:

    def db_sync(version=None):
        if version is not None:
            try:
                version = int(version)
            except ValueError:
                raise exception.SysinvException(
                    _("version should be an integer"))

        current_version = db_version()
        repository = _find_migrate_repo()
        if version is None or version > current_version:
            return versioning_api.upgrade(get_engine(), repository, version)
        else:
            return versioning_api.downgrade(get_engine(), repository, version)

    def db_version():
        repository = _find_migrate_repo()
        try:
            return versioning_api.db_version(get_engine(), repository)
        except versioning_exceptions.DatabaseNotControlledError:
            meta = sqlalchemy.MetaData()
            engine = get_engine()
            meta.reflect(bind=engine)
            tables = meta.tables
            if len(tables) == 0:
                db_version_control(0)
                return versioning_api.db_version(get_engine(), repository)
            else:
                raise exception.SysinvException(
                    _("Upgrade DB using Essex release first."))

    def db_version_control(version=None):
        repository = _find_migrate_repo()
        versioning_api.version_control(get_engine(), repository, version)
        return version

    def _find_migrate_repo():
        global _REPOSITORY
        path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                            'migrate_repo')
        assert os.path.exists(path)
        if _REPOSITORY is None:
            _REPOSITORY = Repository(path)
        return _REPOSITORY
else:

    def db_sync(version=None):
        if version is not None and str(version).isdigit():
            raise exception.Invalid(
                'You requested an sqlalchemy-migrate database version; this is '
                'no longer supported'
            )

        engine = get_engine()

        with engine.begin() as connection:
            config = _get_alembic_config(connection)
            db_version(connection=connection)

            if version is None:
                command.upgrade(config, "head")
            else:
                command.upgrade(config, version)

    def db_version(connection=None):
        if connection is None:
            with get_engine().begin() as conn:
                return db_version(connection=conn)

        try:
            context = MigrationContext.configure(connection)
            current_rev = context.get_current_revision()
        except Exception as exc:
            raise exception.SysinvException(
                _("Failed to determine Alembic revision: %s") % exc
            )

        if current_rev is not None:
            return current_rev

        inspector = sqlalchemy.inspect(connection)
        tables = inspector.get_table_names()

        if len(tables) == 0:
            cfg = _get_alembic_config(connection)
            command.stamp(cfg, "base")
            return "base"

        if "migrate_version" not in tables:
            raise exception.SysinvException(
                _("Upgrade to 25.09 or 26.03 first")
            )

        legacy_version = connection.execute(
            sqlalchemy.text("SELECT version FROM migrate_version")
        ).scalar()

        if legacy_version not in LEGACY_TO_ALEMBIC_REVISION:
            raise exception.SysinvException(
                _("Upgrade to 25.09 or 26.03 first")
            )

        alembic_revision = LEGACY_TO_ALEMBIC_REVISION[legacy_version]
        cfg = _get_alembic_config(connection)
        command.stamp(cfg, alembic_revision)
        return alembic_revision

    def db_version_control(version=None, connection=None):
        if connection is None:
            with get_engine().begin() as conn:
                return db_version_control(version=version, connection=conn)

        cfg = _get_alembic_config(connection)
        revision = "base" if version is None else version
        command.stamp(cfg, revision)
        return revision

    def _get_alembic_config(connection=None):
        config_path = os.path.join(os.path.dirname(__file__), 'alembic.ini')
        config = Config(config_path)

        raw_url = (
            f"postgresql+psycopg2://{get_engine().url.username}:"
            f"{get_engine().url.password}@{get_engine().url.host}/sysinv"
        )
        config.set_main_option('sqlalchemy.url', raw_url)

        if connection is not None:
            config.attributes['connection'] = connection  # pylint: disable=unsupported-assignment-operation

        return config

# ---------------------------------------------------------------------------
# Trixie: Alembic-based migration
# ---------------------------------------------------------------------------
