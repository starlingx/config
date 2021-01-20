#
# Copyright (c) 2015-2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

#
# This file contains functions used by sysinv to manage upgrades.
#
import json
import glob
import os
import shutil
import subprocess
import yaml

import tsconfig.tsconfig as tsc

from sysinv.common import constants as sysinv_constants
from controllerconfig.upgrades import utils

from oslo_log import log

LOG = log.getLogger(__name__)


def get_upgrade_databases(system_role, shared_services):

    UPGRADE_DATABASES = ('postgres', 'template1', 'sysinv',
                         'barbican', 'fm', 'helmv2')

    UPGRADE_DATABASE_SKIP_TABLES = {'postgres': (), 'template1': (),
                                    'sysinv': (),
                                    'barbican': (),
                                    'fm': ('alarm',),
                                    'helmv2': ()}

    if system_role == sysinv_constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
        UPGRADE_DATABASES += ('dcmanager', 'dcorch',)
        UPGRADE_DATABASE_SKIP_TABLES.update({
            'dcmanager': (),
            'dcorch': ('service', 'orch_job', 'orch_request',)
        })

    if sysinv_constants.SERVICE_TYPE_IDENTITY not in shared_services:
        UPGRADE_DATABASES += ('keystone',)
        UPGRADE_DATABASE_SKIP_TABLES.update({'keystone': ('token',)})

    return UPGRADE_DATABASES, UPGRADE_DATABASE_SKIP_TABLES


def export_postgres(dest_dir, system_role, shared_services):
    """ Export postgres databases """
    devnull = open(os.devnull, 'w')
    try:
        upgrade_databases, upgrade_database_skip_tables = \
            get_upgrade_databases(system_role, shared_services)
        # Dump roles, table spaces and schemas for databases.
        subprocess.check_call([('sudo -u postgres pg_dumpall --clean ' +
                                '--schema-only > %s/%s' %
                                (dest_dir, 'postgres.postgreSql.config'))],
                              shell=True, stderr=devnull)

        # Dump data for databases.
        for _a, db_elem in enumerate(upgrade_databases):

            db_cmd = 'sudo -u postgres pg_dump --format=plain --inserts '
            db_cmd += '--disable-triggers --data-only %s ' % db_elem

            for _b, table_elem in \
                    enumerate(upgrade_database_skip_tables[db_elem]):
                db_cmd += '--exclude-table=%s ' % table_elem

            db_cmd += '> %s/%s.postgreSql.data' % (dest_dir, db_elem)

            subprocess.check_call([db_cmd], shell=True, stderr=devnull)

    except subprocess.CalledProcessError:
        LOG.exception("Failed to export postgres databases for upgrade.")
        raise


def export_vim(dest_dir):
    """ Export VIM database """
    devnull = open(os.devnull, 'w')
    try:
        vim_cmd = ("nfv-vim-manage db-dump-data -d %s -f %s" %
                   (os.path.join(tsc.PLATFORM_PATH, 'nfv/vim', tsc.SW_VERSION),
                    os.path.join(dest_dir, 'vim.data')))
        subprocess.check_call([vim_cmd], shell=True, stderr=devnull)

    except subprocess.CalledProcessError:
        LOG.exception("Failed to export VIM databases for upgrade.")
        raise


def prepare_upgrade(from_load, to_load, i_system, mgmt_address):
    """ Executed on the release N side to prepare for an upgrade. """
    devnull = open(os.devnull, 'w')

    LOG.info("Starting upgrade preparations - from: %s, to: %s" %
             (from_load, to_load))
    dest_dir = os.path.join(utils.POSTGRES_PATH, "upgrade")
    try:
        os.mkdir(dest_dir, 0o755)
    except OSError:
        LOG.exception("Failed to create upgrade export directory %s." %
                      dest_dir)
        raise

    # Export databases
    shared_services = i_system.capabilities.get("shared_services", "")
    export_postgres(dest_dir, i_system.distributed_cloud_role, shared_services)
    export_vim(dest_dir)

    # Export filesystems so controller-1 can access them
    try:
        subprocess.check_call(
            ["exportfs",
             "%s:%s" % (utils.CONTROLLER_1_HOSTNAME, utils.POSTGRES_PATH),
             "-o",
             "rw,no_root_squash"],
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to export %s" % utils.POSTGRES_PATH)
        raise
    try:
        subprocess.check_call(
            ["exportfs",
             "%s:%s" % (utils.CONTROLLER_1_HOSTNAME, utils.RABBIT_PATH),
             "-o",
             "rw,no_root_squash"],
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to export %s" % utils.RABBIT_PATH)
        raise

    # Migrate /opt/platform/config so controller-1 can access when it
    # runs controller_config
    try:
        subprocess.check_call(
            ["cp",
             "-a",
             os.path.join(tsc.PLATFORM_PATH, "config", from_load),
             os.path.join(tsc.PLATFORM_PATH, "config", to_load)],
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to migrate %s" % os.path.join(tsc.PLATFORM_PATH,
                                                            "config"))
        raise

    # Point N+1 etcd to N for now. We will migrate when both controllers are
    # running N+1, during the swact back to controller-0. This solution will
    # present some problems when we do upgrade etcd, so further development
    # will be required at that time.
    etcd_to_dir = os.path.join(tsc.ETCD_PATH, to_load)
    etcd_from_dir = os.path.join(tsc.ETCD_PATH, from_load)
    os.symlink(etcd_from_dir, etcd_to_dir)

    # Copy /etc/kubernetes/admin.conf so controller-1 can access
    # during its upgrade
    try:
        subprocess.check_call(
            ["cp",
             os.path.join(utils.KUBERNETES_CONF_PATH,
                          utils.KUBERNETES_ADMIN_CONF_FILE),
             os.path.join(tsc.PLATFORM_PATH, "config", to_load,
                          "kubernetes", utils.KUBERNETES_ADMIN_CONF_FILE)],
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to copy %s" %
                      os.path.join(utils.KUBERNETES_CONF_PATH,
                                   utils.KUBERNETES_ADMIN_CONF_FILE))
        raise

    # Update admin.conf file to replace the cluster address with
    # the floating management address
    # This is a temporary change used in upgrade of N+1 node
    admin_conf = os.path.join(tsc.PLATFORM_PATH, "config", to_load,
                              "kubernetes", utils.KUBERNETES_ADMIN_CONF_FILE)
    with open(admin_conf, 'r') as yaml_file:
        config = yaml.load(yaml_file)

    for item, values in config.items():
        # update server address in cluster
        if item == 'clusters':
            if 'cluster' in values[0] and 'server' in values[0]['cluster']:
                formatted_address = utils.format_url_address(mgmt_address)
                # TODO use urlparse() to get url components and update
                values[0]['cluster']['server'] = \
                    "https://" + formatted_address + ":6443"
            break  # no need to iterate further

    with open(admin_conf, 'w') as yaml_file:
        yaml.dump(config, yaml_file, default_flow_style=False)

    # Remove branding tar files from the release N+1 directory as branding
    # files are not compatible between releases.
    branding_files = os.path.join(
        tsc.PLATFORM_PATH, "config", to_load, "branding", "*.tgz")
    try:
        subprocess.check_call(["rm -f %s" % branding_files], shell=True,
                              stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to remove branding files %s" % branding_files)

    # Execute migration scripts
    utils.execute_migration_scripts(
        from_load, to_load, utils.ACTION_START)

    LOG.info("Finished upgrade preparations")


def create_simplex_backup(software_upgrade):
    """Creates the upgrade metadata and creates the system backup"""
    backup_data = {}
    upgrade_data = software_upgrade.as_dict()
    if upgrade_data['created_at']:
        upgrade_data['created_at'] = \
            upgrade_data['created_at'].replace(
                microsecond=0).replace(tzinfo=None).isoformat()
    if upgrade_data['updated_at']:
        upgrade_data['updated_at'] = \
            upgrade_data['updated_at'].replace(
                microsecond=0).replace(tzinfo=None).isoformat()
    backup_data['upgrade'] = upgrade_data
    json_data = json.dumps(backup_data)
    metadata_path = os.path.join(tsc.CONFIG_PATH, 'upgrades')
    os.mkdir(metadata_path)
    metadata_filename = os.path.join(metadata_path, 'metadata')
    with open(metadata_filename, 'w') as metadata_file:
        metadata_file.write(json_data)

    upgrade_data, upgrade_images_data = get_upgrade_backup_filenames(
        software_upgrade)
    backup_vars = [
        "platform_backup_file=%s.tgz" % upgrade_data,
        "docker_local_registry_backup_file=%s.tgz" % upgrade_images_data,
        "backup_user_local_registry=true",
        "backup_dir=%s" % tsc.PLATFORM_BACKUP_PATH]
    args = [
        'ansible-playbook',
        '-e', ' '.join(backup_vars),
        sysinv_constants.ANSIBLE_PLATFORM_BACKUP_PLAYBOOK]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE)
    out, _ = proc.communicate()
    LOG.info(out)
    if proc.returncode:
        raise subprocess.CalledProcessError(proc.returncode, args)
    LOG.info("Create simplex backup complete")


def get_upgrade_backup_filenames(software_upgrade):
    """Generates the simplex upgrade backup filename"""
    created_at_date = software_upgrade.created_at.replace(
        microsecond=0).replace(tzinfo=None)
    date_time = created_at_date.isoformat().replace(':', '')
    suffix = date_time + '_' + software_upgrade.uuid
    upgrade_data = 'upgrade_data_' + suffix
    upgrade_images_data = 'upgrade_images_data_' + suffix
    return upgrade_data, upgrade_images_data


def abort_upgrade(from_load, to_load, upgrade):
    """ Executed on the release N side, cleans up data created for upgrade. """
    devnull = open(os.devnull, 'w')
    LOG.info("Starting aborting upgrade - from: %s, to: %s" %
             (from_load, to_load))

    # remove upgrade flags
    try:
        os.remove(tsc.CONTROLLER_UPGRADE_FLAG)
    except OSError:
        LOG.exception("Failed to remove upgrade flag")
    try:
        os.remove(tsc.CONTROLLER_UPGRADE_COMPLETE_FLAG)
    except OSError:
        LOG.exception("Failed to remove upgrade complete flag")
    try:
        os.remove(tsc.CONTROLLER_UPGRADE_FAIL_FLAG)
    except OSError:
        LOG.exception("Failed to remove upgrade fail flag")
    try:
        os.remove(tsc.CONTROLLER_UPGRADE_STARTED_FLAG)
    except OSError:
        LOG.exception("Failed to remove the upgrade started flag")

    # unexport filesystems
    export_list = [utils.POSTGRES_PATH, utils.RABBIT_PATH]
    export_path = None
    try:
        for export_path in export_list:
            subprocess.check_call(
                ["exportfs",
                 "-u",
                 "%s:%s" % (utils.CONTROLLER_1_HOSTNAME, export_path)],
                stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to unexport %s" % export_path)
    except Exception:
        LOG.exception("Failed to unexport filesystems")

    # Depending on where we are in the upgrade we may need to remove the
    # symlink to the etcd directory
    etcd_to_dir = os.path.join(tsc.ETCD_PATH, to_load)
    if os.path.islink(etcd_to_dir):
        LOG.info("Unlinking destination etcd directory: %s " % etcd_to_dir)
        os.unlink(etcd_to_dir)

    # Remove upgrade directories
    upgrade_dirs = [
        os.path.join(tsc.PLATFORM_PATH, "config", to_load),
        os.path.join(tsc.PLATFORM_PATH, "armada", to_load),
        os.path.join(tsc.PLATFORM_PATH, "helm", to_load),
        os.path.join(tsc.ETCD_PATH, to_load),
        os.path.join(utils.POSTGRES_PATH, "upgrade"),
        os.path.join(utils.POSTGRES_PATH, to_load),
        os.path.join(utils.RABBIT_PATH, to_load),
        os.path.join(tsc.PLATFORM_PATH, "nfv/vim", to_load),
        os.path.join(tsc.PLATFORM_PATH, ".keyring", to_load),
        os.path.join(tsc.PLATFORM_PATH, "puppet", to_load),
        os.path.join(tsc.PLATFORM_PATH, "sysinv", to_load),
        os.path.join(tsc.CONFIG_PATH, 'upgrades')
    ]

    for directory in upgrade_dirs:
        try:
            shutil.rmtree(directory)
        except OSError:
            LOG.exception("Failed to remove upgrade directory %s" % directory)

    remove_simplex_upgrade_data(upgrade)

    LOG.info("Finished upgrade abort")


def activate_upgrade(from_load, to_load, i_system):
    """ Executed on release N+1, activate the upgrade on all nodes. """
    LOG.info("Starting upgrade activate - from: %s, to: %s" %
             (from_load, to_load))
    devnull = open(os.devnull, 'w')

    shared_services = i_system.capabilities.get("shared_services", "")
    if sysinv_constants.SERVICE_TYPE_IDENTITY not in shared_services:
        try:
            # Activate keystone
            #
            # CONTRACT - contract the previously expanded to_version DB
            # to remove the old schema and all data migration triggers.
            # When this process completes, the database will no longer
            # be able to support the previous release.
            # To avoid a deadlock during keystone contract we will use offline
            # migration for simplex upgrades. Since all db_sync operations are
            # done offline there is no need for the contract for SX systems
            if not tsc.system_mode == sysinv_constants.SYSTEM_MODE_SIMPLEX:
                keystone_cmd = ('keystone-manage db_sync --contract')
                subprocess.check_call([keystone_cmd], shell=True,
                                      stderr=devnull)

        except subprocess.CalledProcessError:
            LOG.exception("Failed to contract Keystone databases for upgrade.")
            raise
    utils.execute_migration_scripts(from_load, to_load, utils.ACTION_ACTIVATE)

    LOG.info("Finished upgrade activation")


def remove_simplex_upgrade_data(upgrade):
    upgrade_data, upgrade_images_data = get_upgrade_backup_filenames(upgrade)
    simplex_backup_files = glob.glob(
        os.path.join(tsc.PLATFORM_BACKUP_PATH, upgrade_data + "*"))
    simplex_backup_files += glob.glob(
        os.path.join(tsc.PLATFORM_BACKUP_PATH, upgrade_images_data + "*"))

    for file in simplex_backup_files:
        try:
            LOG.info("Removing simplex upgrade file %s" % file)
            os.remove(file)
        except OSError:
            LOG.exception("Failed to remove %s" % file)


def complete_upgrade(from_load, to_load, upgrade):
    """ Executed on release N+1, cleans up data created for upgrade. """
    LOG.info("Starting upgrade complete - from: %s, to: %s" %
             (from_load, to_load))

    # Remove upgrade directories
    upgrade_dirs = [
        os.path.join(tsc.PLATFORM_PATH, "config", from_load),
        os.path.join(utils.POSTGRES_PATH, "upgrade"),
        os.path.join(utils.POSTGRES_PATH, from_load),
        os.path.join(utils.RABBIT_PATH, from_load),
        os.path.join(tsc.PLATFORM_PATH, "nfv/vim", from_load),
        os.path.join(tsc.PLATFORM_PATH, ".keyring", from_load),
        os.path.join(tsc.PLATFORM_PATH, "puppet", from_load),
        os.path.join(tsc.PLATFORM_PATH, "sysinv", from_load),
        os.path.join(tsc.PLATFORM_PATH, "armada", from_load),
        os.path.join(tsc.PLATFORM_PATH, "helm", from_load),
        os.path.join(tsc.ETCD_PATH, from_load)
    ]

    for directory in upgrade_dirs:
        try:
            shutil.rmtree(directory)
        except OSError:
            LOG.exception("Failed to remove upgrade directory %s" % directory)

    remove_simplex_upgrade_data(upgrade)

    LOG.info("Finished upgrade complete")
