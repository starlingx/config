#
# Copyright (c) 2014-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Backup & Restore
"""

import copy
import filecmp
import fileinput
import os
import glob
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import textwrap
import time

from fm_api import constants as fm_constants
from fm_api import fm_api
from sysinv.common import constants as sysinv_constants

from common import log
from common import constants
from common.exceptions import BackupFail, BackupWarn, RestoreFail
from common.exceptions import KeystoneFail, SysInvFail
import openstack
import tsconfig.tsconfig as tsconfig
import utils
import sysinv_api as sysinv


LOG = log.get_logger(__name__)

DEVNULL = open(os.devnull, 'w')
RESTORE_COMPLETE = "restore-complete"
RESTORE_RERUN_REQUIRED = "restore-rerun-required"

# Backup/restore related constants
backup_in_progress = tsconfig.BACKUP_IN_PROGRESS_FLAG
restore_in_progress = tsconfig.RESTORE_IN_PROGRESS_FLAG
restore_system_ready = tsconfig.RESTORE_SYSTEM_FLAG
restore_patching_complete = '/etc/platform/.restore_patching_complete'
node_is_patched = '/var/run/node_is_patched'
keyring_permdir = os.path.join('/opt/platform/.keyring', tsconfig.SW_VERSION)
ldap_permdir = '/var/lib/openldap-data'
ceilometer_permdir = '/opt/cgcs/ceilometer/' + tsconfig.SW_VERSION
glance_permdir = '/opt/cgcs/glance'
patching_permdir = '/opt/patching'
patching_repo_permdir = '/www/pages/updates'
home_permdir = '/home'
cinder_permdir = '/opt/cgcs/cinder'
extension_permdir = '/opt/extension'
patch_vault_permdir = '/opt/patch-vault'


def get_backup_databases(cinder_config=False):
    """
    Retrieve database lists for backup.
    :return: backup_databases and backup_database_skip_tables
    """

    # Databases common to all configurations
    REGION_LOCAL_DATABASES = ('postgres', 'template1', 'nova', 'sysinv',
                              'neutron', 'heat', 'nova_api',
                              'aodh', 'murano', 'magnum', 'panko', 'ironic',
                              'nova_cell0', 'gnocchi')
    REGION_SHARED_DATABASES = ('glance', 'keystone')

    if cinder_config:
        REGION_SHARED_DATABASES += ('cinder', )

    # Indicates which tables have to be dropped for a certain database.
    DB_TABLE_SKIP_MAPPING = {
        'sysinv': ('i_alarm',),
        'gnocchi': ('metric', 'resource'),
        'dcorch': ('orch_job',
                   'orch_request',
                   'resource',
                   'subcloud_resource'), }

    if tsconfig.region_config == 'yes':
        BACKUP_DATABASES = REGION_LOCAL_DATABASES
        # Add databases which are optional in secondary regions(and subclouds)
        shared_services = sysinv.get_shared_services()
        for service_type in ["image", "volume"]:
            if service_type not in shared_services:
                service = 'glance' if service_type == "image" else 'cinder'
                BACKUP_DATABASES += (service, )

    else:
        # Add additional databases for non-region configuration and for the
        # primary region in region deployments.
        BACKUP_DATABASES = REGION_LOCAL_DATABASES + REGION_SHARED_DATABASES

        # Add distributed cloud databases
        if tsconfig.distributed_cloud_role == \
                sysinv_constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            BACKUP_DATABASES += ('dcmanager', 'dcorch')

    # We generate the tables to be skipped for each database
    # mentioned in BACKUP_DATABASES. We explicitly list
    # skip tables in DB_TABLE_SKIP_MAPPING
    BACKUP_DB_SKIP_TABLES = dict(
        map(lambda x: [x, DB_TABLE_SKIP_MAPPING.get(x, ())],
            BACKUP_DATABASES))

    return BACKUP_DATABASES, BACKUP_DB_SKIP_TABLES


def check_load_versions(archive, staging_dir):
    match = False
    try:
        member = archive.getmember('etc/build.info')
        archive.extract(member, path=staging_dir)
        match = filecmp.cmp('/etc/build.info', staging_dir + '/etc/build.info')
        shutil.rmtree(staging_dir + '/etc')
    except Exception as e:
        LOG.exception(e)
        raise RestoreFail("Unable to verify load version in backup file. "
                          "Invalid backup file.")

    if not match:
        LOG.error("Load version mismatch.")
        raise RestoreFail("Load version of backup does not match the "
                          "version of the installed load.")


def get_subfunctions(filename):
    """
    Retrieves the subfunctions from a platform.conf file.
    :param filename: file to retrieve subfunctions from
    :return: a list of the subfunctions or None if no subfunctions exist
    """
    matchstr = 'subfunction='

    with open(filename, 'r') as f:
        for line in f:
            if matchstr in line:
                parsed = line.split('=')
                return parsed[1].rstrip().split(",")
    return


def check_load_subfunctions(archive, staging_dir):
    """
    Verify that the subfunctions in the backup match the installed load.
    :param archive: backup archive
    :param staging_dir: staging directory
    :return: raises exception if the subfunctions do not match
    """
    match = False
    backup_subfunctions = None
    try:
        member = archive.getmember('etc/platform/platform.conf')
        archive.extract(member, path=staging_dir)
        backup_subfunctions = get_subfunctions(staging_dir +
                                               '/etc/platform/platform.conf')
        shutil.rmtree(staging_dir + '/etc')
        if set(backup_subfunctions) ^ set(tsconfig.subfunctions):
            # The set of subfunctions do not match
            match = False
        else:
            match = True
    except Exception:
        LOG.exception("Unable to verify subfunctions in backup file")
        raise RestoreFail("Unable to verify subfunctions in backup file. "
                          "Invalid backup file.")

    if not match:
        LOG.error("Subfunction mismatch - backup: %s, installed: %s" %
                  (str(backup_subfunctions), str(tsconfig.subfunctions)))
        raise RestoreFail("Subfunctions in backup load (%s) do not match the "
                          "subfunctions of the installed load (%s)." %
                          (str(backup_subfunctions),
                           str(tsconfig.subfunctions)))


def file_exists_in_archive(archive, file_path):
    """ Check if file exists in archive """
    try:
        archive.getmember(file_path)
        return True

    except KeyError:
        LOG.info("File %s is not in archive." % file_path)
        return False


def filter_directory(archive, directory):
    for tarinfo in archive:
        if tarinfo.name.split('/')[0] == directory:
            yield tarinfo


def backup_etc_size():
    """ Backup etc size estimate """
    try:
        total_size = utils.directory_get_size('/etc')
        nova_size = utils.directory_get_size('/etc/nova/instances')
        # We only backup .xml and .log files under /etc/nova/instances
        vm_files_re = re.compile(".*\.xml$|.*\.log$")
        filtered_nova_size = utils.directory_get_size('/etc/nova/instances',
                                                      vm_files_re)

        return total_size - nova_size + filtered_nova_size
    except OSError:
        LOG.error("Failed to estimate backup etc size.")
        raise BackupFail("Failed to estimate backup etc size")


def filter_etc(tarinfo):
    """
    Filters all files from the /etc/nova/instances directory.
    :param tarinfo: file to check
    :return: None if file should be excluded from archive, otherwise unchanged
        tarinfo
    """
    if tarinfo.name.startswith('etc/nova/instances'):
        return None
    else:
        return tarinfo


def backup_etc(archive):
    """ Backup etc """
    try:
        archive.add('/etc', arcname='etc', filter=filter_etc)

    except tarfile.TarError:
        LOG.error("Failed to backup etc.")
        raise BackupFail("Failed to backup etc")


def restore_etc_file(archive, dest_dir, etc_file):
    """ Restore etc file """
    try:
        # Change the name of this file to remove the leading path
        member = archive.getmember('etc/' + etc_file)
        # Copy the member to avoid changing the name for future operations on
        # this member.
        temp_member = copy.copy(member)
        temp_member.name = os.path.basename(temp_member.name)
        archive.extract(temp_member, path=dest_dir)

    except tarfile.TarError:
        LOG.error("Failed to restore etc file.")
        raise RestoreFail("Failed to restore etc file")


def filter_etc_nova_instances(tarinfo):
    """
    Filters all files from the /etc/nova/instances directory except .xml and
    .log files.
    :param tarinfo: file to check
    :return: None if file should be excluded from archive, otherwise unchanged
        tarinfo
    """
    if not tarinfo.isdir() and not tarinfo.name.endswith(('.xml', '.log')):
        return None
    else:
        return tarinfo


def restore_etc_ssl_dir(archive, configpath=constants.CONFIG_WORKDIR):
    """ Restore the etc SSL dir """

    def filter_etc_ssl_private(members):
        for tarinfo in members:
            if 'etc/ssl/private' in tarinfo.name:
                yield tarinfo

    if file_exists_in_archive(archive, 'config/server-cert.pem'):
        restore_config_file(
            archive, configpath, 'server-cert.pem')

    if file_exists_in_archive(archive, 'etc/ssl/private'):
        # NOTE: This will include all TPM certificate files if TPM was
        # enabled on the backed up system. However in that case, this
        # restoration is only done for the first controller and TPM
        # will need to be reconfigured once duplex controller (if any)
        # is restored.
        archive.extractall(path='/',
                           members=filter_etc_ssl_private(archive))


def backup_nova_instances(archive):
    """ Backup /etc/nova/instances directory """
    try:
        archive.add(
            '/etc/nova/instances',
            arcname=utils.get_controller_hostname() + '_nova_instances',
            filter=filter_etc_nova_instances)

    except tarfile.TarError:
        LOG.error("Failed to backup etc.")
        raise BackupFail("Failed to backup etc")


def restore_nova_instances(archive, staging_dir):
    """ Restore /etc/nova/instances directory """

    member_name = utils.get_controller_hostname() + '_nova_instances'
    try:
        # Verify that archive contains this directory
        try:
            archive.getmember(member_name)
        except KeyError:
            LOG.info("Archive does not contain directory %s" % member_name)
            # No instance data was backed up on this controller. Continue
            # with the restore.
            return

        # Restore to a temporary directory
        archive.extractall(path=staging_dir,
                           members=filter_directory(archive, member_name))

        # Copy to /etc/nova/instances. Preserve ownership. Don't check return
        # code because there may not be any files to copy.
        cp_command = ('cp -Rp ' + os.path.join(staging_dir, member_name, '*') +
                      ' /etc/nova/instances/')
        subprocess.call(cp_command, shell=True)
    except tarfile.TarError:
        LOG.exception("Failed to restore /etc/nova/instances.")
        raise RestoreFail("Failed to restore /etc/nova/instances")


def backup_mate_nova_instances_size():
    """ Backup mate nova instances size estimate """

    # This is a small system configuration. We will also be backing up
    # .xml and .log files in the /etc/nova directory on the mate
    # controller. Instead of talking to the mate to get the actual
    # size, we will just add 1M.
    return 1024 * 1024


def backup_mate_nova_instances(archive, staging_dir):
    """ Backup /etc/nova/instances on mate controller """

    # This is a small system configuration. Back up the .xml and .log files
    # in the /etc/nova directory on the mate controller.
    mate_hostname = utils.get_mate_controller_hostname()
    tmpdir = tempfile.mkdtemp(dir=staging_dir)
    try:
        output = subprocess.check_output(
            ["rsync",
             "-amv",
             "--include",
             "*.xml",
             "--include",
             "*.log",
             "--include",
             "*/",
             "--exclude",
             "*",
             "rsync://%s/instances/" % mate_hostname,
             "%s/" % tmpdir],
            stderr=subprocess.STDOUT)
        LOG.info("Synced from mate via rsync: %s" % output)
        archive.add(tmpdir, arcname=mate_hostname + '_nova_instances')

    except subprocess.CalledProcessError:
        LOG.exception("Failed to rsync nova instances data from mate.")
        raise BackupWarn(
            "Unable to copy nova instances data from mate controller. No "
            "instances running on the mate controller will be restored if "
            "this backup is used for a system restore.\n"
        )
    except tarfile.TarError:
        LOG.exception("Failed to backup nova instances data from mate.")
        raise BackupFail("Failed to backup nova instances data from mate")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def extract_mate_nova_instances(archive, directory):
    """ Extract mate controller's /etc/nova/instances so the mate can
        restore it when it comes up.
     """
    member_name = utils.get_mate_controller_hostname() + '_nova_instances'
    dest_dir = os.path.join(directory, member_name)

    try:
        shutil.rmtree(dest_dir, ignore_errors=True)
        # Verify that archive contains this directory
        try:
            archive.getmember(member_name)
        except KeyError:
            LOG.warning("Archive does not contain directory %s" % member_name)
            # No instance data was backed up on the mate controller. Continue
            # with the restore.
            return

        archive.extractall(
            path=directory,
            members=filter_directory(archive, member_name))

    except (shutil.Error, tarfile.TarError):
        LOG.exception("Failed to restore %s" % dest_dir)
        raise RestoreFail("Failed to restore %s" % dest_dir)


def backup_nova_size(directory):
    """
    Backup nova directory size estimate. Only includes .xml and .log files.
    :param directory: nova permdir
    :return: size in bytes of files to be backed up
    """

    try:
        # We only backup .xml and .log files under the nova directory
        vm_files_re = re.compile(".*\.xml$|.*\.log$")
        nova_size = utils.directory_get_size(directory, vm_files_re)

        return nova_size
    except OSError:
        LOG.exception("Failed to estimate nova size.")
        raise BackupFail("Failed to estimate nova size")


def filter_nova(tarinfo):
    """
    Filters all files from the nova directory except .xml and
    .log files.
    :param tarinfo: file to check
    :return: None if file should be excluded from archive, otherwise unchanged
        tarinfo
    """

    if not tarinfo.isdir() and not tarinfo.name.endswith(('.xml', '.log')):
        return None
    else:
        return tarinfo


def backup_config_size(config_permdir):
    """ Backup configuration size estimate """
    try:
        return(utils.directory_get_size(config_permdir))

    except OSError:
        LOG.error("Failed to estimate backup configuration size.")
        raise BackupFail("Failed to estimate backup configuration size")


def backup_config(archive, config_permdir):
    """ Backup configuration """
    try:
        # The config dir is versioned, but we're only grabbing the current
        # release
        archive.add(config_permdir, arcname='config')

    except tarfile.TarError:
        LOG.error("Failed to backup config.")
        raise BackupFail("Failed to backup configuration")


def restore_config_file(archive, dest_dir, config_file):
    """ Restore configuration file """
    try:
        # Change the name of this file to remove the leading path
        member = archive.getmember('config/' + config_file)
        # Copy the member to avoid changing the name for future operations on
        # this member.
        temp_member = copy.copy(member)
        temp_member.name = os.path.basename(temp_member.name)
        archive.extract(temp_member, path=dest_dir)

    except tarfile.TarError:
        LOG.error("Failed to restore config file %s." % config_file)
        raise RestoreFail("Failed to restore configuration")


def restore_configuration(archive, staging_dir):
    """ Restore configuration """
    try:
        os.makedirs(constants.CONFIG_WORKDIR, stat.S_IRWXU | stat.S_IRGRP |
                    stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    except OSError:
        LOG.error("Failed to create config directory: %s",
                  constants.CONFIG_WORKDIR)
        raise RestoreFail("Failed to restore configuration files")

    # Restore cgcs_config file from original installation for historical
    # purposes. Not used to restore the system as the information in this
    # file is out of date (not updated after original installation).
    restore_config_file(archive, constants.CONFIG_WORKDIR, 'cgcs_config')

    # Restore platform.conf file and update as necessary. The file will be
    # created in a temporary location and then moved into place when it is
    # complete to prevent access to a partially created file.
    restore_etc_file(archive, staging_dir, 'platform/platform.conf')
    temp_platform_conf_file = os.path.join(tsconfig.PLATFORM_CONF_PATH,
                                           'platform.conf.temp')
    shutil.copyfile(os.path.join(staging_dir, 'platform.conf'),
                    temp_platform_conf_file)
    install_uuid = utils.get_install_uuid()
    for line in fileinput.FileInput(temp_platform_conf_file, inplace=1):
        if line.startswith("INSTALL_UUID="):
            # The INSTALL_UUID must be updated to match the new INSTALL_UUID
            # which was generated when this controller was installed prior to
            # doing the restore.
            print "INSTALL_UUID=%s" % install_uuid
        elif line.startswith("management_interface=") or \
                line.startswith("oam_interface=") or \
                line.startswith("infrastructure_interface=") or \
                line.startswith("UUID="):
            # Strip out any entries that are host specific as the backup can
            # be done on either controller. The application of the
            # platform_conf manifest will add these back in.
            pass
        else:
            print line,
    fileinput.close()
    # Move updated platform.conf file into place.
    os.rename(temp_platform_conf_file, tsconfig.PLATFORM_CONF_FILE)

    # Kick tsconfig to reload the platform.conf file
    tsconfig._load()

    # Restore branding
    restore_config_dir(archive, staging_dir, 'branding', '/opt/branding/')

    # Restore banner customization
    restore_config_dir(archive, staging_dir, 'banner/etc', '/opt/banner')

    # Restore ssh configuration
    restore_config_dir(archive, staging_dir, 'ssh_config',
                       constants.CONFIG_WORKDIR + '/ssh_config')

    # Configure hostname
    utils.configure_hostname('controller-0')

    # Restore hosts file
    restore_etc_file(archive, '/etc', 'hosts')
    restore_etc_file(archive, constants.CONFIG_WORKDIR, 'hosts')

    # Restore certificate files
    restore_etc_ssl_dir(archive)

    # Restore firewall rules file if it is in the archive
    if file_exists_in_archive(archive, 'config/iptables.rules'):
        restore_config_file(
            archive, constants.CONFIG_WORKDIR, 'iptables.rules')
        restore_etc_file(archive, tsconfig.PLATFORM_CONF_PATH,
                         'platform/iptables.rules')


def filter_pxelinux(archive):
    for tarinfo in archive:
        if tarinfo.name.find('config/pxelinux.cfg') == 0:
            yield tarinfo


def restore_dnsmasq(archive, config_permdir):
    """ Restore dnsmasq """
    try:
        etc_files = ['hosts']

        perm_files = ['hosts',
                      'dnsmasq.hosts', 'dnsmasq.leases',
                      'dnsmasq.addn_hosts']

        for etc_file in etc_files:
            restore_config_file(archive, '/etc', etc_file)

        for perm_file in perm_files:
            restore_config_file(archive, config_permdir, perm_file)

        # Extract distributed cloud addn_hosts file if present in archive.
        if file_exists_in_archive(
                archive, 'config/dnsmasq.addn_hosts_dc'):
            restore_config_file(archive, config_permdir,
                                'dnsmasq.addn_hosts_dc')

        tmpdir = tempfile.mkdtemp(prefix="pxerestore_")

        archive.extractall(tmpdir,
                           members=filter_pxelinux(archive))

        if os.path.exists(tmpdir + '/config/pxelinux.cfg'):
            shutil.rmtree(config_permdir + 'pxelinux.cfg', ignore_errors=True)
            shutil.move(tmpdir + '/config/pxelinux.cfg', config_permdir)

        shutil.rmtree(tmpdir, ignore_errors=True)

    except (shutil.Error, subprocess.CalledProcessError, tarfile.TarError):
        LOG.error("Failed to restore dnsmasq config.")
        raise RestoreFail("Failed to restore dnsmasq files")


def backup_puppet_data_size(puppet_permdir):
    """ Backup puppet data size estimate """
    try:
        return(utils.directory_get_size(puppet_permdir))

    except OSError:
        LOG.error("Failed to estimate backup puppet data size.")
        raise BackupFail("Failed to estimate backup puppet data size")


def backup_puppet_data(archive, puppet_permdir):
    """ Backup puppet data """
    try:
        # The puppet dir is versioned, but we're only grabbing the current
        # release
        archive.add(puppet_permdir, arcname='hieradata')

    except tarfile.TarError:
        LOG.error("Failed to backup puppet data.")
        raise BackupFail("Failed to backup puppet data")


def restore_static_puppet_data(archive, puppet_workdir):
    """ Restore static puppet data """
    try:
        member = archive.getmember('hieradata/static.yaml')
        archive.extract(member, path=os.path.dirname(puppet_workdir))

        member = archive.getmember('hieradata/secure_static.yaml')
        archive.extract(member, path=os.path.dirname(puppet_workdir))

    except tarfile.TarError:
        LOG.error("Failed to restore static puppet data.")
        raise RestoreFail("Failed to restore static puppet data")

    except OSError:
        pass


def restore_puppet_data(archive, puppet_workdir):
    """ Restore puppet data """
    try:
        archive.extractall(
            path=os.path.dirname(puppet_workdir),
            members=filter_directory(archive,
                                     os.path.basename(puppet_workdir)))

    except tarfile.TarError:
        LOG.error("Failed to restore puppet data.")
        raise RestoreFail("Failed to restore puppet data")

    except OSError:
        pass


def backup_cinder_config(archive):
    """ Backup cinder configuration """

    # If the iscsi target config file exists, add it to the archive
    # On setups without LVM backends this file is absent
    if os.path.exists(cinder_permdir + '/iscsi-target/saveconfig.json'):
        archive.add(
            cinder_permdir + '/iscsi-target/saveconfig.json',
            arcname='cinder/saveconfig.json')


def restore_cinder_file(archive, dest_dir, cinder_file):
    """ Restore cinder file """
    try:
        # Change the name of this file to remove the leading path
        member = archive.getmember('cinder/' + cinder_file)
        # Copy the member to avoid changing the name for future operations on
        # this member.
        temp_member = copy.copy(member)
        temp_member.name = os.path.basename(temp_member.name)
        archive.extract(temp_member, path=dest_dir)

    except tarfile.TarError:
        LOG.error("Failed to restore cinder file %s." % cinder_file)
        raise RestoreFail("Failed to restore configuration")


def restore_cinder_config(archive):
    """Restore cinder config files"""
    # If the iscsi target config file is present in the archive,
    # restore it.
    if file_exists_in_archive(archive, 'cinder/saveconfig.json'):
        restore_cinder_file(
            archive, cinder_permdir + '/iscsi-target',
            'saveconfig.json')
        # Also create a copy of the original file as the volume
        # restore procedure changes this file and breaks the
        # valid nova settings.
        shutil.copyfile(
            cinder_permdir + '/iscsi-target/saveconfig.json',
            cinder_permdir + '/iscsi-target/saveconfig.json.bck')


def backup_cinder_size(cinder_permdir):
    """ Backup cinder size estimate """
    try:
        if not os.path.exists(
                cinder_permdir + '/iscsi-target/saveconfig.json'):
            return 0
        statinfo = os.stat(cinder_permdir + '/iscsi-target/saveconfig.json')
        return statinfo.st_size

    except OSError:
        LOG.error("Failed to estimate backup cinder size.")
        raise BackupFail("Failed to estimate backup cinder size")


def backup_keyring_size(keyring_permdir):
    """ Backup keyring size estimate """
    try:
        return(utils.directory_get_size(keyring_permdir))

    except OSError:
        LOG.error("Failed to estimate backup keyring size.")
        raise BackupFail("Failed to estimate backup keyring size")


def backup_keyring(archive, keyring_permdir):
    """ Backup keyring configuration """
    try:
        archive.add(keyring_permdir, arcname='.keyring')

    except tarfile.TarError:
        LOG.error("Failed to backup keyring.")
        raise BackupFail("Failed to backup keyring configuration")


def restore_keyring(archive, keyring_permdir):
    """ Restore keyring configuration """
    try:
        shutil.rmtree(keyring_permdir, ignore_errors=False)
        members = filter_directory(archive, '.keyring')
        temp_members = list()
        # remove .keyring and .keyring/ from the member path since they are
        # extracted to keyring_permdir: /opt/platform/.keyring/release
        for m in members:
            temp_member = copy.copy(m)
            lst = temp_member.name.split('.keyring/')
            if len(lst) > 1:
                temp_member.name = lst[1]
                temp_members.append(temp_member)
        archive.extractall(path=keyring_permdir, members=temp_members)

    except (tarfile.TarError, shutil.Error):
        LOG.error("Failed to restore keyring.")
        shutil.rmtree(keyring_permdir, ignore_errors=True)
        raise RestoreFail("Failed to restore keyring configuration")


def prefetch_keyring(archive):
    """ Prefetch keyring configuration for manifest use """
    keyring_tmpdir = '/tmp/.keyring'
    python_keyring_tmpdir = '/tmp/python_keyring'
    try:
        shutil.rmtree(keyring_tmpdir, ignore_errors=True)
        shutil.rmtree(python_keyring_tmpdir, ignore_errors=True)
        archive.extractall(
            path=os.path.dirname(keyring_tmpdir),
            members=filter_directory(archive,
                                     os.path.basename(keyring_tmpdir)))

        shutil.move(keyring_tmpdir + '/python_keyring', python_keyring_tmpdir)

    except (tarfile.TarError, shutil.Error):
        LOG.error("Failed to restore keyring.")
        shutil.rmtree(keyring_tmpdir, ignore_errors=True)
        shutil.rmtree(python_keyring_tmpdir, ignore_errors=True)
        raise RestoreFail("Failed to restore keyring configuration")


def cleanup_prefetched_keyring():
    """ Cleanup fetched keyring """
    try:
        keyring_tmpdir = '/tmp/.keyring'
        python_keyring_tmpdir = '/tmp/python_keyring'

        shutil.rmtree(keyring_tmpdir, ignore_errors=True)
        shutil.rmtree(python_keyring_tmpdir, ignore_errors=True)

    except shutil.Error:
        LOG.error("Failed to cleanup keyring.")
        raise RestoreFail("Failed to cleanup fetched keyring")


def backup_ldap_size():
    """ Backup ldap size estimate """
    try:
        total_size = 0

        proc = subprocess.Popen(
            ['slapcat -d 0 -F /etc/openldap/schema | wc -c'],
            shell=True, stdout=subprocess.PIPE)

        for line in proc.stdout:
            total_size = int(line)
            break

        proc.communicate()

        return total_size

    except subprocess.CalledProcessError:
        LOG.error("Failed to estimate backup ldap size.")
        raise BackupFail("Failed to estimate backup ldap size")


def backup_ldap(archive, staging_dir):
    """ Backup ldap configuration """
    try:
        ldap_staging_dir = staging_dir + '/ldap'
        os.mkdir(ldap_staging_dir, 0655)

        subprocess.check_call([
            'slapcat', '-d', '0', '-F', '/etc/openldap/schema',
            '-l', (ldap_staging_dir + '/ldap.db')], stdout=DEVNULL)

        archive.add(ldap_staging_dir + '/ldap.db', arcname='ldap.db')

    except (OSError, subprocess.CalledProcessError, tarfile.TarError):
        LOG.error("Failed to backup ldap database.")
        raise BackupFail("Failed to backup ldap configuration")


def restore_ldap(archive, ldap_permdir, staging_dir):
    """ Restore ldap configuration """
    try:
        ldap_staging_dir = staging_dir + '/ldap'
        archive.extract('ldap.db', path=ldap_staging_dir)

        utils.stop_lsb_service('openldap')

        subprocess.call(['rm', '-rf', ldap_permdir], stdout=DEVNULL)
        os.mkdir(ldap_permdir, 0755)

        subprocess.check_call(['slapadd', '-F', '/etc/openldap/schema',
                              '-l', ldap_staging_dir + '/ldap.db'],
                              stdout=DEVNULL, stderr=DEVNULL)

    except (subprocess.CalledProcessError, OSError, tarfile.TarError):
        LOG.error("Failed to restore ldap database.")
        raise RestoreFail("Failed to restore ldap configuration")

    finally:
        utils.start_lsb_service('openldap')


def backup_postgres_size(cinder_config=False):
    """ Backup postgres size estimate """
    try:
        total_size = 0

        # Backup roles, table spaces and schemas for databases.
        proc = subprocess.Popen([('sudo -u postgres pg_dumpall --clean ' +
                                  '--schema-only | wc -c')], shell=True,
                                stdout=subprocess.PIPE, stderr=DEVNULL)

        for line in proc.stdout:
            total_size = int(line)
            break

        proc.communicate()

        # get backup database
        backup_databases, backup_db_skip_tables = get_backup_databases(
            cinder_config)

        # Backup data for databases.
        for _, db_elem in enumerate(backup_databases):

            db_cmd = 'sudo -u postgres pg_dump --format=plain --inserts '
            db_cmd += '--disable-triggers --data-only %s ' % db_elem

            for _, table_elem in enumerate(backup_db_skip_tables[db_elem]):
                db_cmd += '--exclude-table=%s ' % table_elem

            db_cmd += '| wc -c'

            proc = subprocess.Popen([db_cmd], shell=True,
                                    stdout=subprocess.PIPE, stderr=DEVNULL)

            for line in proc.stdout:
                total_size += int(line)
                break

            proc.communicate()

        return total_size

    except subprocess.CalledProcessError:
        LOG.error("Failed to estimate backup database size.")
        raise BackupFail("Failed to estimate backup database size")


def backup_postgres(archive, staging_dir, cinder_config=False):
    """ Backup postgres configuration """
    try:
        postgres_staging_dir = staging_dir + '/postgres'
        os.mkdir(postgres_staging_dir, 0655)

        # Backup roles, table spaces and schemas for databases.
        subprocess.check_call([('sudo -u postgres pg_dumpall --clean ' +
                                '--schema-only' +
                                '> %s/%s' % (postgres_staging_dir,
                                             'postgres.sql.config'))],
                              shell=True, stderr=DEVNULL)

        # get backup database
        backup_databases, backup_db_skip_tables = get_backup_databases(
            cinder_config)

        # Backup data for databases.
        for _, db_elem in enumerate(backup_databases):

            db_cmd = 'sudo -u postgres pg_dump --format=plain --inserts '
            db_cmd += '--disable-triggers --data-only %s ' % db_elem

            for _, table_elem in enumerate(backup_db_skip_tables[db_elem]):
                db_cmd += '--exclude-table=%s ' % table_elem

            db_cmd += '> %s/%s.sql.data' % (postgres_staging_dir, db_elem)

            subprocess.check_call([db_cmd], shell=True, stderr=DEVNULL)

        archive.add(postgres_staging_dir, arcname='postgres')

    except (OSError, subprocess.CalledProcessError, tarfile.TarError):
        LOG.error("Failed to backup postgres databases.")
        raise BackupFail("Failed to backup database configuration")


def restore_postgres(archive, staging_dir):
    """ Restore postgres configuration """
    try:
        postgres_staging_dir = staging_dir + '/postgres'
        archive.extractall(path=staging_dir,
                           members=filter_directory(archive, 'postgres'))

        utils.start_service("postgresql")

        # Restore roles, table spaces and schemas for databases.
        subprocess.check_call(["sudo", "-u", "postgres", "psql", "-f",
                               postgres_staging_dir +
                               '/postgres.sql.config', "postgres"],
                              stdout=DEVNULL, stderr=DEVNULL)

        # Restore data for databases.
        for data in glob.glob(postgres_staging_dir + '/*.sql.data'):
            db_elem = data.split('/')[-1].split('.')[0]
            subprocess.check_call(["sudo", "-u", "postgres", "psql", "-f",
                                   data, db_elem],
                                  stdout=DEVNULL)

        if tsconfig.region_config != 'yes':
            # TODO (rchurch): Should this call the sysinv API to see if the
            # backend is configured?
            if subprocess.check_output(["sudo",
                                        "-u", "postgres",
                                        "psql", "-lqt"]).find('cinder') != -1:
                # The backing store for cinder volumes and snapshots is not
                # restored, so their status must be set to error.
                subprocess.check_call(["sudo",
                                       "-u", "postgres",
                                       "psql", "cinder",
                                       "-c",
                                       "UPDATE VOLUMES SET STATUS='error'"],
                                      stdout=DEVNULL, stderr=DEVNULL)
                subprocess.check_call(["sudo", "-u",
                                       "postgres", "psql", "cinder",
                                      "-c",
                                       "UPDATE SNAPSHOTS SET STATUS='error'"],
                                      stdout=DEVNULL, stderr=DEVNULL)

    except (OSError, subprocess.CalledProcessError, tarfile.TarError) as e:
        LOG.error("Failed to restore postgres databases. Error: %s", e)
        raise RestoreFail("Failed to restore database configuration")

    finally:
        utils.stop_service('postgresql')


def backup_ceilometer_size(ceilometer_permdir):
    """ Backup ceilometer size estimate """
    try:
        statinfo = os.stat(ceilometer_permdir + '/pipeline.yaml')
        return statinfo.st_size

    except OSError:
        LOG.error("Failed to estimate backup ceilometer size.")
        raise BackupFail("Failed to estimate backup ceilometer size")


def backup_ceilometer(archive, ceilometer_permdir):
    """ Backup ceilometer """
    try:
        archive.add(ceilometer_permdir + '/pipeline.yaml',
                    arcname='pipeline.yaml')

    except tarfile.TarError:
        LOG.error("Failed to backup ceilometer.")
        raise BackupFail("Failed to backup ceilometer")


def restore_ceilometer(archive, ceilometer_permdir):
    """ Restore ceilometer """
    try:
        archive.extract('pipeline.yaml', path=ceilometer_permdir)

    except tarfile.TarError:
        LOG.error("Failed to restore ceilometer")
        raise RestoreFail("Failed to restore ceilometer")


def filter_config_dir(archive, directory):
    for tarinfo in archive:
        if tarinfo.name.find('config/' + directory) == 0:
            yield tarinfo


def restore_config_dir(archive, staging_dir, config_dir, dest_dir):
    """ Restore configuration directory if it exists """
    try:
        archive.extractall(staging_dir,
                           members=filter_config_dir(archive, config_dir))

        # Copy files from backup to dest dir
        if (os.path.exists(staging_dir + '/config/' + config_dir) and
                os.listdir(staging_dir + '/config/' + config_dir)):
            subprocess.call(["mkdir", "-p", dest_dir])

            try:
                for f in glob.glob(
                        staging_dir + '/config/' + config_dir + '/*'):
                    subprocess.check_call(["cp", "-p", f, dest_dir])
            except IOError:
                LOG.warning("Failed to copy %s files" % config_dir)

    except (subprocess.CalledProcessError, tarfile.TarError):
        LOG.info("No custom %s config was found during restore." % config_dir)


def backup_std_dir_size(directory):
    """ Backup standard directory size estimate """
    try:
        return utils.directory_get_size(directory)

    except OSError:
        LOG.error("Failed to estimate backup size for %s" % directory)
        raise BackupFail("Failed to estimate backup size for %s" % directory)


def backup_std_dir(archive, directory):
    """ Backup standard directory """
    try:
        archive.add(directory, arcname=os.path.basename(directory))

    except tarfile.TarError:
        LOG.error("Failed to backup %s" % directory)
        raise BackupFail("Failed to backup %s" % directory)


def restore_std_dir(archive, directory):
    """ Restore standard directory """
    try:
        shutil.rmtree(directory, ignore_errors=True)
        # Verify that archive contains this directory
        try:
            archive.getmember(os.path.basename(directory))
        except KeyError:
            LOG.error("Archive does not contain directory %s" % directory)
            raise RestoreFail("Invalid backup file - missing directory %s" %
                              directory)
        archive.extractall(
            path=os.path.dirname(directory),
            members=filter_directory(archive, os.path.basename(directory)))

    except (shutil.Error, tarfile.TarError):
        LOG.error("Failed to restore %s" % directory)
        raise RestoreFail("Failed to restore %s" % directory)


def configure_loopback_interface(archive):
    """ Restore and apply configuration for loopback interface """
    utils.remove_interface_config_files()
    restore_etc_file(
        archive, utils.NETWORK_SCRIPTS_PATH,
        'sysconfig/network-scripts/' + utils.NETWORK_SCRIPTS_LOOPBACK)
    utils.restart_networking()


def backup_ceph_crush_map(archive, staging_dir):
    """ Backup ceph crush map """
    try:
        ceph_staging_dir = os.path.join(staging_dir, 'ceph')
        os.mkdir(ceph_staging_dir, 0655)
        crushmap_file = os.path.join(ceph_staging_dir,
                                     sysinv_constants.CEPH_CRUSH_MAP_BACKUP)
        subprocess.check_call(['ceph', 'osd', 'getcrushmap',
                               '-o', crushmap_file], stdout=DEVNULL,
                              stderr=DEVNULL)
        archive.add(crushmap_file, arcname='ceph/' +
                    sysinv_constants.CEPH_CRUSH_MAP_BACKUP)
    except Exception as e:
        LOG.error('Failed to backup ceph crush map. Reason: {}'.format(e))
        raise BackupFail('Failed to backup ceph crush map')


def restore_ceph_crush_map(archive):
    """ Restore ceph crush map """
    if not file_exists_in_archive(archive, 'ceph/' +
                                  sysinv_constants.CEPH_CRUSH_MAP_BACKUP):
        return

    try:
        crush_map_file = 'ceph/' + sysinv_constants.CEPH_CRUSH_MAP_BACKUP
        if file_exists_in_archive(archive, crush_map_file):
            member = archive.getmember(crush_map_file)
            # Copy the member to avoid changing the name for future
            # operations on this member.
            temp_member = copy.copy(member)
            temp_member.name = os.path.basename(temp_member.name)
            archive.extract(temp_member,
                            path=sysinv_constants.SYSINV_CONFIG_PATH)

    except tarfile.TarError as e:
        LOG.error('Failed to restore crush map file. Reason: {}'.format(e))
        raise RestoreFail('Failed to restore crush map file')


def check_size(archive_dir, cinder_config):
    """Check if there is enough space to create backup."""
    backup_overhead_bytes = 1024 ** 3  # extra GB for staging directory

    # backup_cinder_size() will return 0 if cinder/lvm is not configured,
    # So no need to add extra check here.
    backup_size = (backup_overhead_bytes +
                   backup_etc_size() +
                   backup_config_size(tsconfig.CONFIG_PATH) +
                   backup_puppet_data_size(constants.HIERADATA_PERMDIR) +
                   backup_keyring_size(keyring_permdir) +
                   backup_ldap_size() +
                   backup_postgres_size(cinder_config) +
                   backup_ceilometer_size(ceilometer_permdir) +
                   backup_std_dir_size(glance_permdir) +
                   backup_std_dir_size(home_permdir) +
                   backup_std_dir_size(patching_permdir) +
                   backup_std_dir_size(patching_repo_permdir) +
                   backup_std_dir_size(extension_permdir) +
                   backup_std_dir_size(patch_vault_permdir) +
                   backup_cinder_size(cinder_permdir)
                   )

    if utils.is_combined_load():
        backup_size += backup_mate_nova_instances_size()

    archive_dir_free_space = \
        utils.filesystem_get_free_space(archive_dir)

    if backup_size > archive_dir_free_space:
        print ("Archive directory (%s) does not have enough free "
               "space (%s), estimated backup size is %s." %
               (archive_dir, utils.print_bytes(archive_dir_free_space),
                utils.print_bytes(backup_size)))

        raise BackupFail("Not enough free space for backup.")


def backup(backup_name, archive_dir, clone=False):
    """Backup configuration."""

    if not os.path.isdir(archive_dir):
        raise BackupFail("Archive directory (%s) not found." % archive_dir)

    if not utils.is_active("management-ip"):
        raise BackupFail(
            "Backups can only be performed from the active controller.")

    if os.path.isfile(backup_in_progress):
        raise BackupFail("Backup already in progress.")
    else:
        open(backup_in_progress, 'w')

    fmApi = fm_api.FaultAPIs()
    entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                    sysinv_constants.CONTROLLER_HOSTNAME)
    fault = fm_api.Fault(alarm_id=fm_constants.FM_ALARM_ID_BACKUP_IN_PROGRESS,
                         alarm_state=fm_constants.FM_ALARM_STATE_SET,
                         entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                         entity_instance_id=entity_instance_id,
                         severity=fm_constants.FM_ALARM_SEVERITY_MINOR,
                         reason_text=("System Backup in progress."),
                         # operational
                         alarm_type=fm_constants.FM_ALARM_TYPE_7,
                         # congestion
                         probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_8,
                         proposed_repair_action=("No action required."),
                         service_affecting=False)

    fmApi.set_fault(fault)

    cinder_config = False
    backend_services = sysinv.get_storage_backend_services()
    for services in backend_services.values():
        if (services is not None and
                services.find(sysinv_constants.SB_SVC_CINDER) != -1):
            cinder_config = True
            break

    staging_dir = None
    system_tar_path = None
    images_tar_path = None
    warnings = ''
    try:
        os.chdir('/')

        if not clone:
            check_size(archive_dir, cinder_config)

        print ("\nPerforming backup (this might take several minutes):")
        staging_dir = tempfile.mkdtemp(dir=archive_dir)

        system_tar_path = os.path.join(archive_dir,
                                       backup_name + '_system.tgz')
        system_archive = tarfile.open(system_tar_path, "w:gz")
        images_tar_path = os.path.join(archive_dir,
                                       backup_name + '_images.tgz')

        step = 1
        total_steps = 16

        if sysinv_constants.SB_TYPE_CEPH in backend_services.keys():
            total_steps += 1

        if tsconfig.region_config == "yes":
            # We don't run the glance backup step
            total_steps -= 1

        # Step 1: Backup etc
        backup_etc(system_archive)
        utils.progress(total_steps, step, 'backup etc', 'DONE')
        step += 1

        # Step 2: Backup configuration
        backup_config(system_archive, tsconfig.CONFIG_PATH)
        utils.progress(total_steps, step, 'backup configuration', 'DONE')
        step += 1

        # Step 3: Backup puppet data
        backup_puppet_data(system_archive, constants.HIERADATA_PERMDIR)
        utils.progress(total_steps, step, 'backup puppet data', 'DONE')
        step += 1

        # Step 4: Backup keyring
        backup_keyring(system_archive, keyring_permdir)
        utils.progress(total_steps, step, 'backup keyring', 'DONE')
        step += 1

        # Step 5: Backup ldap
        backup_ldap(system_archive, staging_dir)
        utils.progress(total_steps, step, 'backup ldap', 'DONE')
        step += 1

        # Step 6: Backup postgres
        backup_postgres(system_archive, staging_dir, cinder_config)
        utils.progress(total_steps, step, 'backup postgres', 'DONE')
        step += 1

        # Step 7: Backup ceilometer
        backup_ceilometer(system_archive, ceilometer_permdir)
        utils.progress(total_steps, step, 'backup ceilometer', 'DONE')
        step += 1

        if tsconfig.region_config != "yes":
            # Step 8: Backup glance
            images_archive = tarfile.open(images_tar_path, "w:gz")
            backup_std_dir(images_archive, glance_permdir)
            images_archive.close()
            utils.progress(total_steps, step, 'backup glance', 'DONE')
            step += 1

        # Step 9: Backup nova
        if utils.is_combined_load() and not clone:
            # Small system configuration uses /etc/nova/instances on both
            # controllers for instance data.
            backup_nova_instances(system_archive)
            try:
                backup_mate_nova_instances(system_archive, staging_dir)
            except BackupWarn as e:
                warnings += e.message
        utils.progress(total_steps, step, 'backup nova', 'DONE')
        step += 1

        # Step 10: Backup home
        backup_std_dir(system_archive, home_permdir)
        utils.progress(total_steps, step, 'backup home directory', 'DONE')
        step += 1

        # Step 11: Backup patching
        if not clone:
            backup_std_dir(system_archive, patching_permdir)
            utils.progress(total_steps, step, 'backup patching', 'DONE')
        step += 1

        # Step 12: Backup patching repo
        if not clone:
            backup_std_dir(system_archive, patching_repo_permdir)
            utils.progress(total_steps, step, 'backup patching repo', 'DONE')
        step += 1

        # Step 13: Backup extension filesystem
        backup_std_dir(system_archive, extension_permdir)
        utils.progress(total_steps, step, 'backup extension filesystem '
                                          'directory', 'DONE')
        step += 1

        # Step 14: Backup patch-vault filesystem
        if os.path.exists(patch_vault_permdir):
            backup_std_dir(system_archive, patch_vault_permdir)
            utils.progress(total_steps, step, 'backup patch-vault filesystem '
                                              'directory', 'DONE')
        step += 1

        # Step 15: Backup cinder config/LVM config
        # No need to add extra check here as if cinder/LVM is not configured,
        # ../iscsi-target/saveconfig.json will be absent, so this function will
        # do nothing.
        backup_cinder_config(system_archive)
        utils.progress(total_steps, step, 'backup cinder/LVM config', 'DONE')
        step += 1

        # Step 16: Backup ceph crush map
        if sysinv_constants.SB_TYPE_CEPH in backend_services.keys():
            backup_ceph_crush_map(system_archive, staging_dir)
            utils.progress(total_steps, step, 'backup ceph crush map', 'DONE')
            step += 1

        # Step 17: Create archive
        system_archive.close()
        utils.progress(total_steps, step, 'create archive', 'DONE')
        step += 1

    except Exception:
        if system_tar_path and os.path.isfile(system_tar_path):
            os.remove(system_tar_path)
        if images_tar_path and os.path.isfile(images_tar_path):
            os.remove(images_tar_path)

        raise
    finally:
        fmApi.clear_fault(fm_constants.FM_ALARM_ID_BACKUP_IN_PROGRESS,
                          entity_instance_id)
        os.remove(backup_in_progress)
        if staging_dir:
            shutil.rmtree(staging_dir, ignore_errors=True)

    system_msg = "System backup file created"
    images_msg = "Images backup file created"
    if not clone:
        system_msg += ": " + system_tar_path
        images_msg += ": " + images_tar_path

    print system_msg
    if tsconfig.region_config != "yes":
        print images_msg
    if warnings != '':
        print "WARNING: The following problems occurred:"
        print textwrap.fill(warnings, 80)


def create_restore_runtime_config(filename):
    """ Create any runtime parameters needed for Restore."""
    config = {}
    # We need to re-enable Openstack password rules, which
    # were previously disabled while the controller manifests
    # were applying during a Restore
    config['classes'] = ['keystone::security_compliance']
    utils.create_manifest_runtime_config(filename, config)


def overwrite_iscsi_target_config():
    """
    Overwrite the current iscsi target config file with the one
    from the backup archive.
    """

    if not os.path.exists(
            cinder_permdir + '/iscsi-target/saveconfig.json'):
        LOG.info("Restore: Missing current saveconfig.json file")
        return

    if not os.path.exists(
            cinder_permdir + '/iscsi-target/saveconfig.json.bck'):
        LOG.info("Restore: Missing backup saveconfig.json file")
        return

    os.remove(cinder_permdir + '/iscsi-target/saveconfig.json')
    shutil.copyfile(
        cinder_permdir + '/iscsi-target/saveconfig.json.bck',
        cinder_permdir + '/iscsi-target/saveconfig.json')

    os.remove(cinder_permdir + '/iscsi-target/saveconfig.json.bck')
    subprocess.call(["targetctl", "restore"], stdout=DEVNULL, stderr=DEVNULL)


def restore_complete():
    """
    Restore proper ISCSI configuration file after cinder restore.
    Enable compute functionality for AIO system.
    :return: True if compute-config-complete is executed
    """
    if utils.get_system_type() == sysinv_constants.TIS_AIO_BUILD:
        if not os.path.isfile(restore_system_ready):
            print textwrap.fill(
                "--restore-complete can only be run "
                "after restore-system has completed "
                "successfully", 80
            )
            return False

        # The iscsi target config file must be overwritten with the
        # original file from the backup archive.
        # This is due to the cinder restore process actually changing
        # this file. These changes cause VMs that were present at
        # backup time to not boot up properly anymore.
        # The original icsci config file has the proper settings so
        # we use use that.
        overwrite_iscsi_target_config()

        print ("\nApplying compute manifests for %s. " %
               (utils.get_controller_hostname()))
        print ("Node will reboot on completion.")

        sysinv.do_compute_config_complete(utils.get_controller_hostname())

        # show in-progress log on console every 30 seconds
        # until self reboot or timeout
        os.remove(restore_system_ready)
        time.sleep(30)
        for i in range(1, 10):
            print("compute manifest apply in progress ... ")
            time.sleep(30)

        raise RestoreFail("Timeout running compute manifests, "
                          "reboot did not occur")

    else:
        if not os.path.isfile(restore_system_ready):
            print textwrap.fill(
                "--restore-complete can only be run "
                "after restore-system has completed "
                "successfully", 80
            )
            return False
        overwrite_iscsi_target_config()
        os.remove(restore_system_ready)
        return True


def restore_system(backup_file, clone=False):
    """Restoring system configuration."""

    if (os.path.exists(constants.CGCS_CONFIG_FILE) or
            os.path.exists(tsconfig.CONFIG_PATH) or
            os.path.exists(constants.INITIAL_CONFIG_COMPLETE_FILE)):
        print textwrap.fill(
            "Configuration has already been done. "
            "A system restore operation can only be done "
            "immediately after the load has been installed.", 80)
        print
        raise RestoreFail("System configuration already completed")

    if not os.path.isabs(backup_file):
        raise RestoreFail("Backup file (%s) not found. Full path is "
                          "required." % backup_file)

    if os.path.isfile(restore_in_progress):
        raise RestoreFail("Restore already in progress.")
    else:
        open(restore_in_progress, 'w')

    # Add newline to console log for install-clone scenario
    newline = clone
    staging_dir = None

    try:
        try:
            with open(os.devnull, "w") as fnull:
                subprocess.check_call(["vgdisplay", "cgts-vg"],
                                      stdout=fnull,
                                      stderr=fnull)
        except subprocess.CalledProcessError:
            LOG.error("The cgts-vg volume group was not found")
            raise RestoreFail("Volume groups not configured")

        print "\nRestoring system (this will take several minutes):"
        # Use /scratch for the staging dir for now,
        # until /opt/backups is available
        staging_dir = tempfile.mkdtemp(dir='/scratch')
        # Permission change required or postgres restore fails
        subprocess.call(['chmod', 'a+rx', staging_dir], stdout=DEVNULL)
        os.chdir('/')

        step = 1
        total_steps = 24

        # Step 1: Open archive and verify installed load matches backup
        try:
            archive = tarfile.open(backup_file)
        except tarfile.TarError as e:
            LOG.exception(e)
            raise RestoreFail("Error opening backup file. Invalid backup "
                              "file.")
        check_load_versions(archive, staging_dir)
        check_load_subfunctions(archive, staging_dir)
        utils.progress(total_steps, step, 'open archive', 'DONE', newline)
        step += 1

        # Patching is potentially a multi-phase step.
        # If the controller is impacted by patches from the backup,
        # it must be rebooted before continuing the restore.
        # If this is the second pass through, we can skip over this.
        if not os.path.isfile(restore_patching_complete) and not clone:
            # Step 2: Restore patching
            restore_std_dir(archive, patching_permdir)
            utils.progress(total_steps, step, 'restore patching', 'DONE',
                           newline)
            step += 1

            # Step 3: Restore patching repo
            restore_std_dir(archive, patching_repo_permdir)
            utils.progress(total_steps, step, 'restore patching repo', 'DONE',
                           newline)
            step += 1

            # Step 4: Apply patches
            try:
                subprocess.check_output(["sw-patch", "install-local"])
            except subprocess.CalledProcessError:
                LOG.error("Failed to install patches")
                raise RestoreFail("Failed to install patches")
            utils.progress(total_steps, step, 'install patches', 'DONE',
                           newline)
            step += 1

            open(restore_patching_complete, 'w')

            # If the controller was impacted by patches, we need to reboot.
            if os.path.isfile(node_is_patched):
                if not clone:
                    print ("\nThis controller has been patched. " +
                           "A reboot is required.")
                    print ("After the reboot is complete, " +
                           "re-execute the restore command.")
                    while True:
                        user_input = raw_input(
                            "Enter 'reboot' to reboot controller: ")
                        if user_input == 'reboot':
                            break
                LOG.info("This controller has been patched. Rebooting now")
                print("\nThis controller has been patched. Rebooting now\n\n")
                time.sleep(5)
                os.remove(restore_in_progress)
                if staging_dir:
                    shutil.rmtree(staging_dir, ignore_errors=True)
                subprocess.call("reboot")

            else:
                # We need to restart the patch controller and agent, since
                # we setup the repo and patch store outside its control
                with open(os.devnull, "w") as devnull:
                    subprocess.call(
                        ["systemctl",
                         "restart",
                         "sw-patch-controller-daemon.service"],
                        stdout=devnull, stderr=devnull)
                    subprocess.call(
                        ["systemctl",
                         "restart",
                         "sw-patch-agent.service"],
                        stdout=devnull, stderr=devnull)
                if clone:
                    #  No patches were applied, return to cloning code
                    #  to run validation code.
                    return RESTORE_RERUN_REQUIRED
        else:
            # Add the skipped steps
            step += 3

        if os.path.isfile(node_is_patched):
            # If we get here, it means the node was patched by the user
            # AFTER the restore applied patches and rebooted, but didn't
            # reboot.
            # This means the patch lineup no longer matches what's in the
            # backup, but we can't (and probably shouldn't) prevent that.
            # However, since this will ultimately cause the node to fail
            # the goenabled step, we can fail immediately and force the
            # user to reboot.
            print ("\nThis controller has been patched, but not rebooted.")
            print ("Please reboot before continuing the restore process.")
            raise RestoreFail("Controller node patched without rebooting")

        # Flag can now be cleared
        if os.path.exists(restore_patching_complete):
            os.remove(restore_patching_complete)

        # Prefetch keyring
        prefetch_keyring(archive)

        # Step 5: Restore configuration
        restore_configuration(archive, staging_dir)
        # In AIO SX systems, the loopback interface is used as the management
        # interface. However, the application of the interface manifest will
        # not configure the necessary addresses on the loopback interface (see
        # apply_network_config.sh for details). So, we need to configure the
        # loopback interface here.
        if tsconfig.system_mode == sysinv_constants.SYSTEM_MODE_SIMPLEX:
            configure_loopback_interface(archive)
        # Write the simplex flag
        utils.write_simplex_flag()
        utils.progress(total_steps, step, 'restore configuration', 'DONE',
                       newline)
        step += 1

        # Step 6: Apply restore bootstrap manifest
        controller_0_address = utils.get_address_from_hosts_file(
            'controller-0')
        restore_static_puppet_data(archive, constants.HIERADATA_WORKDIR)
        try:
            utils.apply_manifest(controller_0_address,
                                 sysinv_constants.CONTROLLER,
                                 'bootstrap',
                                 constants.HIERADATA_WORKDIR)
        except Exception as e:
            LOG.exception(e)
            raise RestoreFail(
                'Failed to apply bootstrap manifest. '
                'See /var/log/puppet/latest/puppet.log for details.')

        utils.progress(total_steps, step, 'apply bootstrap manifest', 'DONE',
                       newline)
        step += 1

        # Step 7: Restore puppet data
        restore_puppet_data(archive, constants.HIERADATA_WORKDIR)
        utils.progress(total_steps, step, 'restore puppet data', 'DONE',
                       newline)
        step += 1

        # Step 8: Persist configuration
        utils.persist_config()
        utils.progress(total_steps, step, 'persist configuration', 'DONE',
                       newline)
        step += 1

        # Step 9: Apply controller manifest
        try:
            utils.apply_manifest(controller_0_address,
                                 sysinv_constants.CONTROLLER,
                                 'controller',
                                 constants.HIERADATA_PERMDIR)
        except Exception as e:
            LOG.exception(e)
            raise RestoreFail(
                'Failed to apply controller manifest. '
                'See /var/log/puppet/latest/puppet.log for details.')
        utils.progress(total_steps, step, 'apply controller manifest', 'DONE',
                       newline)
        step += 1

        # Step 10: Apply runtime controller manifests
        restore_filename = os.path.join(staging_dir, 'restore.yaml')
        create_restore_runtime_config(restore_filename)
        try:
            utils.apply_manifest(controller_0_address,
                                 sysinv_constants.CONTROLLER,
                                 'runtime',
                                 constants.HIERADATA_PERMDIR,
                                 runtime_filename=restore_filename)
        except Exception as e:
            LOG.exception(e)
            raise RestoreFail(
                'Failed to apply runtime controller manifest. '
                'See /var/log/puppet/latest/puppet.log for details.')
        utils.progress(total_steps, step,
                       'apply runtime controller manifest', 'DONE',
                       newline)
        step += 1

        # Move the staging dir under /opt/backups, now that it's setup
        shutil.rmtree(staging_dir, ignore_errors=True)
        staging_dir = tempfile.mkdtemp(dir=constants.BACKUPS_PATH)
        # Permission change required or postgres restore fails
        subprocess.call(['chmod', 'a+rx', staging_dir], stdout=DEVNULL)

        # Step 11: Restore cinder config file
        restore_cinder_config(archive)
        utils.progress(total_steps, step, 'restore cinder config', 'DONE',
                       newline)
        step += 1

        # Step 12: Apply banner customization
        utils.apply_banner_customization()
        utils.progress(total_steps, step, 'apply banner customization', 'DONE',
                       newline)
        step += 1

        # Step 13: Restore dnsmasq and pxeboot config
        restore_dnsmasq(archive, tsconfig.CONFIG_PATH)
        utils.progress(total_steps, step, 'restore dnsmasq', 'DONE', newline)
        step += 1

        # Step 14: Restore keyring
        restore_keyring(archive, keyring_permdir)
        utils.progress(total_steps, step, 'restore keyring', 'DONE', newline)
        step += 1

        # Step 15: Restore ldap
        restore_ldap(archive, ldap_permdir, staging_dir)
        utils.progress(total_steps, step, 'restore ldap', 'DONE', newline)
        step += 1

        # Step 16: Restore postgres
        restore_postgres(archive, staging_dir)
        utils.progress(total_steps, step, 'restore postgres', 'DONE', newline)
        step += 1

        # Step 17: Restore ceilometer
        restore_ceilometer(archive, ceilometer_permdir)
        utils.progress(total_steps, step, 'restore ceilometer', 'DONE',
                       newline)
        step += 1

        # Step 18: Restore nova
        if utils.is_combined_load():
            restore_nova_instances(archive, staging_dir)
            extract_mate_nova_instances(archive, tsconfig.CONFIG_PATH)
        utils.progress(total_steps, step, 'restore nova', 'DONE', newline)
        step += 1

        # Step 19: Restore ceph crush map
        restore_ceph_crush_map(archive)
        utils.progress(total_steps, step, 'restore ceph crush map', 'DONE',
                       newline)
        step += 1

        # Step 20: Restore home
        restore_std_dir(archive, home_permdir)
        utils.progress(total_steps, step, 'restore home directory', 'DONE',
                       newline)
        step += 1

        # Step 21: Restore extension filesystem
        restore_std_dir(archive, extension_permdir)
        utils.progress(total_steps, step, 'restore extension filesystem '
                                          'directory', 'DONE', newline)
        step += 1

        # Step 22: Restore patch-vault filesystem
        if file_exists_in_archive(archive,
                                  os.path.basename(patch_vault_permdir)):
            restore_std_dir(archive, patch_vault_permdir)
            utils.progress(total_steps, step, 'restore patch-vault filesystem '
                                              'directory', 'DONE', newline)

        step += 1

        # Step 23: Shutdown file systems
        archive.close()
        shutil.rmtree(staging_dir, ignore_errors=True)
        utils.shutdown_file_systems()
        utils.progress(total_steps, step, 'shutdown file systems', 'DONE',
                       newline)
        step += 1

        # Step 24: Recover services
        utils.mtce_restart()
        utils.mark_config_complete()
        time.sleep(120)

        for service in ['sysinv-conductor', 'sysinv-inv']:
            if not utils.wait_sm_service(service):
                raise RestoreFail("Services have failed to initialize.")

        utils.progress(total_steps, step, 'recover services', 'DONE', newline)
        step += 1

        if tsconfig.system_mode != sysinv_constants.SYSTEM_MODE_SIMPLEX:

            print "\nRestoring node states (this will take several minutes):"

            backend_services = sysinv.get_storage_backend_services()

            with openstack.OpenStack() as client:
                # On ceph setups storage nodes take about 90 seconds
                # to become locked. Setting the timeout to 120 seconds
                # for such setups
                lock_timeout = 60
                if sysinv_constants.SB_TYPE_CEPH in backend_services.keys():
                    lock_timeout = 120

                failed_lock_host = False
                skip_hosts = ['controller-0']

                # Wait for nodes to be identified as disabled before attempting
                # to lock hosts. Even if after 3 minute nodes are still not
                # identified as disabled, we still continue the restore.
                if not client.wait_for_hosts_disabled(
                        exempt_hostnames=skip_hosts,
                        timeout=180):
                    LOG.info("At least one node is not in a disabling state. "
                             "Continuing.")

                print "\nLocking nodes:"
                try:
                    failed_hosts = client.lock_hosts(skip_hosts,
                                                     utils.progress,
                                                     timeout=lock_timeout)
                    # Don't power off nodes that could not be locked
                    if len(failed_hosts) > 0:
                        skip_hosts.append(failed_hosts)

                except (KeystoneFail, SysInvFail) as e:
                    LOG.exception(e)
                    failed_lock_host = True

                if not failed_lock_host:
                    print "\nPowering-off nodes:"
                    try:
                        client.power_off_hosts(skip_hosts,
                                               utils.progress,
                                               timeout=60)
                    except (KeystoneFail, SysInvFail) as e:
                        LOG.exception(e)
                        # this is somehow expected

                if failed_lock_host or len(skip_hosts) > 1:
                    print textwrap.fill(
                        "Failed to lock at least one node. " +
                        "Please lock the unlocked nodes manually.", 80
                    )

                if not clone:
                    print textwrap.fill(
                        "Before continuing to the next step in the restore, " +
                        "please ensure all nodes other than controller-0 " +
                        "are powered off. Please refer to the system " +
                        "administration guide for more details.", 80
                    )

    finally:
        os.remove(restore_in_progress)
        if staging_dir:
            shutil.rmtree(staging_dir, ignore_errors=True)
        cleanup_prefetched_keyring()

    fmApi = fm_api.FaultAPIs()
    entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                    sysinv_constants.CONTROLLER_HOSTNAME)
    fault = fm_api.Fault(
        alarm_id=fm_constants.FM_ALARM_ID_BACKUP_IN_PROGRESS,
        alarm_state=fm_constants.FM_ALARM_STATE_MSG,
        entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
        entity_instance_id=entity_instance_id,
        severity=fm_constants.FM_ALARM_SEVERITY_MINOR,
        reason_text=("System Restore complete."),
        # other
        alarm_type=fm_constants.FM_ALARM_TYPE_0,
        # unknown
        probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_UNKNOWN,
        proposed_repair_action=(""),
        service_affecting=False)

    fmApi.set_fault(fault)

    # Mark system restore as complete
    if (utils.get_controller_hostname() ==
            sysinv_constants.CONTROLLER_0_HOSTNAME):
        # Create the flag file that permits the
        # restore_complete command option.
        utils.touch(restore_system_ready)

    return RESTORE_COMPLETE


def restore_images(backup_file, clone=False):
    """Restoring images."""

    if not os.path.exists(constants.INITIAL_CONFIG_COMPLETE_FILE):
        print textwrap.fill(
            "System restore has not been done. "
            "An image restore operation can only be done after "
            "the system restore has been completed.", 80)
        print
        raise RestoreFail("System restore required")

    if not os.path.isabs(backup_file):
        raise RestoreFail("Backup file (%s) not found. Full path is "
                          "required." % backup_file)

    if os.path.isfile(restore_in_progress):
        raise RestoreFail("Restore already in progress.")
    else:
        open(restore_in_progress, 'w')

    # Add newline to console log for install-clone scenario
    newline = clone

    try:
        print "\nRestoring images (this will take several minutes):"
        os.chdir('/')

        step = 1
        total_steps = 2

        # Step 1: Open archive
        try:
            archive = tarfile.open(backup_file)
        except tarfile.TarError as e:
            LOG.exception(e)
            raise RestoreFail("Error opening backup file. Invalid backup "
                              "file.")
        utils.progress(total_steps, step, 'open archive', 'DONE', newline)
        step += 1

        # Step 2: Restore glance
        restore_std_dir(archive, glance_permdir)
        utils.progress(total_steps, step, 'restore glance', 'DONE',
                       newline)
        step += 1
        archive.close()

    finally:
        os.remove(restore_in_progress)
