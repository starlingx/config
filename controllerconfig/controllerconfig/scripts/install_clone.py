#!/usr/bin/python3
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import time
import uuid
import shutil
import tempfile
import subprocess
from six.moves import configparser

import tsconfig.tsconfig as tsconfig
from controllerconfig.common import log
import controllerconfig.utils as utils
import controllerconfig.sysinv_api as sysinv
import controllerconfig.backup_restore as backup_restore
import controllerconfig.clone as clone
from controllerconfig.common.exceptions import CloneFail
from sysinv.common import constants as si_const

LOG = log.get_logger("cloning")
DEVNULL = open(os.devnull, 'w')
INI_FILE = os.path.join("/", clone.CLONE_ARCHIVE_DIR, clone.CLONE_ISO_INI)
SECTION = "clone_iso"
parser = configparser.SafeConfigParser()
clone_name = ""


def console_log(str, err=False):
    """ Log onto console also """
    if err:
        str = "Failed to install clone-image. " + str
        LOG.error(str)
    else:
        LOG.info(str)
    print("\n" + str)


def persist(key, value):
    """ Write into ini file """
    parser.set(SECTION, key, value)
    with open(INI_FILE, 'w') as f:
        parser.write(f)


def set_result(value):
    """ Set the result of installation of clone image """
    persist(clone.RESULT, value)
    persist(clone.INSTALLED, time.strftime("%Y-%m-%d %H:%M:%S %Z"))


def validate_hardware_compatibility():
    """ validate if cloned-image can be installed on this h/w """
    valid = True
    disk_paths = ""
    if parser.has_option(SECTION, "disks"):
        disk_paths = parser.get(SECTION, "disks")
    if not disk_paths:
        console_log("Missing value [disks] in ini file")
        valid = False
    for d in disk_paths.split():
        disk_path, size = d.split('#')
        if os.path.exists('/dev/disk/by-path/' + disk_path):
            LOG.info("Disk [{}] exists".format(disk_path))
            disk_size = clone.get_disk_size('/dev/disk/by-path/' +
                                            disk_path)
            if int(disk_size) >= int(size):
                LOG.info("Disk size is good: {} >= {}"
                         .format(utils.print_bytes(int(disk_size)),
                                 utils.print_bytes(int(size))))
            else:
                console_log("Not enough disk size[{}], "
                            "found:{} looking_for:{}".format(
                                disk_path, utils.print_bytes(int(disk_size)),
                                utils.print_bytes(int(size))), err=True)
                valid = False
        else:
            console_log("Disk [{}] does not exist!"
                        .format(disk_path), err=True)
            valid = False

    interfaces = ""
    if parser.has_option(SECTION, "interfaces"):
        interfaces = parser.get(SECTION, "interfaces")
    if not interfaces:
        console_log("Missing value [interfaces] in ini file")
        valid = False
    for f in interfaces.split():
        if os.path.exists('/sys/class/net/' + f):
            LOG.info("Interface [{}] exists".format(f))
        else:
            console_log("Interface [{}] does not exist!"
                        .format(f), err=True)
            valid = False

    maxcpuid = ""
    if parser.has_option(SECTION, "cpus"):
        maxcpuid = parser.get(SECTION, "cpus")
    if not maxcpuid:
        console_log("Missing value [cpus] in ini file")
        valid = False
    else:
        my_maxcpuid = clone.get_online_cpus()
        if int(maxcpuid) <= int(my_maxcpuid):
            LOG.info("Got enough cpus {},{}".format(
                     maxcpuid, my_maxcpuid))
        else:
            console_log("Not enough CPUs, found:{} looking_for:{}"
                        .format(my_maxcpuid, maxcpuid), err=True)
            valid = False

    mem_total = ""
    if parser.has_option(SECTION, "mem"):
        mem_total = parser.get(SECTION, "mem")
    if not mem_total:
        console_log("Missing value [mem] in ini file")
        valid = False
    else:
        my_mem_total = clone.get_total_mem()
        # relaxed RAM check: within 1 GiB
        if (int(mem_total) - (1024 * 1024)) <= int(my_mem_total):
            LOG.info("Got enough memory {},{}".format(
                     mem_total, my_mem_total))
        else:
            console_log("Not enough memory; found:{} kB, "
                        "looking for a minimum of {} kB"
                        .format(my_mem_total, mem_total), err=True)
            valid = False

    if not valid:
        console_log("Validation failure!")
        set_result(clone.FAIL)
        time.sleep(20)
        exit(1)

    console_log("Successful validation")


def update_sysuuid_in_archive(tmpdir):
    """Update system uuid in system archive file."""
    sysuuid = str(uuid.uuid4())
    clone.find_and_replace(
        [os.path.join(tmpdir, 'postgres/sysinv.sql.data')],
        "CLONEISO_SYSTEM_UUID", sysuuid)
    LOG.info("System uuid updated [%s]" % sysuuid)


def update_db(archive_dir, backup_name):
    """ Update DB before restore """
    path_to_archive = os.path.join(archive_dir, backup_name)
    LOG.info("Updating system archive [%s] DB." % path_to_archive)
    tmpdir = tempfile.mkdtemp(dir=archive_dir)
    try:
        subprocess.check_call(
            ['gunzip', path_to_archive + '.tgz'],
            stdout=DEVNULL, stderr=DEVNULL)
        # Extract only postgres dir to update system uuid
        subprocess.check_call(
            ['tar', '-x',
             '--directory=' + tmpdir,
             '-f', path_to_archive + '.tar',
             'postgres'],
            stdout=DEVNULL, stderr=DEVNULL)
        update_sysuuid_in_archive(tmpdir)
        subprocess.check_call(
            ['tar', '--update',
             '--directory=' + tmpdir,
             '-f', path_to_archive + '.tar',
             'postgres'],
            stdout=DEVNULL, stderr=DEVNULL)
        subprocess.check_call(['gzip', path_to_archive + '.tar'])
        shutil.move(path_to_archive + '.tar.gz', path_to_archive + '.tgz')

    except Exception as e:
        LOG.error("Update of system archive {} failed {}".format(
                  path_to_archive, str(e)))
        raise CloneFail("Failed to update system archive")

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def config_worker():
    """
    Enable worker functionality for AIO system.
    :return: True if worker-config-complete is executed
    """
    if utils.get_system_type() == si_const.TIS_AIO_BUILD:
        console_log("Applying worker manifests for {}. "
                    "Node will reboot on completion."
                    .format(utils.get_controller_hostname()))
        sysinv.do_worker_config_complete(utils.get_controller_hostname())
        time.sleep(30)
        # worker-config-complete has no logs to console. So, wait
        # for some time before showing the login prompt.
        for i in range(1, 10):
            console_log("worker-config in progress..")
            time.sleep(30)
        console_log("Timed out on do_worker_config_complete")
        raise CloneFail("Timed out on do_worker_config_complete")
        return True
    else:
        # worker_config_complete is not needed.
        return False


def finalize_install():
    """ Complete the installation """
    subprocess.call(["rm", "-f", tsconfig.CONFIG_PATH + '/dnsmasq.leases'])
    console_log("Updating system parameters...")
    i = 1
    system_update = False
    # Retries if sysinv is not yet ready
    while i < 10:
        time.sleep(20)
        LOG.info("Attempt %d to update system parameters..." % i)
        try:
            if sysinv.update_clone_system('Cloned_from_' + clone_name,
                                          utils.get_controller_hostname()):
                system_update = True
                break
        except Exception:
            # Sysinv might not be ready yet
            pass
        i += 1
    if not system_update:
        LOG.error("System update failed")
        raise CloneFail("System update failed")

    try:
        output = subprocess.check_output(["finish_install_clone.sh"],
                                         stderr=subprocess.STDOUT)
        LOG.info("finish_install_clone out: {}".format(output))
    except Exception:
        console_log("Failed to cleanup stale OpenStack resources. "
                    "Manually delete the Volumes and Instances.")


def cleanup():
    """ Cleanup after installation """
    LOG.info("Cleaning up...")
    subprocess.call(['systemctl', 'disable', 'install-clone'], stderr=DEVNULL)
    OLD_FILE = os.path.join(tsconfig.PLATFORM_CONF_PATH, clone.CLONE_ISO_INI)
    if os.path.exists(OLD_FILE):
        os.remove(OLD_FILE)
    if os.path.exists(INI_FILE):
        os.chmod(INI_FILE, 0o400)
        shutil.move(INI_FILE, tsconfig.PLATFORM_CONF_PATH)
    shutil.rmtree(os.path.join("/", clone.CLONE_ARCHIVE_DIR),
                  ignore_errors=True)


log.configure()
if os.path.exists(INI_FILE):
    try:
        parser.read(INI_FILE)
        if parser.has_section(SECTION):
            clone_name = parser.get(SECTION, clone.NAME)
            LOG.info("System archive [%s] to be installed." % clone_name)

            first_boot = False
            last_result = clone.IN_PROGRESS
            if not parser.has_option(SECTION, clone.RESULT):
                # first boot after cloning
                first_boot = True
            else:
                last_result = parser.get(SECTION, clone.RESULT)
                LOG.info("Last attempt to install clone was [{}]"
                         .format(last_result))

            if last_result == clone.IN_PROGRESS:
                if first_boot:
                    update_db(os.path.join("/", clone.CLONE_ARCHIVE_DIR),
                              clone_name + '_system')
                else:
                    # Booting up after patch application, do validation
                    validate_hardware_compatibility()

                console_log("+++++ Starting to install clone-image [{}] +++++"
                            .format(clone_name))
                set_result(clone.IN_PROGRESS)
                clone_arch_path = os.path.join("/", clone.CLONE_ARCHIVE_DIR,
                                               clone_name)
                if (backup_restore.RESTORE_RERUN_REQUIRED ==
                    backup_restore.restore_system(
                        clone_arch_path + "_system.tgz",
                        clone=True)):
                    # If there are no patches to be applied, run validation
                    # code and resume restore. If patches were applied, node
                    # will be rebooted and validate will after reboot.
                    validate_hardware_compatibility()
                    LOG.info("validate passed, resuming restore...")
                    backup_restore.restore_system(
                        clone_arch_path + "_system.tgz", clone=True)
                console_log("System archive installed from [%s]" % clone_name)
                backup_restore.restore_images(clone_arch_path + "_images.tgz",
                                              clone=True)
                console_log("Images archive installed from [%s]" % clone_name)
                finalize_install()
                set_result(clone.OK)
                if not config_worker():
                    # do cleanup if worker_config_complete is not required
                    cleanup()
            elif last_result == clone.OK:
                # Installation completed successfully before last reboot
                cleanup()
        else:
            LOG.error("Bad file: {}".format(INI_FILE))
            set_result(clone.FAIL)
            exit(1)
    except Exception as e:
        console_log("Clone [%s] installation failed" % clone_name)
        LOG.exception("install failed")
        set_result(clone.FAIL)
        exit(1)
else:
    console_log("nothing to do, Not installing clone?")
