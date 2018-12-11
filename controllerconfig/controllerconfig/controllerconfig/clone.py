#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Clone a Configured System and Install the image on another
identical hardware or the same hardware.
"""

from __future__ import print_function
import os
import re
import glob
import time
import shutil
import netaddr
import tempfile
import fileinput
import subprocess

from common import constants
from sysinv.common import constants as si_const
import sysinv_api
import tsconfig.tsconfig as tsconfig
from common import log
from common.exceptions import CloneFail, BackupFail
import utils
import backup_restore

DEBUG = False
LOG = log.get_logger(__name__)
DEVNULL = open(os.devnull, 'w')
CLONE_ARCHIVE_DIR = "clone-archive"
CLONE_ISO_INI = ".cloneiso.ini"
NAME = "name"
INSTALLED = "installed_at"
RESULT = "result"
IN_PROGRESS = "in-progress"
FAIL = "failed"
OK = "ok"


def clone_status():
    """ Check status of last install-clone. """
    INI_FILE1 = os.path.join("/", CLONE_ARCHIVE_DIR, CLONE_ISO_INI)
    INI_FILE2 = os.path.join(tsconfig.PLATFORM_CONF_PATH, CLONE_ISO_INI)
    name = "unknown"
    result = "unknown"
    installed_at = "unknown time"
    for ini_file in [INI_FILE1, INI_FILE2]:
        if os.path.exists(ini_file):
            with open(ini_file) as f:
                s = f.read()
                for line in s.split("\n"):
                    if line.startswith(NAME):
                        name = line.split("=")[1].strip()
                    elif line.startswith(RESULT):
                        result = line.split("=")[1].strip()
                    elif line.startswith(INSTALLED):
                        installed_at = line.split("=")[1].strip()
                break  # one file was found, skip the other file
    if result != "unknown":
        if result == OK:
            print("\nInstallation of cloned image [{}] was successful at {}\n"
                  .format(name, installed_at))
        elif result == FAIL:
            print("\nInstallation of cloned image [{}] failed at {}\n"
                  .format(name, installed_at))
        else:
            print("\ninstall-clone is in progress.\n")
    else:
        print("\nCloned image is not installed on this node.\n")


def check_size(archive_dir):
    """ Check if there is enough space to create iso. """
    overhead_bytes = 1024 ** 3  # extra GB for staging directory
    # Size of the cloned iso is directly proportional to the
    # installed package repository (note that patches are a part of
    # the system archive size below).
    # 1G overhead size added (above) will accomodate the temporary
    # workspace (updating system archive etc) needed to create the iso.
    feed_dir = os.path.join('/www', 'pages', 'feed',
                            'rel-' + tsconfig.SW_VERSION)
    overhead_bytes += backup_restore.backup_std_dir_size(feed_dir)

    cinder_config = False
    backend_services = sysinv_api.get_storage_backend_services()
    for services in backend_services.values():
        if (services.find(si_const.SB_SVC_CINDER) != -1):
            cinder_config = True
            break

    clone_size = (
        overhead_bytes +
        backup_restore.backup_etc_size() +
        backup_restore.backup_config_size(tsconfig.CONFIG_PATH) +
        backup_restore.backup_puppet_data_size(constants.HIERADATA_PERMDIR) +
        backup_restore.backup_keyring_size(backup_restore.keyring_permdir) +
        backup_restore.backup_ldap_size() +
        backup_restore.backup_postgres_size(cinder_config) +
        backup_restore.backup_ceilometer_size(
            backup_restore.ceilometer_permdir) +
        backup_restore.backup_std_dir_size(backup_restore.glance_permdir) +
        backup_restore.backup_std_dir_size(backup_restore.home_permdir) +
        backup_restore.backup_std_dir_size(backup_restore.patching_permdir) +
        backup_restore.backup_std_dir_size(
            backup_restore.patching_repo_permdir) +
        backup_restore.backup_std_dir_size(backup_restore.extension_permdir) +
        backup_restore.backup_std_dir_size(
            backup_restore.patch_vault_permdir) +
        backup_restore.backup_cinder_size(backup_restore.cinder_permdir))

    archive_dir_free_space = \
        utils.filesystem_get_free_space(archive_dir)

    if clone_size > archive_dir_free_space:
        print("\nArchive directory (%s) does not have enough free "
              "space (%s), estimated size to create image is %s." %
              (archive_dir,
               utils.print_bytes(archive_dir_free_space),
               utils.print_bytes(clone_size)))
        raise CloneFail("Not enough free space.\n")


def update_bootloader_default(bl_file, host):
    """ Update bootloader files for cloned image """
    if not os.path.exists(bl_file):
        LOG.error("{} does not exist".format(bl_file))
        raise CloneFail("{} does not exist".format(os.path.basename(bl_file)))

    # Tags should be in sync with common-bsp/files/centos.syslinux.cfg
    # and common-bsp/files/grub.cfg
    STANDARD_STANDARD = '0'
    STANDARD_EXTENDED = 'S0'
    AIO_STANDARD = '2'
    AIO_EXTENDED = 'S2'
    AIO_LL_STANDARD = '4'
    AIO_LL_EXTENDED = 'S4'
    if "grub.cfg" in bl_file:
        STANDARD_STANDARD = 'standard>serial>' + \
            si_const.SYSTEM_SECURITY_PROFILE_STANDARD
        STANDARD_EXTENDED = 'standard>serial>' + \
            si_const.SYSTEM_SECURITY_PROFILE_EXTENDED
        AIO_STANDARD = 'aio>serial>' + \
            si_const.SYSTEM_SECURITY_PROFILE_STANDARD
        AIO_EXTENDED = 'aio>serial>' + \
            si_const.SYSTEM_SECURITY_PROFILE_EXTENDED
        AIO_LL_STANDARD = 'aio-lowlat>serial>' + \
            si_const.SYSTEM_SECURITY_PROFILE_STANDARD
        AIO_LL_EXTENDED = 'aio-lowlat>serial>' + \
            si_const.SYSTEM_SECURITY_PROFILE_EXTENDED
        SUBMENUITEM_TBOOT = 'tboot'
        SUBMENUITEM_SECUREBOOT = 'secureboot'

    timeout_line = None
    default_line = None
    default_label_num = STANDARD_STANDARD
    if utils.get_system_type() == si_const.TIS_AIO_BUILD:
        if si_const.LOWLATENCY in tsconfig.subfunctions:
            default_label_num = AIO_LL_STANDARD
        else:
            default_label_num = AIO_STANDARD
    if (tsconfig.security_profile ==
            si_const.SYSTEM_SECURITY_PROFILE_EXTENDED):
        default_label_num = STANDARD_EXTENDED
        if utils.get_system_type() == si_const.TIS_AIO_BUILD:
            if si_const.LOWLATENCY in tsconfig.subfunctions:
                default_label_num = AIO_LL_EXTENDED
            else:
                default_label_num = AIO_EXTENDED
        if "grub.cfg" in bl_file:
            if host.tboot is not None:
                if host.tboot == "true":
                    default_label_num = default_label_num + '>' + \
                        SUBMENUITEM_TBOOT
                else:
                    default_label_num = default_label_num + '>' + \
                        SUBMENUITEM_SECUREBOOT

    try:
        with open(bl_file) as f:
            s = f.read()
            for line in s.split("\n"):
                if line.startswith("timeout"):
                    timeout_line = line
                elif line.startswith("default"):
                    default_line = line

            if "grub.cfg" in bl_file:
                replace = "default='{}'\ntimeout=10".format(default_label_num)
            else:  # isolinux format
                replace = "default {}\ntimeout 10".format(default_label_num)

            if default_line and timeout_line:
                s = s.replace(default_line, "")
                s = s.replace(timeout_line, replace)
            elif default_line:
                s = s.replace(default_line, replace)
            elif timeout_line:
                s = s.replace(timeout_line, replace)
            else:
                s = replace + s

            s = re.sub(r'boot_device=[^\s]*',
                       'boot_device=%s' % host.boot_device,
                       s)
            s = re.sub(r'rootfs_device=[^\s]*',
                       'rootfs_device=%s' % host.rootfs_device,
                       s)
            s = re.sub(r'console=[^\s]*',
                       'console=%s' % host.console,
                       s)

        with open(bl_file, "w") as f:
            LOG.info("rewriting {}: label={} find=[{}][{}] replace=[{}]"
                     .format(bl_file, default_label_num, timeout_line,
                             default_line, replace.replace('\n', '<newline>')))
            f.write(s)

    except Exception as e:
        LOG.error("update_bootloader_default failed: {}".format(e))
        raise CloneFail("Failed to update bootloader files")


def get_online_cpus():
    """ Get max cpu id """
    with open('/sys/devices/system/cpu/online') as f:
        s = f.read()
        max_cpu_id = s.split('-')[-1].strip()
        LOG.info("Max cpu id:{} [{}]".format(max_cpu_id, s.strip()))
        return max_cpu_id
    return ""


def get_total_mem():
    """ Get total memory size """
    with open('/proc/meminfo') as f:
        s = f.read()
        for line in s.split("\n"):
            if line.startswith("MemTotal:"):
                mem_total = line.split()[1]
                LOG.info("MemTotal:[{}]".format(mem_total))
                return mem_total
    return ""


def get_disk_size(disk):
    """ Get the disk size """
    disk_size = ""
    try:
        disk_size = subprocess.check_output(
            ['lsblk', '--nodeps', '--output', 'SIZE',
             '--noheadings', '--bytes', disk])
    except Exception as e:
        LOG.exception(e)
        LOG.error("Failed to get disk size [{}]".format(disk))
        raise CloneFail("Failed to get disk size")
    return disk_size.strip()


def create_ini_file(clone_archive_dir, iso_name):
    """Create clone ini file."""
    interfaces = ""
    my_hostname = utils.get_controller_hostname()
    macs = sysinv_api.get_mac_addresses(my_hostname)
    for intf in macs.keys():
        interfaces += intf + " "

    disk_paths = ""
    for _, _, files in os.walk('/dev/disk/by-path'):
        for f in files:
            if f.startswith("pci-") and "part" not in f and "usb" not in f:
                disk_size = get_disk_size('/dev/disk/by-path/' + f)
                disk_paths += f + "#" + disk_size + " "
        break  # no need to go into sub-dirs.

    LOG.info("create ini: {} {}".format(macs, files))
    with open(os.path.join(clone_archive_dir, CLONE_ISO_INI), 'w') as f:
            f.write('[clone_iso]\n')
            f.write('name=' + iso_name + '\n')
            f.write('host=' + my_hostname + '\n')
            f.write('created_at=' + time.strftime("%Y-%m-%d %H:%M:%S %Z")
                    + '\n')
            f.write('interfaces=' + interfaces + '\n')
            f.write('disks=' + disk_paths + '\n')
            f.write('cpus=' + get_online_cpus() + '\n')
            f.write('mem=' + get_total_mem() + '\n')
    LOG.info("create ini: ({}) ({})".format(interfaces, disk_paths))


def create_iso(iso_name, archive_dir):
    """ Create iso image. This is modelled after
        the cgcs-root/build-tools/build-iso tool. """
    try:
        controller_0 = sysinv_api.get_host_data('controller-0')
    except Exception as e:
        e_log = "Failed to retrieve controller-0 inventory details."
        LOG.exception(e_log)
        raise CloneFail(e_log)

    iso_dir = os.path.join(archive_dir, 'isolinux')
    clone_archive_dir = os.path.join(iso_dir, CLONE_ARCHIVE_DIR)
    output = None
    tmpdir = None
    total_steps = 6
    step = 1
    print ("\nCreating ISO:")

    # Add the correct kick-start file to the image
    ks_file = "controller_ks.cfg"
    if utils.get_system_type() == si_const.TIS_AIO_BUILD:
        if si_const.LOWLATENCY in tsconfig.subfunctions:
            ks_file = "smallsystem_lowlatency_ks.cfg"
        else:
            ks_file = "smallsystem_ks.cfg"

    try:
        # prepare the iso files
        images_dir = os.path.join(iso_dir, 'images')
        os.mkdir(images_dir, 0644)
        pxe_dir = os.path.join('/pxeboot',
                               'rel-' + tsconfig.SW_VERSION)
        os.symlink(pxe_dir + '/installer-bzImage',
                   iso_dir + '/vmlinuz')
        os.symlink(pxe_dir + '/installer-initrd',
                   iso_dir + '/initrd.img')
        utils.progress(total_steps, step, 'preparing files', 'DONE')
        step += 1

        feed_dir = os.path.join('/www', 'pages', 'feed',
                                'rel-' + tsconfig.SW_VERSION)
        os.symlink(feed_dir + '/Packages', iso_dir + '/Packages')
        os.symlink(feed_dir + '/repodata', iso_dir + '/repodata')
        os.symlink(feed_dir + '/LiveOS', iso_dir + '/LiveOS')
        shutil.copy2(feed_dir + '/isolinux.cfg', iso_dir)
        update_bootloader_default(iso_dir + '/isolinux.cfg', controller_0)
        shutil.copyfile('/usr/share/syslinux/isolinux.bin',
                        iso_dir + '/isolinux.bin')
        os.symlink('/usr/share/syslinux/vesamenu.c32',
                   iso_dir + '/vesamenu.c32')
        for filename in glob.glob(os.path.join(feed_dir, '*ks.cfg')):
            shutil.copy(os.path.join(feed_dir, filename), iso_dir)
        utils.progress(total_steps, step, 'preparing files', 'DONE')
        step += 1

        efiboot_dir = os.path.join(iso_dir, 'EFI', 'BOOT')
        os.makedirs(efiboot_dir, 0644)
        l_efi_dir = os.path.join('/boot', 'efi', 'EFI')
        shutil.copy2(l_efi_dir + '/BOOT/BOOTX64.EFI', efiboot_dir)
        shutil.copy2(l_efi_dir + '/centos/MokManager.efi', efiboot_dir)
        shutil.copy2(l_efi_dir + '/centos/grubx64.efi', efiboot_dir)
        shutil.copy2('/pxeboot/EFI/grub.cfg', efiboot_dir)
        update_bootloader_default(efiboot_dir + '/grub.cfg', controller_0)
        shutil.copytree(l_efi_dir + '/centos/fonts',
                        efiboot_dir + '/fonts')
        # copy EFI boot image and update the grub.cfg file
        efi_img = images_dir + '/efiboot.img'
        shutil.copy2(pxe_dir + '/efiboot.img', efi_img)
        tmpdir = tempfile.mkdtemp(dir=archive_dir)
        output = subprocess.check_output(
            ["mount", "-t", "vfat", "-o", "loop",
             efi_img, tmpdir],
            stderr=subprocess.STDOUT)
        # replace the grub.cfg file with the updated file
        efi_grub_f = os.path.join(tmpdir, 'EFI', 'BOOT', 'grub.cfg')
        os.remove(efi_grub_f)
        shutil.copy2(efiboot_dir + '/grub.cfg', efi_grub_f)
        subprocess.call(['umount', tmpdir])
        shutil.rmtree(tmpdir, ignore_errors=True)
        tmpdir = None

        epoch_time = "%.9f" % time.time()
        disc_info = [epoch_time, tsconfig.SW_VERSION, "x86_64"]
        with open(iso_dir + '/.discinfo', 'w') as f:
            f.write('\n'.join(disc_info))

        # copy the latest install_clone executable
        shutil.copy2('/usr/bin/install_clone', iso_dir)
        subprocess.check_output("cat /pxeboot/post_clone_iso_ks.cfg >> " +
                                iso_dir + "/" + ks_file, shell=True)
        utils.progress(total_steps, step, 'preparing files', 'DONE')
        step += 1

        # copy patches
        iso_patches_dir = os.path.join(iso_dir, 'patches')
        iso_patch_repo_dir = os.path.join(iso_patches_dir, 'repodata')
        iso_patch_pkgs_dir = os.path.join(iso_patches_dir, 'Packages')
        iso_patch_metadata_dir = os.path.join(iso_patches_dir, 'metadata')
        iso_patch_applied_dir = os.path.join(iso_patch_metadata_dir, 'applied')
        iso_patch_committed_dir = os.path.join(iso_patch_metadata_dir,
                                               'committed')

        os.mkdir(iso_patches_dir, 0o755)
        os.mkdir(iso_patch_repo_dir, 0o755)
        os.mkdir(iso_patch_pkgs_dir, 0o755)
        os.mkdir(iso_patch_metadata_dir, 0o755)
        os.mkdir(iso_patch_applied_dir, 0o755)
        os.mkdir(iso_patch_committed_dir, 0o755)

        repodata = '/www/pages/updates/rel-%s/repodata/' % tsconfig.SW_VERSION
        pkgsdir = '/www/pages/updates/rel-%s/Packages/' % tsconfig.SW_VERSION
        patch_applied_dir = '/opt/patching/metadata/applied/'
        patch_committed_dir = '/opt/patching/metadata/committed/'
        subprocess.check_call(['rsync', '-a', repodata,
                               '%s/' % iso_patch_repo_dir])
        if os.path.exists(pkgsdir):
            subprocess.check_call(['rsync', '-a', pkgsdir,
                                   '%s/' % iso_patch_pkgs_dir])
        if os.path.exists(patch_applied_dir):
            subprocess.check_call(['rsync', '-a', patch_applied_dir,
                                   '%s/' % iso_patch_applied_dir])
        if os.path.exists(patch_committed_dir):
            subprocess.check_call(['rsync', '-a', patch_committed_dir,
                                   '%s/' % iso_patch_committed_dir])
        utils.progress(total_steps, step, 'preparing files', 'DONE')
        step += 1

        create_ini_file(clone_archive_dir, iso_name)

        os.chmod(iso_dir + '/isolinux.bin', 0664)
        iso_file = os.path.join(archive_dir, iso_name + ".iso")
        output = subprocess.check_output(
            ["nice", "mkisofs",
             "-o", iso_file, "-R", "-D",
             "-A", "oe_iso_boot", "-V", "oe_iso_boot",
             "-f", "-quiet",
             "-b", "isolinux.bin", "-c", "boot.cat", "-no-emul-boot",
             "-boot-load-size", "4", "-boot-info-table",
             "-eltorito-alt-boot", "-e", "images/efiboot.img",
             "-no-emul-boot",
             iso_dir],
            stderr=subprocess.STDOUT)
        LOG.info("{} created: [{}]".format(iso_file, output))
        utils.progress(total_steps, step, 'iso created', 'DONE')
        step += 1

        output = subprocess.check_output(
            ["nice", "isohybrid",
             "--uefi",
             iso_file],
            stderr=subprocess.STDOUT)
        LOG.debug("isohybrid: {}".format(output))

        output = subprocess.check_output(
            ["nice", "implantisomd5",
             iso_file],
            stderr=subprocess.STDOUT)
        LOG.debug("implantisomd5: {}".format(output))
        utils.progress(total_steps, step, 'checksum implanted', 'DONE')
        print("Cloned iso image created: {}".format(iso_file))

    except Exception as e:
        LOG.exception(e)
        e_log = "ISO creation ({}) failed".format(iso_name)
        if output:
            e_log += ' [' + output + ']'
        LOG.error(e_log)
        raise CloneFail("ISO creation failed.")

    finally:
        if tmpdir:
            subprocess.call(['umount', tmpdir], stderr=DEVNULL)
            shutil.rmtree(tmpdir, ignore_errors=True)


def find_and_replace_in_file(target, find, replace):
    """ Find and replace a string in a file. """
    found = None
    try:
        for line in fileinput.FileInput(target, inplace=1):
            if find in line:
                # look for "find" string within word boundaries
                fpat = r'\b' + find + r'\b'
                line = re.sub(fpat, replace, line)
                found = True
            print(line, end=' ')

    except Exception as e:
        LOG.error("Failed to replace [{}] with [{}] in [{}]: {}"
                  .format(find, replace, target, str(e)))
        found = None
    finally:
        fileinput.close()
    return found


def find_and_replace(target_list, find, replace):
    """ Find and replace a string in all files in a directory. """
    found = False
    file_list = []
    for target in target_list:
        if os.path.isfile(target):
            if find_and_replace_in_file(target, find, replace):
                found = True
                file_list.append(target)
        elif os.path.isdir(target):
            try:
                output = subprocess.check_output(
                    ['grep', '-rl', find, target])
                if output:
                    for line in output.split('\n'):
                        if line and find_and_replace_in_file(
                           line, find, replace):
                            found = True
                            file_list.append(line)
            except Exception:
                pass  # nothing found in that directory
    if not found:
        LOG.error("[{}] not found in backup".format(find))
    else:
        LOG.info("Replaced [{}] with [{}] in {}".format(
                 find, replace, file_list))


def remove_from_archive(archive, unwanted):
    """ Remove a file from the archive. """
    try:
        subprocess.check_call(["tar", "--delete",
                               "--file=" + archive,
                               unwanted])
    except subprocess.CalledProcessError as e:
        LOG.error("Delete of {} failed: {}".format(unwanted, e.output))
        raise CloneFail("Failed to modify backup archive")


def update_oamip_in_archive(tmpdir):
    """ Update OAM IP in system archive file. """
    oam_list = sysinv_api.get_oam_ip()
    if not oam_list:
        raise CloneFail("Failed to get OAM IP")
    for oamfind in [oam_list.oam_start_ip, oam_list.oam_end_ip,
                    oam_list.oam_subnet, oam_list.oam_floating_ip,
                    oam_list.oam_c0_ip, oam_list.oam_c1_ip]:
        if not oamfind:
            continue
        ip = netaddr.IPNetwork(oamfind)
        find_str = ""
        if ip.version == 4:
            # if ipv4, use 192.0.x.x as the temporary oam ip
            find_str = str(ip.ip)
            ipstr_list = find_str.split('.')
            ipstr_list[0] = '192'
            ipstr_list[1] = '0'
            repl_ipstr = ".".join(ipstr_list)
        else:
            # if ipv6, use 2001:db8:x as the temporary oam ip
            find_str = str(ip.ip)
            ipstr_list = find_str.split(':')
            ipstr_list[0] = '2001'
            ipstr_list[1] = 'db8'
            repl_ipstr = ":".join(ipstr_list)
        if repl_ipstr:
            find_and_replace(
                [os.path.join(tmpdir, 'etc/hosts'),
                 os.path.join(tmpdir, 'etc/sysconfig/network-scripts'),
                 os.path.join(tmpdir, 'etc/nfv/vim/config.ini'),
                 os.path.join(tmpdir, 'etc/haproxy/haproxy.cfg'),
                 os.path.join(tmpdir, 'etc/heat/heat.conf'),
                 os.path.join(tmpdir, 'etc/keepalived/keepalived.conf'),
                 os.path.join(tmpdir, 'etc/murano/murano.conf'),
                 os.path.join(tmpdir, 'etc/vswitch/vswitch.ini'),
                 os.path.join(tmpdir, 'etc/nova/nova.conf'),
                 os.path.join(tmpdir, 'config/hosts'),
                 os.path.join(tmpdir, 'hieradata'),
                 os.path.join(tmpdir, 'postgres/keystone.sql.data'),
                 os.path.join(tmpdir, 'postgres/sysinv.sql.data')],
                find_str, repl_ipstr)
        else:
            LOG.error("Failed to modify OAM IP:[{}]"
                      .format(oamfind))
            raise CloneFail("Failed to modify OAM IP")


def update_mac_in_archive(tmpdir):
    """ Update MAC addresses in system archive file. """
    hostname = utils.get_controller_hostname()
    macs = sysinv_api.get_mac_addresses(hostname)
    for intf, mac in macs.items():
        find_and_replace(
            [os.path.join(tmpdir, 'postgres/sysinv.sql.data')],
            mac, "CLONEISOMAC_{}{}".format(hostname, intf))

    if (tsconfig.system_mode == si_const.SYSTEM_MODE_DUPLEX or
            tsconfig.system_mode == si_const.SYSTEM_MODE_DUPLEX_DIRECT):
        hostname = utils.get_mate_controller_hostname()
        macs = sysinv_api.get_mac_addresses(hostname)
        for intf, mac in macs.items():
            find_and_replace(
                [os.path.join(tmpdir, 'postgres/sysinv.sql.data')],
                mac, "CLONEISOMAC_{}{}".format(hostname, intf))


def update_disk_serial_id_in_archive(tmpdir):
    """ Update disk serial id in system archive file. """
    hostname = utils.get_controller_hostname()
    disk_sids = sysinv_api.get_disk_serial_ids(hostname)
    for d_dnode, d_sid in disk_sids.items():
        find_and_replace(
            [os.path.join(tmpdir, 'postgres/sysinv.sql.data')],
            d_sid, "CLONEISODISKSID_{}{}".format(hostname, d_dnode))

    if (tsconfig.system_mode == si_const.SYSTEM_MODE_DUPLEX or
            tsconfig.system_mode == si_const.SYSTEM_MODE_DUPLEX_DIRECT):
        hostname = utils.get_mate_controller_hostname()
        disk_sids = sysinv_api.get_disk_serial_ids(hostname)
        for d_dnode, d_sid in disk_sids.items():
            find_and_replace(
                [os.path.join(tmpdir, 'postgres/sysinv.sql.data')],
                d_sid, "CLONEISODISKSID_{}{}".format(hostname, d_dnode))


def update_sysuuid_in_archive(tmpdir):
    """ Update system uuid in system archive file. """
    sysuuid = sysinv_api.get_system_uuid()
    find_and_replace(
        [os.path.join(tmpdir, 'postgres/sysinv.sql.data')],
        sysuuid, "CLONEISO_SYSTEM_UUID")


def update_backup_archive(backup_name, archive_dir):
    """ Update backup archive file to be included in clone-iso """
    path_to_archive = os.path.join(archive_dir, backup_name)
    tmpdir = tempfile.mkdtemp(dir=archive_dir)
    try:
        subprocess.check_call(
            ['gunzip', path_to_archive + '.tgz'],
            stdout=DEVNULL, stderr=DEVNULL)
        # 70-persistent-net.rules with the correct MACs will be
        # generated on the linux boot on the cloned side. Remove
        # the stale file from original side.
        remove_from_archive(path_to_archive + '.tar',
                            'etc/udev/rules.d/70-persistent-net.rules')
        # Extract only a subset of directories which have files to be
        # updated for oam-ip and MAC addresses. After updating the files
        # these directories are added back to the archive.
        subprocess.check_call(
            ['tar', '-x',
             '--directory=' + tmpdir,
             '-f', path_to_archive + '.tar',
             'etc', 'postgres', 'config',
             'hieradata'],
            stdout=DEVNULL, stderr=DEVNULL)
        update_oamip_in_archive(tmpdir)
        update_mac_in_archive(tmpdir)
        update_disk_serial_id_in_archive(tmpdir)
        update_sysuuid_in_archive(tmpdir)
        subprocess.check_call(
            ['tar', '--update',
             '--directory=' + tmpdir,
             '-f', path_to_archive + '.tar',
             'etc', 'postgres', 'config',
             'hieradata'],
            stdout=DEVNULL, stderr=DEVNULL)
        subprocess.check_call(['gzip', path_to_archive + '.tar'])
        shutil.move(path_to_archive + '.tar.gz', path_to_archive + '.tgz')

    except Exception as e:
        LOG.error("Update of backup archive {} failed {}".format(
                  path_to_archive, str(e)))
        raise CloneFail("Failed to update backup archive")

    finally:
        if not DEBUG:
            shutil.rmtree(tmpdir, ignore_errors=True)


def validate_controller_state():
    """ Cloning allowed now? """
    # Check if this Controller is enabled and provisioned
    try:
        if not sysinv_api.controller_enabled_provisioned(
                utils.get_controller_hostname()):
            raise CloneFail("Controller is not enabled/provisioned")
        if (tsconfig.system_mode == si_const.SYSTEM_MODE_DUPLEX or
                tsconfig.system_mode == si_const.SYSTEM_MODE_DUPLEX_DIRECT):
            if not sysinv_api.controller_enabled_provisioned(
                    utils.get_mate_controller_hostname()):
                raise CloneFail("Mate controller is not enabled/provisioned")
    except CloneFail:
        raise
    except Exception:
        raise CloneFail("Controller is not enabled/provisioned")

    if utils.get_system_type() != si_const.TIS_AIO_BUILD:
        raise CloneFail("Cloning supported only on All-in-one systems")

    if len(sysinv_api.get_alarms()) > 0:
        raise CloneFail("There are active alarms on this system!")


def clone(backup_name, archive_dir):
    """ Do Cloning """
    validate_controller_state()
    LOG.info("Cloning [{}] at [{}]".format(backup_name, archive_dir))
    check_size(archive_dir)

    isolinux_dir = os.path.join(archive_dir, 'isolinux')
    clone_archive_dir = os.path.join(isolinux_dir, CLONE_ARCHIVE_DIR)
    if os.path.exists(isolinux_dir):
        LOG.info("deleting old iso_dir %s" % isolinux_dir)
        shutil.rmtree(isolinux_dir, ignore_errors=True)
    os.makedirs(clone_archive_dir, 0644)

    try:
        backup_restore.backup(backup_name, clone_archive_dir, clone=True)
        LOG.info("system backup done")
        update_backup_archive(backup_name + '_system', clone_archive_dir)
        create_iso(backup_name, archive_dir)
    except BackupFail as e:
        raise CloneFail(e.message)
    except CloneFail as e:
        raise
    finally:
        if not DEBUG:
            shutil.rmtree(isolinux_dir, ignore_errors=True)
