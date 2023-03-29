#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import shutil

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils
from sysinv.loads import base


PLAYBOOKS_PATH = "/usr/share/ansible/stx-ansible/playbooks"


class ExtractFiles(base.BaseLoadImport):
    def extract_files(self, load_version):
        target_dir = "/var/opt/ansible/%s" % load_version
        os.makedirs(target_dir, exist_ok=True)
        os_version = utils.get_os_target(load_version)

        if os_version == constants.OS_CENTOS:
            self._extract_centos_playbooks(load_version, target_dir)
        elif os_version == constants.OS_DEBIAN:
            self._extract_debian_playbooks(load_version, target_dir)

    def _extract_centos_playbooks(self, load_version, target_dir):
        package_name = "playbookconfig"
        playbook_pkg = utils.get_rpm_package(load_version, package_name)

        if not playbook_pkg:
            raise exception.SysinvException(
                "playbookconfig package not found",
            )

        utils.extract_rpm_package(playbook_pkg, target_dir)

        source_dir = os.path.join(target_dir, PLAYBOOKS_PATH)

        self._move_all_files(source_dir, target_dir)

        shutil.rmtree("%s/usr" % target_dir)

    def _move_all_files(self, source_dir, target_dir):
        file_names = os.listdir(source_dir)

        for file_name in file_names:
            file_path = os.path.join(source_dir, file_name)
            shutil.move(file_path, target_dir)

    def _extract_debian_playbooks(self, load_version, target_dir):
        ostree_repo = "/var/www/pages/feed/rel-%s/ostree_repo/" % load_version
        repo_commit = utils.get_ostree_commit(ostree_repo)

        if not repo_commit:
            raise exception.SysinvException(
                "Commit ostree not found for repo: %s" % ostree_repo
            )

        utils.checkout_ostree(ostree_repo, repo_commit, target_dir, subpath=PLAYBOOKS_PATH)
