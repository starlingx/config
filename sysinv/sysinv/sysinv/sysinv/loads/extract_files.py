#
# Copyright (c) 2023-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os

from sysinv.common import exception
from sysinv.common import utils
from sysinv.loads import base


PLAYBOOKS_PATH = "/usr/share/ansible/stx-ansible/playbooks"


class ExtractFiles(base.BaseLoadImport):
    def extract_files(self, load_version):
        target_dir = "/opt/dc-vault/playbooks/%s" % load_version
        os.makedirs(target_dir, exist_ok=True)

        self._extract_debian_playbooks(load_version, target_dir)

    def _extract_debian_playbooks(self, load_version, target_dir):
        ostree_repo = "/var/www/pages/feed/rel-%s/ostree_repo/" % load_version
        repo_commit = utils.get_ostree_commit(ostree_repo)

        if not repo_commit:
            raise exception.SysinvException(
                "Commit ostree not found for repo: %s" % ostree_repo
            )

        utils.checkout_ostree(ostree_repo, repo_commit, target_dir, subpath=PLAYBOOKS_PATH)
