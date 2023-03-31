#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log as logging
from stevedore import extension


LOG = logging.getLogger(__name__)


class LoadImport(object):
    @staticmethod
    def extract_files(version):
        mgr = extension.ExtensionManager(
            namespace='systemconfig.loads_plugins',
            propagate_map_exceptions=True,
            invoke_on_load=True,
            invoke_args=()
        )

        for plugin in mgr:
            LOG.info("Loaded loads plugin: %s" % plugin.name)

        def extract_files(ext, version):
            return (ext.name, ext.obj.extract_files(version))

        mgr.map(extract_files, version)
