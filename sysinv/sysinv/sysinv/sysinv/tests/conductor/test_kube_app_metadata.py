# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8

# Copyright (c) 2025 Wind River Systems, Inc.

# SPDX-License-Identifier: Apache-2.0
#

"""Test class for Conductor application metadata validations"""

import copy
import io
import os
import ruamel.yaml as yaml

from sysinv.common import constants
from sysinv.conductor import kube_app
from sysinv.conductor import manager
from sysinv.tests import base


class TestKubeAppMetadata(base.TestCase):

    def setUp(self):
        super(TestKubeAppMetadata, self).setUp()

        self.service = manager.ConductorManager("test-host", "test-topic")

    def test_no_dependency_cycle(self):
        # Temporary copy
        mock_apps_metadata = copy.deepcopy(self.service.apps_metadata)

        yaml_file = os.path.join(os.path.dirname(__file__),
                        "data", "metadata_multiple_dependencies.yaml")

        with io.open(yaml_file, 'r', encoding='utf-8') as f:
            metadata_collection = yaml.safe_load_all(f)

            for metadata in metadata_collection:
                kube_app.AppOperator.update_and_process_app_metadata(mock_apps_metadata,
                                                                     metadata['app_name'],
                                                                     metadata)

        self.assertEqual(mock_apps_metadata[constants.APP_METADATA_CYCLIC_DEPENDENCIES], [])

    def test_dependency_cycle(self):
        # Temporary copy
        mock_apps_metadata = copy.deepcopy(self.service.apps_metadata)

        yaml_file = os.path.join(os.path.dirname(__file__),
                        "data", "metadata_mutual_cyclic_dependency.yaml")

        with io.open(yaml_file, 'r', encoding='utf-8') as f:
            metadata_collection = yaml.safe_load_all(f)

            for metadata in metadata_collection:
                kube_app.AppOperator.update_and_process_app_metadata(mock_apps_metadata,
                                                                     metadata['app_name'],
                                                                     metadata)

        self.assertEqual(
            len(mock_apps_metadata[constants.APP_METADATA_CYCLIC_DEPENDENCIES]), 2)

        for dependency in ["app-a", "app-b"]:
            self.assertTrue(dependency
                in mock_apps_metadata[constants.APP_METADATA_CYCLIC_DEPENDENCIES])

    def test_indirect_dependency_cycle(self):
        # Temporary copy
        mock_apps_metadata = copy.deepcopy(self.service.apps_metadata)

        yaml_file = os.path.join(os.path.dirname(__file__),
                        "data", "metadata_indirect_cyclic_dependency.yaml")

        with io.open(yaml_file, 'r', encoding='utf-8') as f:
            metadata_collection = yaml.safe_load_all(f)

            for metadata in metadata_collection:
                kube_app.AppOperator.update_and_process_app_metadata(mock_apps_metadata,
                                                                     metadata['app_name'],
                                                                     metadata)

        self.assertEqual(
            len(mock_apps_metadata[constants.APP_METADATA_CYCLIC_DEPENDENCIES]), 3)

        for dependency in ["app-a", "app-b", "app-c"]:
            self.assertTrue(dependency
                in mock_apps_metadata[constants.APP_METADATA_CYCLIC_DEPENDENCIES])
