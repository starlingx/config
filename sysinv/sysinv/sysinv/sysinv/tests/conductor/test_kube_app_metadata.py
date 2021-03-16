#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Test class for Sysinv Kube App Metadata operations."""

import copy
import os
import ruamel.yaml as yaml

from sysinv.common import constants
from sysinv.conductor import kube_app
from sysinv.conductor import manager
from sysinv.tests import base


class TestKubeAppMetadata(base.TestCase):

    def setUp(self):
        super(TestKubeAppMetadata, self).setUp()

        # Manager holds apps_metadata dict
        self.service = manager.ConductorManager('test-host', 'test-topic')

    def test_reapply_order_computation(self):
        # Temporary copy
        mock_apps_metadata = copy.deepcopy(self.service.apps_metadata)

        yaml_file = os.path.join(os.path.dirname(__file__),
                                 "data", "metadata_app_reapply_1.yaml")
        with open(yaml_file, 'r') as f:
            metadata_collection = yaml.safe_load_all(f)

            for metadata in metadata_collection:
                kube_app.AppOperator.update_and_process_app_metadata(mock_apps_metadata,
                                                                     metadata['app_name'],
                                                                     metadata)

        ordered_list = mock_apps_metadata[constants.APP_METADATA_ORDERED_APPS]

        before_apps = {}
        self._compute_before_apps(mock_apps_metadata, before_apps)

        # All apps are present in the ordered list
        for app in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
            self.assertTrue(app in ordered_list)

        # All apps are present only once
        self.assertEqual(len(ordered_list),
                         len(mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]))

        # All apps have the constrains satisfied
        for app in before_apps.keys():
            for before in before_apps[app]:
                self.assertTrue(ordered_list.index(before) < ordered_list.index(app))

    def test_reapply_non_existing_1(self):
        # Temporary copy
        mock_apps_metadata = copy.deepcopy(self.service.apps_metadata)

        yaml_file = os.path.join(os.path.dirname(__file__),
                                 "data", "metadata_app_reapply_non_existing_1.yaml")
        with open(yaml_file, 'r') as f:
            metadata_collection = yaml.safe_load_all(f)

            for metadata in metadata_collection:
                kube_app.AppOperator.update_and_process_app_metadata(mock_apps_metadata,
                                                                     metadata['app_name'],
                                                                     metadata)

        ordered_list = mock_apps_metadata[constants.APP_METADATA_ORDERED_APPS]

        before_apps = {}
        self._compute_before_apps(mock_apps_metadata, before_apps)

        # All apps are present in the ordered list
        for app in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
            self.assertTrue(app in ordered_list)

        # All apps are present only once
        self.assertEqual(len(ordered_list),
                         len(mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]))

        self.skipTest("Corner case not implemented -> "
                      "app based only on non-existing")

        # All apps have the constrains satisfied
        for app in before_apps.keys():
            for before in before_apps[app]:
                # Skip non-existing
                if app in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS] and \
                        before in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
                    self.assertTrue(ordered_list.index(before) < ordered_list.index(app))

    def test_reapply_non_existing_2(self):
        # Temporary copy
        mock_apps_metadata = copy.deepcopy(self.service.apps_metadata)

        yaml_file = os.path.join(os.path.dirname(__file__),
                                 "data", "metadata_app_reapply_non_existing_2.yaml")
        with open(yaml_file, 'r') as f:
            metadata_collection = yaml.safe_load_all(f)

            for metadata in metadata_collection:
                kube_app.AppOperator.update_and_process_app_metadata(mock_apps_metadata,
                                                                     metadata['app_name'],
                                                                     metadata)

        ordered_list = mock_apps_metadata[constants.APP_METADATA_ORDERED_APPS]

        before_apps = {}
        self._compute_before_apps(mock_apps_metadata, before_apps)

        # All apps are present in the ordered list
        for app in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
            self.assertTrue(app in ordered_list)

        # All apps are present only once
        self.assertEqual(len(ordered_list),
                         len(mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]))

        # All apps have the constrains satisfied
        for app in before_apps.keys():
            for before in before_apps[app]:
                # Skip non-existing
                if app in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS] and \
                        before in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
                    self.assertTrue(ordered_list.index(before) < ordered_list.index(app))

    def test_reapply_non_managed_1(self):
        # Temporary copy
        mock_apps_metadata = copy.deepcopy(self.service.apps_metadata)

        yaml_file = os.path.join(os.path.dirname(__file__),
                                 "data", "metadata_app_reapply_non_managed_1.yaml")
        with open(yaml_file, 'r') as f:
            metadata_collection = yaml.safe_load_all(f)

            for metadata in metadata_collection:
                kube_app.AppOperator.update_and_process_app_metadata(mock_apps_metadata,
                                                                     metadata['app_name'],
                                                                     metadata)

        ordered_list = mock_apps_metadata[constants.APP_METADATA_ORDERED_APPS]

        before_apps = {}
        self._compute_before_apps(mock_apps_metadata, before_apps)

        # All apps are present in the ordered list
        for app in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
            self.assertTrue(app in ordered_list)

        # All apps are present only once
        self.assertEqual(len(ordered_list),
                         len(mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]))

        self.skipTest("Corner case not implemented -> "
                      "app based only on non platform managed")

        # All apps have the constrains satisfied
        for app in before_apps.keys():
            for before in before_apps[app]:
                # Skip non-existing
                if app in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS] and \
                        before in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
                    self.assertTrue(ordered_list.index(before) < ordered_list.index(app))

    def test_reapply_not_cycle_1(self):
        # Temporary copy
        mock_apps_metadata = copy.deepcopy(self.service.apps_metadata)

        yaml_file = os.path.join(os.path.dirname(__file__),
                                 "data", "metadata_app_reapply_not_cycle_1_non_managed.yaml")
        with open(yaml_file, 'r') as f:
            metadata_collection = yaml.safe_load_all(f)

            for metadata in metadata_collection:
                kube_app.AppOperator.update_and_process_app_metadata(mock_apps_metadata,
                                                                     metadata['app_name'],
                                                                     metadata)

        ordered_list = mock_apps_metadata[constants.APP_METADATA_ORDERED_APPS]

        before_apps = {}
        self._compute_before_apps(mock_apps_metadata, before_apps)

        # All apps are present in the ordered list
        for app in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
            self.assertTrue(app in ordered_list)

        # All apps are present only once
        self.assertEqual(len(ordered_list),
                         len(mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]))

        self.skipTest("Corner case not implemented -> "
                      "app based only on non platform managed")

        # All apps have the constrains satisfied
        for app in before_apps.keys():
            for before in before_apps[app]:
                # Skip non-existing
                if app in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS] and \
                        before in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
                    self.assertTrue(ordered_list.index(before) < ordered_list.index(app))

    def test_reapply_not_cycle_2(self):
        # Temporary copy
        mock_apps_metadata = copy.deepcopy(self.service.apps_metadata)

        yaml_file = os.path.join(os.path.dirname(__file__),
                                 "data", "metadata_app_reapply_not_cycle_2.yaml")
        with open(yaml_file, 'r') as f:
            metadata_collection = yaml.safe_load_all(f)

            for metadata in metadata_collection:
                kube_app.AppOperator.update_and_process_app_metadata(mock_apps_metadata,
                                                                     metadata['app_name'],
                                                                     metadata)

        ordered_list = mock_apps_metadata[constants.APP_METADATA_ORDERED_APPS]

        before_apps = {}
        self._compute_before_apps(mock_apps_metadata, before_apps)

        # All apps are present in the ordered list
        for app in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
            self.assertTrue(app in ordered_list)

        # All apps are present only once
        self.assertEqual(len(ordered_list),
                         len(mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]))

        # All apps have the constrains satisfied
        for app in before_apps.keys():
            for before in before_apps[app]:
                # Skip non-existing
                if app in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS] and \
                        before in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
                    self.assertTrue(ordered_list.index(before) < ordered_list.index(app))

    def _compute_before_apps(self, mock_apps_metadata, before_apps):
        # Initialize structures
        for app_name in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
            before_apps[app_name] = []

        # For each app remember which apps are before
        for app_name in mock_apps_metadata[constants.APP_METADATA_PLATFORM_MANAGED_APPS]:
            app_metadata = mock_apps_metadata[constants.APP_METADATA_APPS][app_name]
            metadata_after = app_metadata.get(constants.APP_METADATA_BEHAVIOR, None)

            if metadata_after is not None:
                metadata_after = metadata_after.get(constants.APP_METADATA_EVALUATE_REAPPLY, None)
            if metadata_after is not None:
                metadata_after = metadata_after.get('after', None)
            if metadata_after is not None:
                for before_app in metadata_after:
                    # Append to apps that are before
                    before_apps[app_name].append(before_app)

    def test_reapply_order_cycle_detection_1(self):
        # Temporary copy
        mock_apps_metadata = copy.deepcopy(self.service.apps_metadata)

        yaml_file = os.path.join(os.path.dirname(__file__),
                                 "data", "metadata_app_reapply_cycle_1.yaml")
        with open(yaml_file, 'r') as f:
            metadata_collection = yaml.safe_load_all(f)

            for metadata in metadata_collection:
                kube_app.AppOperator.update_and_process_app_metadata(mock_apps_metadata,
                                                                     metadata['app_name'],
                                                                     metadata)

        ordered_list = mock_apps_metadata[constants.APP_METADATA_ORDERED_APPS]

        self.assertEqual(ordered_list, [])

    def test_reapply_order_cycle_detection_2(self):
        # Temporary copy
        mock_apps_metadata = copy.deepcopy(self.service.apps_metadata)

        yaml_file = os.path.join(os.path.dirname(__file__),
                                 "data", "metadata_app_reapply_cycle_2.yaml")
        with open(yaml_file, 'r') as f:
            metadata_collection = yaml.safe_load_all(f)

            for metadata in metadata_collection:
                kube_app.AppOperator.update_and_process_app_metadata(mock_apps_metadata,
                                                                     metadata['app_name'],
                                                                     metadata)

        ordered_list = mock_apps_metadata[constants.APP_METADATA_ORDERED_APPS]

        self.assertEqual(ordered_list, [])

    def test_reapply_order_cycle_detection_3(self):
        # Temporary copy
        mock_apps_metadata = copy.deepcopy(self.service.apps_metadata)

        yaml_file = os.path.join(os.path.dirname(__file__),
                                 "data", "metadata_app_reapply_cycle_3.yaml")
        with open(yaml_file, 'r') as f:
            metadata_collection = yaml.safe_load_all(f)

            for metadata in metadata_collection:
                kube_app.AppOperator.update_and_process_app_metadata(mock_apps_metadata,
                                                                     metadata['app_name'],
                                                                     metadata)

        ordered_list = mock_apps_metadata[constants.APP_METADATA_ORDERED_APPS]

        self.assertEqual(ordered_list, [])
