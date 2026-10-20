#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Tests for the kube_app_bundle database queries."""

from sysinv.common import constants
from sysinv.common import exception
from sysinv.db import api as dbapi
from sysinv.tests.db import base
from sysinv.tests.db import utils


class KubeAppBundleTestCase(base.DbTestCase):
    """Kubernetes application bundle queries.

    A maximum supported Kubernetes version declared as major.minor covers
    every patch release of that minor series.
    See https://bugs.launchpad.net/starlingx/+bug/2165067
    """

    def setUp(self):
        super(KubeAppBundleTestCase, self).setUp()
        self.dbapi = dbapi.get_instance()

    def _create_bundle(self, **kw):
        return utils.create_test_kube_app_bundle(**kw)

    def test_get_by_version_regex_max_version_without_patch(self):
        self._create_bundle(name='app-a', version='1.0-1',
                            file_path='/tmp/app-a-1.0-1.tgz',
                            k8s_maximum_version='1.29')

        bundle = self.dbapi.kube_app_bundle_get_by_version_regex(
            'app-a', '1.0-1', 'v1.29.2')

        self.assertEqual('1.0-1', bundle.version)

    def test_update_by_file_path_refreshes_legacy_maximum(self):
        file_path = '/tmp/app-legacy-1.0-1.tgz'
        self._create_bundle(name='app-legacy', version='1.0-1',
                            file_path=file_path,
                            k8s_maximum_version='1.29.0')

        bundle = self.dbapi.kube_app_bundle_update_by_file_path(
            file_path, {'k8s_maximum_version': '1.29'})

        self.assertEqual('1.29', bundle.k8s_maximum_version)

    def test_get_by_version_regex_beyond_max_version(self):
        self._create_bundle(name='app-b', version='1.0-1',
                            file_path='/tmp/app-b-1.0-1.tgz',
                            k8s_maximum_version='1.29')

        self.assertRaises(exception.KubeAppBundleNotFound,
                          self.dbapi.kube_app_bundle_get_by_version_regex,
                          'app-b', '1.0-1', 'v1.30.0')

    def test_get_by_version_regex_without_max_version(self):
        self._create_bundle(name='app-c', version='1.0-1',
                            file_path='/tmp/app-c-1.0-1.tgz',
                            k8s_maximum_version=None)

        bundle = self.dbapi.kube_app_bundle_get_by_version_regex(
            'app-c', '1.0-1', 'v1.42.0')

        self.assertEqual('1.0-1', bundle.version)

    def test_is_k8s_compatible_max_version_without_patch(self):
        self._create_bundle(name='app-d', version='1.0-1',
                            file_path='/tmp/app-d-1.0-1.tgz',
                            k8s_maximum_version='1.29')

        self.assertTrue(self.dbapi.kube_app_bundle_is_k8s_compatible(
            'app-d', constants.APP_METADATA_TIMING_PRE, '1.29.2'))
        self.assertTrue(self.dbapi.kube_app_bundle_is_k8s_compatible(
            'app-d', constants.APP_METADATA_TIMING_PRE, '1.29.2',
            current_k8s_version='1.29.1'))
        self.assertFalse(self.dbapi.kube_app_bundle_is_k8s_compatible(
            'app-d', constants.APP_METADATA_TIMING_PRE, '1.30.0'))

    def test_is_k8s_compatible_current_version_beyond_max_version(self):
        self._create_bundle(name='app-e', version='1.0-1',
                            file_path='/tmp/app-e-1.0-1.tgz',
                            k8s_maximum_version='1.29')

        self.assertFalse(self.dbapi.kube_app_bundle_is_k8s_compatible(
            'app-e', constants.APP_METADATA_TIMING_PRE, '1.29.2',
            current_k8s_version='1.30.0'))

    def test_max_k8s_compatible_by_name_without_patch(self):
        self._create_bundle(name='app-f', version='1.0-1',
                            file_path='/tmp/app-f-1.0-1.tgz',
                            k8s_timing=constants.APP_METADATA_TIMING_POST,
                            k8s_maximum_version='1.29')

        result = self.dbapi.kube_app_bundle_max_k8s_compatible_by_name(
            'app-f', '1.24.0', '1.30.0')

        self.assertEqual('1.29', result)

    def test_max_k8s_compatible_by_name_picks_highest_bound(self):
        # a plain string comparison would pick 1.29.2 as the highest bound
        self._create_bundle(name='app-g', version='1.0-1',
                            file_path='/tmp/app-g-1.0-1.tgz',
                            k8s_timing=constants.APP_METADATA_TIMING_POST,
                            k8s_maximum_version='1.29.2')
        self._create_bundle(name='app-g', version='2.0-1',
                            file_path='/tmp/app-g-2.0-1.tgz',
                            k8s_timing=constants.APP_METADATA_TIMING_POST,
                            k8s_maximum_version='1.29.10')

        result = self.dbapi.kube_app_bundle_max_k8s_compatible_by_name(
            'app-g', '1.24.0', '1.30.0')

        self.assertEqual('1.29.10', result)

    def test_max_k8s_compatible_by_name_beyond_target(self):
        self._create_bundle(name='app-h', version='1.0-1',
                            file_path='/tmp/app-h-1.0-1.tgz',
                            k8s_timing=constants.APP_METADATA_TIMING_POST,
                            k8s_maximum_version='1.31')

        result = self.dbapi.kube_app_bundle_max_k8s_compatible_by_name(
            'app-h', '1.24.0', '1.30.0')

        self.assertIsNone(result)
