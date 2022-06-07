# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock
import os

from sysinv.helm import kustomize_generic
from sysinv.tests import base as test_base


FLUXCD_TEST_MANIFEST = os.path.join(
    os.path.dirname(__file__),
    'fluxcd-test-manifest'
)


class TestGenericFluxCDKustomizeOperator(test_base.TestCase):

    def setUp(self):
        super(TestGenericFluxCDKustomizeOperator, self).setUp()
        self.instance = kustomize_generic.GenericFluxCDKustomizeOperator()
        self.maxDiff = None

    def test_load_manifest_fqpn_doesnt_exist(self):
        self.assertIsNone(self.instance.load('fake-folder'))
        # check log

    @mock.patch('sysinv.helm.kustomize_base.dbapi')
    def test_load_fluxcd_test_manifest(self, _):
        self.instance.load(FLUXCD_TEST_MANIFEST)

        self.assertDictEqual(
            {
                'release1': {
                    'name': 'release1',
                    'namespace': 'test-app',
                    'resource': 'release1',
                },
                'release2': {
                    'name': 'release2',
                    'namespace': 'test-rls-kust',
                    'resource': 'release2',
                },
                'release-3': {
                    'name': 'release-3',
                    'namespace': 'test-rls',
                    'resource': 'release3',
                },
            },
            self.instance.helmrelease_resource_map
        )

    def tearDown(self):
        super(TestGenericFluxCDKustomizeOperator, self).tearDown()
        try:
            if self.instance.kustomization_fqpn and os.path.exists(self.instance.original_kustomization_fqpn):
                os.remove(self.instance.kustomization_fqpn)
                os.rename(
                    self.instance.original_kustomization_fqpn,
                    self.instance.kustomization_fqpn
                )
            if self.instance.helmrepo_path and os.path.exists(self.instance.original_helmrepo_fqpn):
                os.remove(self.instance.helmrepo_path)
                os.rename(
                    self.instance.original_helmrepo_fqpn,
                    self.instance.helmrepo_path
                )
            # delete release-cleanup
        except Exception:
            raise
