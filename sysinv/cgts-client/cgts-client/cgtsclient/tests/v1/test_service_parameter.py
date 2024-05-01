#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy
import testtools
import uuid

from cgtsclient.tests import utils
import cgtsclient.v1.service_parameter

CREATE_PARAMETER_1 = {
    'service': 'platform',
    'section': 'config',
    'parameters': {
        'sysinv_api_workers': 10
    },
    'personality': None,
    'resource': None,
}

PARAMETER_1 = {
    'uuid': str(uuid.uuid4()),
    'service': 'platform',
    'section': 'config',
    'name': 'sysinv_api_workers',
    'value': 10,
    'personality': None,
    'resource': None,
}

CREATE_PARAMETER_2 = {
    'service': 'docker',
    'section': 'docker-registry',
    'parameters': {
        'url': 'oldregistry:5000/starlingx/docker.io'
    },
    'personality': None,
    'resource': None,
}

PARAMETER_2 = {
    'uuid': str(uuid.uuid4()),
    'service': 'docker',
    'section': 'docker-registry',
    'name': 'url',
    'value': 'oldregistry:5000/starlingx/docker.io',
    'personality': None,
    'resource': None,
}

UPDATED_PARAMETER_1 = copy.deepcopy(PARAMETER_1)
NEW_VALUE_PARAMETER_1 = 15
UPDATED_PARAMETER_1['value'] = NEW_VALUE_PARAMETER_1

UPDATED_PARAMETER_2 = copy.deepcopy(PARAMETER_2)
NEW_VALUE_PARAMETER_2 = 'newregistry:5000/starlingx/docker.io'
UPDATED_PARAMETER_2['value'] = NEW_VALUE_PARAMETER_2

PARAMETERS = {
    "parameters": [PARAMETER_1, PARAMETER_2]
}

fixtures_default = {
    '/v1/service_parameter':
    {
        'GET': (
            {},
            PARAMETERS,
        ),
        'POST': (
            {},
            PARAMETER_1,
        ),
    },
    '/v1/service_parameter/%s' % PARAMETER_1['uuid']:
    {
        'GET': (
            {},
            PARAMETER_1,
        ),
        'DELETE': (
            {},
            None,
        ),
        'PATCH': (
            {},
            UPDATED_PARAMETER_1,
        ),
    },
    '/v1/service_parameter/%s' % PARAMETER_2['uuid']:
    {
        'GET': (
            {},
            PARAMETER_2,
        ),
        'DELETE': (
            {},
            None,
        ),
        'PATCH': (
            {},
            UPDATED_PARAMETER_2,
        ),
    },
    '/v1/service_parameter/apply':
    {
        'POST': (
            {},
            None,
        )
    },
}


class ServiceParameterManagerTest(testtools.TestCase):

    def setUp(self):
        super(ServiceParameterManagerTest, self).setUp()
        self.api = utils.FakeAPI(fixtures_default)
        self.mgr = \
            cgtsclient.v1.service_parameter.ServiceParameterManager(self.api)

    def test_service_parameter_list(self):
        parameters = self.mgr.list()
        expect = [
            # (method , url , headers , body )
            ('GET', '/v1/service_parameter', {}, None)
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(len(parameters), 2)

    def test_service_parameter_get(self):
        parameter_1 = self.mgr.get(PARAMETER_1['uuid'])
        expect = [
            ('GET',
             '/v1/service_parameter/%s' % PARAMETER_1['uuid'],
             {},
             None),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertTrue(
            isinstance(parameter_1,
                       cgtsclient.v1.service_parameter.ServiceParameter))

        self.assertEqual(parameter_1.uuid, PARAMETER_1['uuid'])
        self.assertEqual(parameter_1.service, PARAMETER_1['service'])
        self.assertEqual(parameter_1.section, PARAMETER_1['section'])
        self.assertEqual(parameter_1.name, PARAMETER_1['name'])
        self.assertEqual(parameter_1.value, PARAMETER_1['value'])

        parameter_2 = self.mgr.get(UPDATED_PARAMETER_2['uuid'])
        expect = [
            ('GET',
             '/v1/service_parameter/%s' % PARAMETER_1['uuid'],
             {},
             None),
            ('GET',
             '/v1/service_parameter/%s' % PARAMETER_2['uuid'],
             {},
             None)
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertTrue(
            isinstance(parameter_2,
                       cgtsclient.v1.service_parameter.ServiceParameter))

        self.assertEqual(parameter_2.uuid, PARAMETER_2['uuid'])
        self.assertEqual(parameter_2.service, PARAMETER_2['service'])
        self.assertEqual(parameter_2.section, PARAMETER_2['section'])
        self.assertEqual(parameter_2.name, PARAMETER_2['name'])
        self.assertEqual(parameter_2.value, PARAMETER_2['value'])

    def test_service_parameter_create(self):
        parameter_1 = self.mgr.create(
            PARAMETER_1['service'],
            PARAMETER_1['section'],
            PARAMETER_1['personality'],
            PARAMETER_1['resource'],
            {
                PARAMETER_1['name']: PARAMETER_1['value'],
            }
        )

        self.api.fixtures['/v1/service_parameter']['POST'] = (
            {},
            PARAMETER_2,
        )
        parameter_2 = self.mgr.create(
            PARAMETER_2['service'],
            PARAMETER_2['section'],
            PARAMETER_2['personality'],
            PARAMETER_2['resource'],
            {
                PARAMETER_2['name']: PARAMETER_2['value'],
            }
        )

        expect = [
            ('POST',
             '/v1/service_parameter',
             {},
             CREATE_PARAMETER_1),
            ('POST',
             '/v1/service_parameter',
             {},
             CREATE_PARAMETER_2),
        ]

        self.assertEqual(self.api.calls, expect)

        isinstance(
            parameter_1,
            cgtsclient.v1.service_parameter.ServiceParameter)
        isinstance(
            parameter_2,
            cgtsclient.v1.service_parameter.ServiceParameter)

        self.assertEqual(parameter_1.uuid, PARAMETER_1['uuid'])
        self.assertEqual(parameter_1.service, PARAMETER_1['service'])
        self.assertEqual(parameter_1.section, PARAMETER_1['section'])
        self.assertEqual(parameter_1.name, PARAMETER_1['name'])
        self.assertEqual(parameter_1.value, PARAMETER_1['value'])

        self.assertEqual(parameter_2.uuid, PARAMETER_2['uuid'])
        self.assertEqual(parameter_2.service, PARAMETER_2['service'])
        self.assertEqual(parameter_2.section, PARAMETER_2['section'])
        self.assertEqual(parameter_2.name, PARAMETER_2['name'])
        self.assertEqual(parameter_2.value, PARAMETER_2['value'])

    def test_service_parameter_delete(self):
        parameter = self.mgr.delete(PARAMETER_1['uuid'])
        expect = [
            ('DELETE',
             '/v1/service_parameter/%s' % PARAMETER_1['uuid'],
             {},
             None),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertTrue(parameter is None)

    def test_service_parameter_apply(self):
        _, body = self.mgr.apply(
            PARAMETER_1['service'],
            PARAMETER_1['section'],
        )
        expect = [
            (
                'POST',
                '/v1/service_parameter/apply',
                {},
                {
                    "service": PARAMETER_1['service'],
                    "section": PARAMETER_1['section'],
                }
            ),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertTrue(body is None)

    def test_service_parameter_update(self):
        patch_1 = [
            {
                'op': 'replace',
                'path': '/name',
                'value': PARAMETER_1['name'],
            },
            {
                'op': 'replace',
                'path': '/value',
                'value': PARAMETER_1['value']
            },
        ]
        patch_2 = [
            {
                'op': 'replace',
                'path': '/name',
                'value': PARAMETER_2['name'],
            },
            {
                'op': 'replace',
                'path': '/value',
                'value': PARAMETER_2['value']
            },
        ]
        parameter_1 = self.mgr.update(PARAMETER_1['uuid'], patch_1)
        parameter_2 = self.mgr.update(PARAMETER_2['uuid'], patch_2)
        expect = [
            ('PATCH',
             '/v1/service_parameter/%s' % PARAMETER_1['uuid'],
             {},
             patch_1),
            ('PATCH',
             '/v1/service_parameter/%s' % PARAMETER_2['uuid'],
             {},
             patch_2),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(parameter_1.value, NEW_VALUE_PARAMETER_1)
        self.assertEqual(parameter_2.value, NEW_VALUE_PARAMETER_2)
