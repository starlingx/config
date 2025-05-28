#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import testtools
import uuid

from cgtsclient.tests import utils
import cgtsclient.v1.label

CONTROLLER_0 = {
    'uuid': str(uuid.uuid4()),
    'hostname': 'controller-0',
    'id': '0',
}

LABEL_1 = {
    'uuid': str(uuid.uuid4()),
    'host_uuid': CONTROLLER_0['uuid'],
    'label_key': 'key1',
    'label_value': 'value1',
}

LABEL_2 = {
    'uuid': str(uuid.uuid4()),
    'host_uuid': CONTROLLER_0['uuid'],
    'label_key': 'key2',
    'label_value': 'value2',
}

LABEL_3 = {
    'uuid': str(uuid.uuid4()),
    'host_uuid': CONTROLLER_0['uuid'],
    'label_key': 'key3',
    'label_value': 'value3',
}

LABEL_4 = {
    'uuid': str(uuid.uuid4()),
    'host_uuid': CONTROLLER_0['uuid'],
    'label_key': 'key4',
    'label_value': 'value4',
}

LABELS = {
    'labels': [LABEL_1, LABEL_2]
}

NEW_LABELS = {
    'labels': [LABEL_3, LABEL_4]
}

OVERWRITE_PARAMETER = "overwrite=" + str(True)

fixtures_default = {
    '/v1/labels':
    {
        'GET': (
            {},
            LABELS,
        ),
    },
    f'/v1/labels/{LABEL_1["uuid"]}':
    {
        'GET': (
            {},
            LABEL_1,
        ),
        'DELETE': (
            {},
            None,
        )
    },
    f'/v1/labels/{LABEL_2["uuid"]}':
    {
        'GET': (
            {},
            LABEL_2,
        ),
        'DELETE': (
            {},
            None,
        )
    },
    f'/v1/labels/{LABEL_3["uuid"]}':
    {
        'GET': (
            {},
            LABEL_3,
        ),
        'DELETE': (
            {},
            None,
        )
    },
    f'/v1/labels/{LABEL_4["uuid"]}':
    {
        'GET': (
            {},
            LABEL_4,
        ),
        'DELETE': (
            {},
            None,
        )
    },
    f'/v1/ihosts/{CONTROLLER_0["uuid"]}/labels':
    {
        'GET': (
            {},
            LABELS
        ),
    },
    f'/v1/labels/{CONTROLLER_0["uuid"]}?{OVERWRITE_PARAMETER}':
    {
        'POST': (
            {},
            NEW_LABELS,
        )
    }

}


class KubernetesLabelManagerTest(testtools.TestCase):

    def setUp(self):
        super(KubernetesLabelManagerTest, self).setUp()
        self.api = utils.FakeAPI(fixtures_default)
        self.mgr = \
            cgtsclient.v1.label.KubernetesLabelManager(self.api)

    def test_host_label_list(self):
        host_uuid = CONTROLLER_0['uuid']
        labels = self.mgr.list(host_uuid)
        expect = [
            # (method, url, headers, body )
            (
                'GET',
                f'/v1/ihosts/{host_uuid}/labels',
                {},
                None
            )
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(len(labels), 2)

    def test_host_label_get(self):
        label_id = LABEL_1['uuid']
        label = self.mgr.get(label_id)
        expect = [
            # (method, url, headers, body )
            (
                'GET',
                f'/v1/labels/{label_id}',
                {},
                None,
            )
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertTrue(
            isinstance(label,
                       cgtsclient.v1.label.KubernetesLabel))

        self.assertEqual(label.uuid, LABEL_1['uuid'])
        self.assertEqual(label.host_uuid, LABEL_1['host_uuid'])
        self.assertEqual(label.label_key, LABEL_1['label_key'])
        self.assertEqual(label.label_value, LABEL_1['label_value'])

    def test_host_label_assign(self):
        keyvaluepairs = {
            LABEL_3['label_key']: LABEL_3['label_value'],
            LABEL_4['label_key']: LABEL_4['label_value'],
        }
        host_uuid = CONTROLLER_0['uuid']
        assigned_labels = self.mgr.assign(host_uuid,
                                          keyvaluepairs,
                                          [OVERWRITE_PARAMETER])
        expect = [
            # (method, url, headers, body )
            (
                'POST',
                f'/v1/labels/{host_uuid}?{OVERWRITE_PARAMETER}',
                {},
                keyvaluepairs,
            )
        ]
        self.assertEqual(self.api.calls, expect)
        for label in assigned_labels:
            self.assertTrue(
                isinstance(label, cgtsclient.v1.label.KubernetesLabel)
            )

        expected_labels = [
            cgtsclient.v1.label.KubernetesLabel(None, LABEL_3, True),
            cgtsclient.v1.label.KubernetesLabel(None, LABEL_4, True),
        ]

        self.assertEqual(expected_labels, assigned_labels)

    def test_host_label_remove(self):
        label_uuid = LABEL_4['uuid']
        label = self.mgr.remove(label_uuid)
        expect = [
            # (method, url, headers, body )
            (
                'DELETE',
                f'/v1/labels/{label_uuid}',
                {},
                None,
            )
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertTrue(label is None)
