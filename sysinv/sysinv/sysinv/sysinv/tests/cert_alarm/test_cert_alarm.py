# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


"""Test class for Sysinv CertAlarm"""

from datetime import datetime
import os.path
from OpenSSL import crypto

from sysinv.common import constants
from sysinv.cert_alarm import service as cert_alarm
from sysinv.cert_alarm import utils as cert_alarm_utils
from sysinv.tests.db import base


class CertAlarmTestCase(base.DbTestCase):

    def setUp(self):
        super(CertAlarmTestCase, self).setUp()

        # Set up objects for testing
        self.service = cert_alarm.CertificateAlarmService()

    def tearDown(self):
        super(CertAlarmTestCase, self).tearDown()

    def get_data_file_path(self, file_name):
        return os.path.join(os.path.dirname(__file__), "data", file_name)

    def test_platform_certs_present(self):
        assert constants.CERT_MODE_KUBERNETES_ROOT_CA in constants.CERT_LOCATION_MAP
        assert constants.CERT_MODE_ETCD in constants.CERT_LOCATION_MAP

    def test_get_cert_expiration_date(self):
        cert_filename = self.get_data_file_path("cert.pem")
        with open(cert_filename, "r") as f:
            cert_buf = f.read()

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_buf)
        exp_date = cert_alarm_utils.get_cert_expiration_date(cert)
        days_to_expiry = exp_date - datetime.now()
        assert days_to_expiry.days > 0

    def test_expired_get_cert_expiration_date(self):
        cert_filename = self.get_data_file_path("expired-cert.pem")
        with open(cert_filename, "r") as f:
            cert_buf = f.read()

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_buf)
        exp_date = cert_alarm_utils.get_cert_expiration_date(cert)
        days_to_expiry = exp_date - datetime.now()
        assert days_to_expiry.days < 0

    def test_collect_certificate_data_from_file(self):
        cert_name = 'test_cert'

        # If file doesn't exist, should return (certname, None, None)
        non_existent_file = "file.pem"
        ret = cert_alarm_utils.collect_certificate_data_from_file(cert_name, non_existent_file)
        self.assertEqual(ret[0], "test_cert")
        self.assertEqual(ret[1], None)
        self.assertEqual(ret[2], None)

        # Run test on valid file
        cert_filename = self.get_data_file_path("cert.pem")
        ret = cert_alarm_utils.collect_certificate_data_from_file(cert_name, cert_filename)
        self.assertEqual(ret[0], "test_cert")
        days_to_expiry = ret[1] - datetime.now()
        self.assertGreater(days_to_expiry.days, 0)
        annotation_data = ret[2]
        self.assertIsNotNone(annotation_data)
        self.assertIn(constants.CERT_ALARM_ANNOTATION_ALARM, annotation_data)
        self.assertIn(constants.CERT_ALARM_ANNOTATION_ALARM_BEFORE, annotation_data)
        self.assertIn(constants.CERT_ALARM_ANNOTATION_ALARM_SEVERITY, annotation_data)
        self.assertIn(constants.CERT_ALARM_ANNOTATION_ALARM_TEXT, annotation_data)
        mode_metadata = ret[3]
        self.assertIsNotNone(mode_metadata)
        self.assertIn(cert_alarm_utils.SNAPSHOT_KEY_MODE, mode_metadata)
        self.assertIn(cert_alarm_utils.SNAPSHOT_KEY_uuid, mode_metadata)
        self.assertIn(cert_alarm_utils.SNAPSHOT_KEY_k8s_ns, mode_metadata)
        self.assertIn(cert_alarm_utils.SNAPSHOT_KEY_k8s_cert, mode_metadata)
        self.assertIn(cert_alarm_utils.SNAPSHOT_KEY_k8s_secret, mode_metadata)

    def test_process_annotation_data(self):
        # 1. Test with blank dict - should return default annotations + patch_needed True
        test_dict = dict()
        annotation_data, patch_needed = cert_alarm_utils.process_annotation_data(test_dict)
        self.assertEqual(len(annotation_data), 4)
        self.assertEqual(annotation_data[constants.CERT_ALARM_ANNOTATION_ALARM],
                        constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM)
        self.assertEqual(annotation_data[constants.CERT_ALARM_ANNOTATION_ALARM_BEFORE],
                        constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_BEFORE)
        self.assertEqual(annotation_data[constants.CERT_ALARM_ANNOTATION_ALARM_SEVERITY],
                        constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_SEVERITY)
        self.assertEqual(annotation_data[constants.CERT_ALARM_ANNOTATION_ALARM_TEXT],
                        constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_TEXT)
        self.assertEqual(patch_needed, True)

        # 2. Test with dict containing other data
        # Should return default annotations + patch_needed True + other data should remain intact
        test_dict2 = {'key1': 'val1', 'key2': 'val2'}
        annotation_data2, patch_needed2 = cert_alarm_utils.process_annotation_data(test_dict2)
        self.assertEqual(len(annotation_data2), 6)
        self.assertEqual(annotation_data2['key1'], 'val1')
        self.assertEqual(annotation_data2['key2'], 'val2')
        self.assertEqual(annotation_data2[constants.CERT_ALARM_ANNOTATION_ALARM],
                        constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM)
        self.assertEqual(annotation_data2[constants.CERT_ALARM_ANNOTATION_ALARM_BEFORE],
                        constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_BEFORE)
        self.assertEqual(annotation_data2[constants.CERT_ALARM_ANNOTATION_ALARM_SEVERITY],
                        constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_SEVERITY)
        self.assertEqual(annotation_data2[constants.CERT_ALARM_ANNOTATION_ALARM_TEXT],
                        constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_TEXT)
        self.assertEqual(patch_needed2, True)

        # 3. Test with dict containing partial expected annotation_data
        # Should return expected annotations + patch_needed True + other data should remain intact
        test_dict3 = {'key1': 'val1',
                    'key2': 'val2',
                    'key3': 'val3',
                    constants.CERT_ALARM_ANNOTATION_ALARM: 'disabled',
                    constants.CERT_ALARM_ANNOTATION_ALARM_SEVERITY:
                    constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_SEVERITY}
        annotation_data3, patch_needed3 = cert_alarm_utils.process_annotation_data(test_dict3)
        self.assertEqual(len(annotation_data3), 7)
        self.assertEqual(annotation_data3['key1'], 'val1')
        self.assertEqual(annotation_data3['key2'], 'val2')
        self.assertEqual(annotation_data3['key3'], 'val3')
        self.assertEqual(annotation_data3[constants.CERT_ALARM_ANNOTATION_ALARM],
                        'disabled')
        self.assertEqual(annotation_data3[constants.CERT_ALARM_ANNOTATION_ALARM_BEFORE],
                        constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_BEFORE)
        self.assertEqual(annotation_data3[constants.CERT_ALARM_ANNOTATION_ALARM_SEVERITY],
                        constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_SEVERITY)
        self.assertEqual(annotation_data3[constants.CERT_ALARM_ANNOTATION_ALARM_TEXT],
                        constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_TEXT)
        self.assertEqual(patch_needed3, True)

        # 4. Test with dict containing all expected annotation_data
        # Should return same annotation values + patch_needed False + other data should remain intact
        test_dict4 = {'key1': 'val1',
                    constants.CERT_ALARM_ANNOTATION_ALARM: 'disabled',
                    constants.CERT_ALARM_ANNOTATION_ALARM_BEFORE: '10d',
                    constants.CERT_ALARM_ANNOTATION_ALARM_SEVERITY: 'critical',
                    constants.CERT_ALARM_ANNOTATION_ALARM_TEXT: 'foobar'}
        annotation_data4, patch_needed4 = cert_alarm_utils.process_annotation_data(test_dict4)
        self.assertEqual(len(annotation_data4), 5)
        self.assertEqual(annotation_data4['key1'], 'val1')
        self.assertEqual(annotation_data4[constants.CERT_ALARM_ANNOTATION_ALARM],
                        'disabled')
        self.assertEqual(annotation_data4[constants.CERT_ALARM_ANNOTATION_ALARM_BEFORE],
                        '10d')
        self.assertEqual(annotation_data4[constants.CERT_ALARM_ANNOTATION_ALARM_SEVERITY],
                        'critical')
        self.assertEqual(annotation_data4[constants.CERT_ALARM_ANNOTATION_ALARM_TEXT],
                        'foobar')
        self.assertEqual(patch_needed4, False)

    def test_cert_expiry_snapshot(self):
        cert_alarm_utils.reset_cert_snapshot()
        self.assertEqual(len(cert_alarm_utils.CERT_SNAPSHOT), 0)

        certname1 = 'c1'
        certname2 = 'c2'
        now = datetime.now()
        ann_data = cert_alarm_utils.get_default_annotation_values()
        mode_metadata = cert_alarm_utils.get_default_mode_metadata()
        cert_alarm_utils.add_cert_snapshot(certname1, now, ann_data, mode_metadata)
        cert_alarm_utils.add_cert_snapshot(certname2, now, ann_data, mode_metadata)

        self.assertEqual(len(cert_alarm_utils.CERT_SNAPSHOT), 2)
        item1 = cert_alarm_utils.CERT_SNAPSHOT[certname1]
        self.assertEqual(item1[cert_alarm_utils.SNAPSHOT_KEY_EXPDATE], now)
        item2 = cert_alarm_utils.CERT_SNAPSHOT[certname2]
        self.assertEqual(item2[cert_alarm_utils.SNAPSHOT_KEY_EXPDATE], now)

        cert_alarm_utils.reset_cert_snapshot()
        self.assertEqual(len(cert_alarm_utils.CERT_SNAPSHOT), 0)

    def test_get_default_annotation_values(self):
        data = cert_alarm_utils.get_default_annotation_values()
        self.assertIn(constants.CERT_ALARM_ANNOTATION_ALARM, data)
        self.assertIn(constants.CERT_ALARM_ANNOTATION_ALARM_BEFORE, data)
        self.assertIn(constants.CERT_ALARM_ANNOTATION_ALARM_SEVERITY, data)
        self.assertIn(constants.CERT_ALARM_ANNOTATION_ALARM_TEXT, data)

        self.assertEqual(data[constants.CERT_ALARM_ANNOTATION_ALARM],
                        constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM)
        self.assertEqual(data[constants.CERT_ALARM_ANNOTATION_ALARM_BEFORE],
                        constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_BEFORE)
        self.assertEqual(data[constants.CERT_ALARM_ANNOTATION_ALARM_SEVERITY],
                        constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_SEVERITY)
        self.assertEqual(data[constants.CERT_ALARM_ANNOTATION_ALARM_TEXT],
                        constants.CERT_ALARM_DEFAULT_ANNOTATION_ALARM_TEXT)

    def test_get_default_mode_metadata(self):
        data = cert_alarm_utils.get_default_mode_metadata()
        self.assertIn(cert_alarm_utils.SNAPSHOT_KEY_MODE, data)
        self.assertIn(cert_alarm_utils.SNAPSHOT_KEY_uuid, data)
        self.assertIn(cert_alarm_utils.SNAPSHOT_KEY_k8s_ns, data)
        self.assertIn(cert_alarm_utils.SNAPSHOT_KEY_k8s_cert, data)
        self.assertIn(cert_alarm_utils.SNAPSHOT_KEY_k8s_secret, data)

        self.assertEqual(data[cert_alarm_utils.SNAPSHOT_KEY_MODE], "")
        self.assertEqual(data[cert_alarm_utils.SNAPSHOT_KEY_uuid], "")
        self.assertEqual(data[cert_alarm_utils.SNAPSHOT_KEY_k8s_ns], "")
        self.assertEqual(data[cert_alarm_utils.SNAPSHOT_KEY_k8s_cert], "")
        self.assertEqual(data[cert_alarm_utils.SNAPSHOT_KEY_k8s_secret], "")
