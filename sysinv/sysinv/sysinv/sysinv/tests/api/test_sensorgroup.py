import mock
from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils
from sysinv.api.controllers.v1 import hwmon_api
from sysinv.api.controllers.v1 import sensorgroup
from sysinv.common import constants


class sensorgroupTestCase(base.FunctionalTest):

    def setUp(self):
        super(sensorgroupTestCase, self).setUp()
        self.system = dbutils.create_test_isystem()
        self.load = dbutils.create_test_load()
        self.host = dbutils.create_test_ihost(forisystemid=self.system.id)

    def assertDeleted(self, fullPath):
        self.get_json(fullPath, expect_errors=True)  # Make sure this line raises an error

    @mock.patch.object(hwmon_api, 'sensorgroup_modify', return_value={'status': 'pass'})
    def test_propagated_to_sensor(self, mock_sgmodify):

        # Create sensorgroup
        sensorgroupVals = {
            'host_uuid': self.host['uuid'],
            'datatype': 'analog',
            'sensortype': 'testsensortype',
            'sensorgroupname': 'defaultSensorGroupName',
        }
        sensorgroup = self.post_json('/isensorgroups', sensorgroupVals)

        # Test post_json worked properly
        self.assertEqual('defaultSensorGroupName',  # Expected
                         self.get_json('/isensorgroups/%s/' % sensorgroup.json['uuid'])['sensorgroupname'])  # Result

        # Create sensor
        sensorVals = {
            'host_uuid': self.host['uuid'],
            'datatype': 'analog',
            'sensortype': 'testsensortype',
            'sensorname': 'defaultSensorName',
        }
        sensor = self.post_json('/isensors', sensorVals, headers={'User-Agent': 'hwmon'})
        self.patch_dict_json('/isensors/%s/' % sensor.json['uuid'],
                            headers={'User-Agent': 'hwmon'},
                            sensorgroup_uuid=sensorgroup.json['uuid'])

        # Assert sensorgroup/sensor created properly in DB
        self.assertEqual('defaultSensorGroupName',  # Expected
                         self.get_json('/isensorgroups/%s/' % sensorgroup.json['uuid'])['sensorgroupname'])  # Result
        self.assertEqual('defaultSensorName',  # Expected
                         self.get_json('/isensors/%s/' % sensor.json['uuid'])['sensorname'])  # Result
        self.assertEqual(self.get_json('/isensors/%s/' % sensor.json['uuid'])['sensorgroup_uuid'],
                         self.get_json('/isensorgroups/%s/' % sensorgroup.json['uuid'])['uuid'])

        # Set values in sensorgroup
        self.patch_dict_json('/isensorgroups/%s/' % sensorgroup.json['uuid'],
                             headers={'User-Agent': 'hwmon'},
                             audit_interval_group=42,
                             actions_minor_group='action minor',
                             actions_major_group='action major',
                             actions_critical_group='action critical',
                             suppress='False',)

        # Assert values got set properly in sensorgroup
        self.assertEqual(42,  # Expected
                         self.get_json('/isensorgroups/%s/' % sensorgroup.json['uuid'])['audit_interval_group'])  # Result
        self.assertEqual('action minor',  # Expected
                         self.get_json('/isensorgroups/%s/' % sensorgroup.json['uuid'])['actions_minor_group'])  # Result
        self.assertEqual('action major',  # Expected
                         self.get_json('/isensorgroups/%s/' % sensorgroup.json['uuid'])['actions_major_group'])  # Result
        self.assertEqual('action critical',  # Expected
                         self.get_json('/isensorgroups/%s/' % sensorgroup.json['uuid'])['actions_critical_group'])  # Result
        self.assertEqual('False',  # Expected
                         self.get_json('/isensorgroups/%s/' % sensorgroup.json['uuid'])['suppress'])  # Result

        # Assert values got propagated to sensor
        self.assertEqual(42,  # Expected
                         self.get_json('/isensors/%s/' % sensor.json['uuid'])['audit_interval'])  # Result
        self.assertEqual('action minor',  # Expected
                         self.get_json('/isensors/%s/' % sensor.json['uuid'])['actions_minor'])  # Result
        self.assertEqual('action major',  # Expected
                         self.get_json('/isensors/%s/' % sensor.json['uuid'])['actions_major'])  # Result
        self.assertEqual('action critical',  # Expected
                         self.get_json('/isensors/%s/' % sensor.json['uuid'])['actions_critical'])  # Result
        self.assertEqual('False',  # Expected
                         self.get_json('/isensors/%s/' % sensor.json['uuid'])['suppress'])  # Result

        # delete sensorgroup and assert sensorgroup/sensor got deleted
        self.delete('/isensorgroups/%s/' % sensorgroup.json['uuid'])
        self.delete('/isensors/%s/' % sensor.json['uuid'])
        self.assertDeleted('/isensorgroups/%s/' % sensorgroup.json['uuid'])
        self.assertDeleted('/isensors/%s/' % sensor.json['uuid'])

    @mock.patch.object(hwmon_api, 'sensorgroup_modify', return_value={'status': 'pass'})
    def test_propagated_to_multiple_sensors(self, mock_sgmodify):

        # Create sensorgroup in DB
        sensorgroupVals = {
            'host_uuid': self.host['uuid'],
            'datatype': 'analog',
            'sensortype': 'testsensortype',
            'sensorgroupname': 'testsensorgroupname',
        }
        sensorgroup = self.post_json('/isensorgroups', sensorgroupVals)

        # Test post_json worked properly
        self.assertEqual('testsensorgroupname',  # Expected
                         self.get_json('/isensorgroups/%s/' % sensorgroup.json['uuid'])['sensorgroupname'])  # Result

        # Create sensors
        numOfSensors = 10
        sensor = []
        sensorVals = {
            'host_uuid': self.host['uuid'],
            'datatype': 'analog',
            'sensortype': 'testsensortype',
            'sensorname': 'defaultSensorName',
        }
        for i in xrange(numOfSensors):
            sensor.append(self.post_json('/isensors', sensorVals, headers={'User-Agent': 'hwmon'}))
            self.patch_dict_json('/isensors/%s/' % sensor[i].json['uuid'],
                                 headers={'User-Agent': 'hwmon'},
                                 sensorgroup_uuid=sensorgroup.json['uuid'])

        # Assert sensors created properly in DB
        for i in xrange(numOfSensors):
            self.assertEqual('defaultSensorName',  # Expected
                             self.get_json('/isensors/%s/' % sensor[i].json['uuid'])['sensorname'])  # Result
            self.assertEqual(sensorgroup.json['uuid'],  # Expected
                             self.get_json('/isensors/%s/' % sensor[i].json['uuid'])['sensorgroup_uuid'])  # Result

        # Set values in sensorgroup, then propagate to sensors
        self.patch_dict_json('/isensorgroups/%s/' % (sensorgroup.json['uuid']),
                             headers={'User-Agent': 'hwmon'},
                             audit_interval_group=42,
                             actions_minor_group='action minor',
                             actions_major_group='action major',
                             actions_critical_group='action critical',
                             suppress='False', )

        # Assert values got set properly in sensorgroup
        self.assertEqual(42,  # Expected
                         self.get_json('/isensorgroups/%s/' % sensorgroup.json['uuid'])['audit_interval_group'])  # Result
        self.assertEqual('action minor',  # Expected
                         self.get_json('/isensorgroups/%s/' % sensorgroup.json['uuid'])['actions_minor_group'])  # Result
        self.assertEqual('action major',  # Expected
                         self.get_json('/isensorgroups/%s/' % sensorgroup.json['uuid'])['actions_major_group'])  # Result
        self.assertEqual('action critical',  # Expected
                         self.get_json('/isensorgroups/%s/' % sensorgroup.json['uuid'])['actions_critical_group'])  # Result
        self.assertEqual('False',  # Expected
                         self.get_json('/isensorgroups/%s/' % sensorgroup.json['uuid'])['suppress'])  # Result

        # Assert values got propagated to sensor
        for i in xrange(numOfSensors):
            self.assertEqual(42,  # Expected
                             self.get_json('/isensors/%s/' % sensor[i].json['uuid'])['audit_interval'])  # Result
            self.assertEqual('action minor',  # Expected
                             self.get_json('/isensors/%s/' % sensor[i].json['uuid'])['actions_minor'])  # Result
            self.assertEqual('action major',  # Expected
                             self.get_json('/isensors/%s/' % sensor[i].json['uuid'])['actions_major'])  # Result
            self.assertEqual('action critical',  # Expected
                             self.get_json('/isensors/%s/' % sensor[i].json['uuid'])['actions_critical'])  # Result
            self.assertEqual('False',  # Expected
                             self.get_json('/isensors/%s/' % sensor[i].json['uuid'])['suppress'])  # Result

        # Delete sensorgroup and sensors
        self.delete('/isensorgroups/%s/' % sensorgroup.json['uuid'])
        for i in xrange(numOfSensors):
            self.delete('/isensors/%s/' % sensor[i].json['uuid'])

        # Assert deletion of sensorgroup and sensors
        self.assertDeleted('/isensorgroups/%s/' % sensorgroup.json['uuid'])
        for i in xrange(numOfSensors):
            self.assertDeleted('/isensors/%s/' % sensor[i].json['uuid'])

    def test_sensorgroup_post(self):
        sensorgroupVals = {
            'host_uuid': self.host['uuid'],
            'datatype': 'analog',
            'sensortype': 'testsensortype',
            'sensorgroupname': 'testsensorgroupname',
        }
        response = self.post_json('/isensorgroups', sensorgroupVals)
        self.assertEqual('testsensorgroupname',  # Expected
                         self.get_json('/isensorgroups/%s/' % response.json['uuid'])['sensorgroupname'])  # Result

        self.delete('/isensorgroups/%s/' % response.json['uuid'])
        self.assertDeleted('/isensorgroups/%s/' % response.json['uuid'])

    def test_sensor_post(self):
        sensorVals = {
            'host_uuid': self.host['uuid'],
            'datatype': 'analog',
            'sensortype': 'testsensortype',
            'sensorname': 'testsensorname',
        }
        response = self.post_json('/isensors', sensorVals)
        self.assertEqual('testsensorname',  # Expected
                         self.get_json('/isensors/%s/' % response.json['uuid'])['sensorname'])  # Result
        self.delete('/isensors/%s/' % response.json['uuid'])
        self.assertDeleted('/isensors/%s/' % response.json['uuid'])

    @mock.patch.object(sensorgroup.SensorGroupController, '_get_host_uuid')
    @mock.patch.object(sensorgroup.hwmon_api, 'sensorgroup_relearn', return_value={'status': 'pass'})
    def test_sensorgroup_relearn(self, mock_hwmon_relearn, mock_get_host_uuid):
        mock_get_host_uuid.return_value = self.host['uuid']
        request_relearn = {
            'host_uuid': self.host['uuid'],
        }
        response = self.post_json('/isensorgroups/relearn', request_relearn)
        mock_hwmon_relearn.assert_called_once()
