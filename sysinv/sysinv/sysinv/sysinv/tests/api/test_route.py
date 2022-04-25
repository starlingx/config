#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API route methods.
"""

from six.moves import http_client

from oslo_utils import uuidutils
from sysinv.common import constants
from sysinv.db import api as db_api

from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


# route updates are disallowed prior to controller-0 upgrade or during abort
DISALLOWED_UPGRADE_STATES = [
    constants.UPGRADE_STARTING,
    constants.UPGRADE_STARTED,
    constants.UPGRADE_DATA_MIGRATION,
    constants.UPGRADE_DATA_MIGRATION_COMPLETE,
    constants.UPGRADE_DATA_MIGRATION_FAILED,

    constants.UPGRADE_ABORTING,
    constants.UPGRADE_ABORT_COMPLETING,
    constants.UPGRADE_ABORTING_ROLLBACK
]

# route updates are allowed after controller-0 is upgraded
ALLOWED_UPGRADE_STATES = [
    s for s in constants.PLATFORM_UPGRADE_STATES
    if s not in DISALLOWED_UPGRADE_STATES]


class RouteTestCase(base.FunctionalTest, dbbase.BaseHostTestCase):
    # can perform API operations on this object at a sublevel of host
    HOST_PREFIX = '/ihosts'

    # can perform API operations on this object at a sublevel of interface
    IFACE_PREFIX = '/iinterfaces'

    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/routes'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'routes'

    # COMMON_FIELD is a field that is known to exist for inputs and outputs
    COMMON_FIELD = 'network'

    # expected_api_fields are attributes that should be populated by
    # an API query
    expected_api_fields = ['uuid',
                           'interface_uuid',
                           'ifname',
                           'network',
                           'prefix',
                           'gateway',
                           'metric',
                           'forihostid'
                           ]

    # hidden_api_fields are attributes that should not be populated by
    # an API query
    hidden_api_fields = ['id']

    def setUp(self):
        super(RouteTestCase, self).setUp()
        self.host = self._create_test_host(constants.CONTROLLER)
        self.interface = dbutils.create_test_interface(
            ifname="test0",
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=self.host.id,
            ihost_uuid=self.host.uuid)

        self.address = dbutils.create_test_address(
            interface_id=self.interface.id,
            name="enptest01",
            family=self.system_controller_subnet.version,
            address=str(self.system_controller_subnet[25]),
            prefix=self.system_controller_subnet.prefixlen)

    def get_single_url(self, uuid):
        return '%s/%s' % (self.API_PREFIX, uuid)

    def get_host_scoped_url(self, host_uuid):
        return '%s/%s%s' % (self.HOST_PREFIX, host_uuid, self.API_PREFIX)

    def get_iface_scoped_url(self, interface_uuid):
        return '%s/%s%s' % (self.IFACE_PREFIX, interface_uuid, self.API_PREFIX)

    def assert_fields(self, api_object):
        # check the uuid is a uuid
        assert(uuidutils.is_uuid_like(api_object['uuid']))

        # Verify that expected attributes are returned
        for field in self.expected_api_fields:
            self.assertIn(field, api_object)

        # Verify that hidden attributes are not returned
        for field in self.hidden_api_fields:
            self.assertNotIn(field, api_object)

    def get_post_object(self, interface, gateway, family=4, network='10.10.10.0',
                        prefix=24):
        route_db = dbutils.get_test_route(
            uuid=interface.uuid,
            gateway=gateway,
            family=family,
            network=network,
            prefix=prefix,
        )

        # interface_uuid in api corresponds to uuid in db
        route_db['interface_uuid'] = route_db.pop('uuid')

        # the following fields are not expected by api on POST
        del route_db['id']
        del route_db['interface_id']
        del route_db['family']

        return route_db

    def _test_create_route_success(self, interface, family, network, prefix, gateway):
        # Test creation of object
        route_db = self.get_post_object(
            interface, family=family, network=network, prefix=prefix, gateway=gateway)
        response = self.post_json(self.API_PREFIX,
                                  route_db,
                                  headers=self.API_HEADERS)

        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        # Check that an expected field matches.
        self.assertEqual(response.json[self.COMMON_FIELD],
                         route_db[self.COMMON_FIELD])

    def _test_create_route_fail(
            self, interface, family, network, prefix,
            gateway, status_code, error_message):
        # Test creation of object
        route_db = self.get_post_object(
            interface, gateway, family=family, network=network, prefix=prefix)
        response = self.post_json(self.API_PREFIX,
                                  route_db,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, status_code)
        self.assertIn(error_message, response.json['error_message'])

    def _create_platform_upgrade(self):
        self.upgrade = dbutils.create_test_upgrade(
            state=constants.UPGRADE_STARTING
        )


class TestPost(RouteTestCase):
    def test_create_route(self):
        self._test_create_route_success(
            self.interface,
            family=4,
            network='10.10.10.0',
            prefix=24,
            gateway=str(self.system_controller_subnet[1])
        )

    def test_create_route_not_reachable(self):
        self._test_create_route_fail(
            self.interface,
            family=4,
            network='192.168.10.0',
            prefix=24,
            gateway=str(self.mgmt_subnet[1]),
            status_code=http_client.CONFLICT,
            error_message="not reachable by any address on this interface",
        )


class TestPostUpgrade(RouteTestCase):
    """ Tests route create operation during an upgrade.
    """
    def setUp(self):
        super(TestPostUpgrade, self).setUp()
        self.dbapi = db_api.get_instance()
        self._create_platform_upgrade()

    def test_create_route_during_disallowed_upgrade_state(self):

        for upgrade_state in DISALLOWED_UPGRADE_STATES:
            self.dbapi.software_upgrade_update(
                self.upgrade.uuid,
                {'state': upgrade_state})

            self._test_create_route_fail(
                self.interface,
                family=4,
                network='10.10.10.0',
                prefix=24,
                gateway=str(self.system_controller_subnet[1]),
                status_code=http_client.CONFLICT,
                error_message=("An Upgrade is in progress with state %s" %
                               upgrade_state)
            )

    def test_create_route_during_allowed_upgrade_state(self):
        network_subnet = 0
        for upgrade_state in ALLOWED_UPGRADE_STATES:
            self.dbapi.software_upgrade_update(
                self.upgrade.uuid,
                {'state': upgrade_state})

            network_subnet += 10
            self._test_create_route_success(
                self.interface,
                family=4,
                network='10.10.%s.0' % network_subnet,
                prefix=24,
                gateway=str(self.system_controller_subnet[1]),
            )


class TestDelete(RouteTestCase):
    """ Tests deletion.
        Typically, delete APIs return NO CONTENT.
        python2 and python3 libraries may return different
        content_type (None, or empty json) when NO_CONTENT returned.
    """

    def setUp(self):
        super(TestDelete, self).setUp()

    def test_delete_route_with_interface(self):
        interface = dbutils.create_test_interface(
            ifname="test1",
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=self.host.id,
            ihost_uuid=self.host.uuid)
        route_db = dbutils.create_test_route(
            interface_id=interface.id,
            family=4,
            network='10.10.10.0',
            prefix=24,
            gateway=str(self.oam_subnet[1]))

        self.assertEqual(route_db["interface_id"], interface.id)

        response = self.delete(self.get_single_url(route_db.uuid),
                               headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)


class TestDeleteUpgrade(RouteTestCase):
    """ Tests deletion during an upgrade.
    """
    def setUp(self):
        super(TestDeleteUpgrade, self).setUp()
        self.dbapi = db_api.get_instance()
        self._create_platform_upgrade()

    def test_delete_route_during_disallowed_upgrade_state(self):
        route_db = dbutils.create_test_route(
            interface_id=self.interface.id,
            family=4,
            network='10.10.10.0',
            prefix=24,
            gateway=str(self.oam_subnet[1]))

        for upgrade_state in DISALLOWED_UPGRADE_STATES:
            self.dbapi.software_upgrade_update(
                self.upgrade.uuid,
                {'state': upgrade_state})

            response = self.delete(self.get_single_url(route_db.uuid),
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
            # Check HTTP response is failed
            error_message = ("An Upgrade is in progress with state %s" %
                             upgrade_state)
            self.assertEqual('application/json', response.content_type)
            self.assertEqual(response.status_code, http_client.CONFLICT)
            self.assertIn(error_message, response.json['error_message'])

    def test_delete_route_during_allowed_upgrade_state(self):
        for upgrade_state in ALLOWED_UPGRADE_STATES:
            self.dbapi.software_upgrade_update(
                self.upgrade.uuid,
                {'state': upgrade_state})

            route_db = dbutils.create_test_route(
                interface_id=self.interface.id,
                family=4,
                network='10.10.10.0',
                prefix=24,
                gateway=str(self.oam_subnet[1]))

            response = self.delete(self.get_single_url(route_db.uuid),
                                   headers=self.API_HEADERS)
            self.assertEqual(response.status_code, http_client.NO_CONTENT)


class TestList(RouteTestCase):
    """ Route list operations
    """

    def setUp(self):
        super(TestList, self).setUp()

    def test_list_default_routes_all(self):
        response = self.get_json(self.API_PREFIX)
        for result in response[self.RESULT_KEY]:
            self.assertIn("address", result)

    def test_list_default_routes_host(self):
        response = self.get_json(self.get_host_scoped_url(self.host.uuid))
        self.assertEqual([], response[self.RESULT_KEY])

    def test_list_default_routes_interface(self):
        ifaces = self._create_test_host_platform_interface(self.host)
        interface_id = ifaces[0].uuid
        response = self.get_json(self.get_iface_scoped_url(interface_id))
        self.assertEqual([], response[self.RESULT_KEY])


class TestPatch(RouteTestCase):

    def setUp(self):
        super(TestPatch, self).setUp()

    def test_patch_not_allowed(self):
        # Try and patch an unmodifiable value

        patch_object = self.mgmt_addresses[0]

        response = self.patch_json(self.get_single_url(patch_object.uuid),
                                   [{'path': '/name',
                                     'value': 'test',
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify the expected API response
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.METHOD_NOT_ALLOWED)
        self.assertIn("The method PATCH is not allowed for this resource.",
                      response.json['error_message'])
