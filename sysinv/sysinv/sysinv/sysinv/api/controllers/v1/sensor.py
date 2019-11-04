# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 UnitedStack Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2013-2015 Wind River Systems, Inc.
#

import copy
import jsonpatch
import pecan
from pecan import rest
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.api.controllers.v1 import hwmon_api
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class SensorPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class Sensor(base.APIBase):
    """API representation of an Sensor

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of an
    isensor.
    """

    uuid = types.uuid
    "Unique UUID for this isensor"

    sensorname = wtypes.text
    "Represent the name of the isensor. Unique with path per host"

    path = wtypes.text
    "Represent the path of the isensor. Unique with isensorname per host"

    sensortype = wtypes.text
    "Represent the type of isensor. e.g. Temperature, WatchDog"

    datatype = wtypes.text
    "Represent the entity monitored. e.g. discrete, analog"

    status = wtypes.text
    "Represent current sensor status: ok, minor, major, critical, disabled"

    state = wtypes.text
    "Represent the current state of the isensor"

    state_requested = wtypes.text
    "Represent the requested state of the isensor"

    audit_interval = int
    "Represent the audit_interval of the isensor."

    algorithm = wtypes.text
    "Represent the algorithm of the isensor."

    actions_minor = wtypes.text
    "Represent the minor configured actions of the isensor. CSV."

    actions_major = wtypes.text
    "Represent the major configured actions of the isensor. CSV."

    actions_critical = wtypes.text
    "Represent the critical configured actions of the isensor. CSV."

    suppress = wtypes.text
    "Represent supress isensor if True, otherwise not suppress isensor"

    value = wtypes.text
    "Represent current value of the discrete isensor"

    unit_base = wtypes.text
    "Represent the unit base of the analog isensor e.g. revolutions"

    unit_modifier = wtypes.text
    "Represent the unit modifier of the analog isensor e.g. 10**2"

    unit_rate = wtypes.text
    "Represent the unit rate of the isensor e.g. /minute"

    t_minor_lower = wtypes.text
    "Represent the minor lower threshold of the analog isensor"

    t_minor_upper = wtypes.text
    "Represent the minor upper threshold of the analog isensor"

    t_major_lower = wtypes.text
    "Represent the major lower threshold of the analog isensor"

    t_major_upper = wtypes.text
    "Represent the major upper threshold of the analog isensor"

    t_critical_lower = wtypes.text
    "Represent the critical lower threshold of the analog isensor"

    t_critical_upper = wtypes.text
    "Represent the critical upper threshold of the analog isensor"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                                                  six.integer_types)}
    "Represent meta data of the isensor"

    host_id = int
    "Represent the host_id the isensor belongs to"

    sensorgroup_id = int
    "Represent the isensorgroup_id the isensor belongs to"

    host_uuid = types.uuid
    "Represent the UUID of the host the isensor belongs to"

    sensorgroup_uuid = types.uuid
    "Represent the UUID of the sensorgroup the isensor belongs to"

    links = [link.Link]
    "Represent a list containing a self link and associated isensor links"

    def __init__(self, **kwargs):
        self.fields = objects.sensor.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_sensor, expand=True):

        sensor = Sensor(**rpc_sensor.as_dict())

        sensor_fields_common = ['uuid', 'host_id', 'sensorgroup_id',
                                'sensortype', 'datatype',
                                'sensorname', 'path',

                                'status',
                                'state', 'state_requested',
                                'sensor_action_requested',
                                'actions_minor',
                                'actions_major',
                                'actions_critical',

                                'suppress',
                                'audit_interval',
                                'algorithm',
                                'capabilities',
                                'host_uuid', 'sensorgroup_uuid',
                                'created_at', 'updated_at', ]

        sensor_fields_analog = ['unit_base',
                                'unit_modifier',
                                'unit_rate',

                                't_minor_lower',
                                't_minor_upper',
                                't_major_lower',
                                't_major_upper',
                                't_critical_lower',
                                't_critical_upper', ]

        if rpc_sensor.datatype == 'discrete':
            sensor_fields = sensor_fields_common
        elif rpc_sensor.datatype == 'analog':
            sensor_fields = sensor_fields_common + sensor_fields_analog
        else:
            LOG.error(_("Invalid datatype=%s" % rpc_sensor.datatype))

        if not expand:
            sensor.unset_fields_except(sensor_fields)

        # never expose the id attribute
        sensor.host_id = wtypes.Unset
        sensor.sensorgroup_id = wtypes.Unset

        sensor.links = [link.Link.make_link('self', pecan.request.host_url,
                                            'isensors', sensor.uuid),
                        link.Link.make_link('bookmark',
                                            pecan.request.host_url,
                                            'isensors', sensor.uuid,
                                            bookmark=True)
                        ]
        return sensor


class SensorCollection(collection.Collection):
    """API representation of a collection of Sensor objects."""

    isensors = [Sensor]
    "A list containing Sensor objects"

    def __init__(self, **kwargs):
        self._type = 'isensors'

    @classmethod
    def convert_with_links(cls, rpc_sensors, limit, url=None,
                           expand=False, **kwargs):
        collection = SensorCollection()
        collection.isensors = [Sensor.convert_with_links(p, expand)
                               for p in rpc_sensors]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'SensorController'


class SensorController(rest.RestController):
    """REST controller for Sensors."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_ihosts=False, from_isensorgroup=False):
        self._from_ihosts = from_ihosts
        self._from_isensorgroup = from_isensorgroup
        self._api_token = None
        self._hwmon_address = constants.LOCALHOST_HOSTNAME
        self._hwmon_port = constants.HWMON_PORT

    def _get_sensors_collection(self, uuid, sensorgroup_uuid,
                                marker, limit, sort_key, sort_dir,
                                expand=False, resource_url=None):

        if self._from_ihosts and not uuid:
            raise exception.InvalidParameterValue(_(
                "Host id not specified."))

        if self._from_isensorgroup and not uuid:
            raise exception.InvalidParameterValue(_(
                "SensorGroup id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.sensor.get_by_uuid(
                pecan.request.context,
                marker)

        if self._from_ihosts:
            sensors = pecan.request.dbapi.isensor_get_by_ihost(
                uuid, limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)
            LOG.debug("dbapi.isensor_get_by_ihost=%s" % sensors)
        elif self._from_isensorgroup:
            sensors = pecan.request.dbapi.isensor_get_by_sensorgroup(
                uuid,
                limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)
            LOG.debug("dbapi.isensor_get_by_sensorgroup=%s" % sensors)
        else:
            if uuid and not sensorgroup_uuid:
                sensors = pecan.request.dbapi.isensor_get_by_ihost(
                    uuid, limit,
                    marker_obj,
                    sort_key=sort_key,
                    sort_dir=sort_dir)
                LOG.debug("dbapi.isensor_get_by_ihost=%s" % sensors)
            elif uuid and sensorgroup_uuid:  # Need ihost_uuid ?
                sensors = pecan.request.dbapi.isensor_get_by_ihost_sensorgroup(
                    uuid,
                    sensorgroup_uuid,
                    limit,
                    marker_obj,
                    sort_key=sort_key,
                    sort_dir=sort_dir)
                LOG.debug("dbapi.isensor_get_by_ihost_sensorgroup=%s" %
                          sensors)

            elif sensorgroup_uuid:  # Need ihost_uuid ?
                sensors = pecan.request.dbapi.isensor_get_by_ihost_sensorgroup(
                    uuid,  # None
                    sensorgroup_uuid,
                    limit,
                    marker_obj,
                    sort_key=sort_key,
                    sort_dir=sort_dir)

            else:
                sensors = pecan.request.dbapi.isensor_get_list(
                    limit, marker_obj,
                    sort_key=sort_key,
                    sort_dir=sort_dir)

        return SensorCollection.convert_with_links(sensors, limit,
                                                   url=resource_url,
                                                   expand=expand,
                                                   sort_key=sort_key,
                                                   sort_dir=sort_dir)

    @wsme_pecan.wsexpose(SensorCollection, types.uuid, types.uuid,
                         types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, uuid=None, sensorgroup_uuid=None,
                marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of sensors."""

        return self._get_sensors_collection(uuid, sensorgroup_uuid,
                                            marker, limit,
                                            sort_key, sort_dir)

    @wsme_pecan.wsexpose(SensorCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of isensors with detail."""

        # NOTE(lucasagomes): /detail should only work against collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "sensors":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['sensors', 'detail'])
        return self._get_sensors_collection(uuid, marker, limit, sort_key,
                                            sort_dir, expand, resource_url)

    @wsme_pecan.wsexpose(Sensor, types.uuid)
    def get_one(self, sensor_uuid):
        """Retrieve information about the given isensor."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_sensor = objects.sensor.get_by_uuid(
            pecan.request.context, sensor_uuid)

        if rpc_sensor.datatype == 'discrete':
            rpc_sensor = objects.sensor_discrete.get_by_uuid(
                pecan.request.context, sensor_uuid)
        elif rpc_sensor.datatype == 'analog':
            rpc_sensor = objects.sensor_analog.get_by_uuid(
                pecan.request.context, sensor_uuid)
        else:
            LOG.error(_("Invalid datatype=%s" % rpc_sensor.datatype))

        return Sensor.convert_with_links(rpc_sensor)

    @staticmethod
    def _new_sensor_semantic_checks(sensor):
        datatype = sensor.as_dict().get('datatype') or ""
        sensortype = sensor.as_dict().get('sensortype') or ""
        if not (datatype and sensortype):
            raise wsme.exc.ClientSideError(_("sensor-add Cannot "
                                             "add a sensor "
                                             "without a valid datatype "
                                             "and sensortype."))

        if datatype not in constants.SENSOR_DATATYPE_VALID_LIST:
            raise wsme.exc.ClientSideError(
                _("sensor datatype must be one of %s.") %
                constants.SENSOR_DATATYPE_VALID_LIST)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Sensor, body=Sensor)
    def post(self, sensor):
        """Create a new isensor."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        self._new_sensor_semantic_checks(sensor)
        try:
            ihost = pecan.request.dbapi.ihost_get(sensor.host_uuid)

            if hasattr(sensor, 'datatype'):
                if sensor.datatype == 'discrete':
                    new_sensor = pecan.request.dbapi.isensor_discrete_create(
                        ihost.id, sensor.as_dict())
                elif sensor.datatype == 'analog':
                    new_sensor = pecan.request.dbapi.isensor_analog_create(
                        ihost.id, sensor.as_dict())
                else:
                    raise wsme.exc.ClientSideError(_("Invalid datatype. %s" %
                                                     sensor.datatype))
            else:
                raise wsme.exc.ClientSideError(_("Unspecified datatype."))

        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data"))
        return sensor.convert_with_links(new_sensor)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [SensorPatchType])
    @wsme_pecan.wsexpose(Sensor, types.uuid,
                         body=[SensorPatchType])
    def patch(self, sensor_uuid, patch):
        """Update an existing sensor."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_sensor = objects.sensor.get_by_uuid(pecan.request.context,
                                                sensor_uuid)
        if rpc_sensor.datatype == 'discrete':
            rpc_sensor = objects.sensor_discrete.get_by_uuid(
                pecan.request.context, sensor_uuid)
        elif rpc_sensor.datatype == 'analog':
            rpc_sensor = objects.sensor_analog.get_by_uuid(
                pecan.request.context, sensor_uuid)
        else:
            raise wsme.exc.ClientSideError(_("Invalid datatype=%s" %
                                             rpc_sensor.datatype))

        rpc_sensor_orig = copy.deepcopy(rpc_sensor)

        # replace ihost_uuid and isensorgroup_uuid with corresponding
        utils.validate_patch(patch)
        patch_obj = jsonpatch.JsonPatch(patch)
        my_host_uuid = None
        for p in patch_obj:
            if p['path'] == '/host_uuid':
                p['path'] = '/host_id'
                host = objects.host.get_by_uuid(pecan.request.context,
                                                p['value'])
                p['value'] = host.id
                my_host_uuid = host.uuid

            if p['path'] == '/sensorgroup_uuid':
                p['path'] = '/sensorgroup_id'
                try:
                    sensorgroup = objects.sensorgroup.get_by_uuid(
                        pecan.request.context, p['value'])
                    p['value'] = sensorgroup.id
                    LOG.info("sensorgroup_uuid=%s id=%s" % (p['value'],
                                                            sensorgroup.id))
                except exception.SysinvException:
                    p['value'] = None

        try:
            sensor = Sensor(**jsonpatch.apply_patch(rpc_sensor.as_dict(),
                                                    patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Update only the fields that have changed
        if rpc_sensor.datatype == 'discrete':
            fields = objects.sensor_discrete.fields
        else:
            fields = objects.sensor_analog.fields

        for field in fields:
            if rpc_sensor[field] != getattr(sensor, field):
                rpc_sensor[field] = getattr(sensor, field)

        delta = rpc_sensor.obj_what_changed()
        sensor_suppress_attrs = ['suppress']
        force_action = False
        if any(x in delta for x in sensor_suppress_attrs):
            valid_suppress = ['True', 'False', 'true', 'false', 'force_action']
            if rpc_sensor.suppress.lower() not in valid_suppress:
                raise wsme.exc.ClientSideError(_("Invalid suppress value, "
                                                 "select 'True' or 'False'"))
            elif rpc_sensor.suppress.lower() == 'force_action':
                LOG.info("suppress=%s" % rpc_sensor.suppress.lower())
                rpc_sensor.suppress = rpc_sensor_orig.suppress
                force_action = True

        self._semantic_modifiable_fields(patch_obj, force_action)

        if not pecan.request.user_agent.startswith('hwmon'):
            hwmon_sensor = cutils.removekeys_nonhwmon(
                rpc_sensor.as_dict())

            if not my_host_uuid:
                host = objects.host.get_by_uuid(pecan.request.context,
                                                rpc_sensor.host_id)
                my_host_uuid = host.uuid
                LOG.warn("Missing host_uuid updated=%s" % my_host_uuid)

            hwmon_sensor.update({'host_uuid': my_host_uuid})

            hwmon_response = hwmon_api.sensor_modify(
                self._api_token, self._hwmon_address, self._hwmon_port,
                hwmon_sensor,
                constants.HWMON_DEFAULT_TIMEOUT_IN_SECS)

            if not hwmon_response:
                hwmon_response = {'status': 'fail',
                                  'reason': 'no response',
                                  'action': 'retry'}

            if hwmon_response['status'] != 'pass':
                msg = _("HWMON has returned with "
                        "a status of %s, reason: %s, "
                        "recommended action: %s") % (
                        hwmon_response.get('status'),
                        hwmon_response.get('reason'),
                        hwmon_response.get('action'))

                if force_action:
                    LOG.error(msg)
                else:
                    raise wsme.exc.ClientSideError(msg)

        rpc_sensor.save()

        return Sensor.convert_with_links(rpc_sensor)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, sensor_uuid):
        """Delete a sensor."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        pecan.request.dbapi.isensor_destroy(sensor_uuid)

    @staticmethod
    def _semantic_modifiable_fields(patch_obj, force_action=False):
        # Prevent auto populated fields from being updated
        state_rel_path = ['/uuid', '/id', '/host_id', '/datatype',
                          '/sensortype']
        if any(p['path'] in state_rel_path for p in patch_obj):
            raise wsme.exc.ClientSideError(_("The following fields can not be "
                                             "modified: %s ") % state_rel_path)

        state_rel_path = ['/actions_critical',
                          '/actions_major',
                          '/actions_minor']
        if any(p['path'] in state_rel_path for p in patch_obj):
            raise wsme.exc.ClientSideError(
                _("The following fields can only be modified at the "
                  "sensorgroup level: %s") % state_rel_path)

        if not (pecan.request.user_agent.startswith('hwmon') or force_action):
            state_rel_path = ['/sensorname',
                              '/path',
                              '/status',
                              '/state',
                              '/possible_states',
                              '/algorithm',
                              '/actions_critical_choices',
                              '/actions_major_choices',
                              '/actions_minor_choices',
                              '/unit_base',
                              '/unit_modifier',
                              '/unit_rate',
                              '/t_minor_lower',
                              '/t_minor_upper',
                              '/t_major_lower',
                              '/t_major_upper',
                              '/t_critical_lower',
                              '/t_critical_upper',
                              ]

            if any(p['path'] in state_rel_path for p in patch_obj):
                raise wsme.exc.ClientSideError(
                    _("The following fields are not remote-modifiable: %s") %
                    state_rel_path)
