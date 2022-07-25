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
# Copyright (c) 2013-2022 Wind River Systems, Inc.
#

import jsonpatch
import pecan
from pecan import rest
import six
import uuid
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from oslo_utils import uuidutils
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.api.controllers.v1 import sensor as sensor_api
from sysinv.api.controllers.v1 import hwmon_api
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class SensorGroupPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return ['/host_uuid', 'uuid']


class SensorGroup(base.APIBase):
    """API representation of an Sensor Group

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of an
    isensorgroup.
    """

    uuid = types.uuid
    "Unique UUID for this isensorgroup"

    sensorgroupname = wtypes.text
    "Represent the name of the isensorgroup. Unique with path per host"

    path = wtypes.text
    "Represent the path of the isensor. Unique with isensorname per host"

    sensortype = wtypes.text
    "Represent the sensortype . e.g. Temperature, WatchDog"

    datatype = wtypes.text
    "Represent the datatype e.g. discrete or analog,"

    state = wtypes.text
    "Represent the state of the isensorgroup"

    possible_states = wtypes.text
    "Represent the possible states of the isensorgroup"

    algorithm = wtypes.text
    "Represent the algorithm of the isensorgroup."

    audit_interval_group = int
    "Represent the audit interval of the isensorgroup."

    actions_critical_choices = wtypes.text
    "Represent the configurable critical severity actions of the isensorgroup. CSV."

    actions_major_choices = wtypes.text
    "Represent the configurable major severity actions of the isensorgroup. CSV."

    actions_minor_choices = wtypes.text
    "Represent the configurable minor severity actions of the isensorgroup. CSV."

    actions_minor_group = wtypes.text
    "Represent the minor configured actions of the isensorgroup. CSV."

    actions_major_group = wtypes.text
    "Represent the major configured actions of the isensorgroup. CSV."

    actions_critical_group = wtypes.text
    "Represent the critical configured actions of the isensorgroup. CSV."

    unit_base_group = wtypes.text
    "Represent the unit base of the analog isensorgroup e.g. revolutions"

    unit_modifier_group = wtypes.text
    "Represent the unit modifier of the analog isensorgroup e.g. 10**2"

    unit_rate_group = wtypes.text
    "Represent the unit rate of the isensorgroup e.g. /minute"

    t_minor_lower_group = wtypes.text
    "Represent the minor lower threshold of the analog isensorgroup"

    t_minor_upper_group = wtypes.text
    "Represent the minor upper threshold of the analog isensorgroup"

    t_major_lower_group = wtypes.text
    "Represent the major lower threshold of the analog isensorgroup"

    t_major_upper_group = wtypes.text
    "Represent the major upper threshold of the analog isensorgroup"

    t_critical_lower_group = wtypes.text
    "Represent the critical lower threshold of the analog isensorgroup"

    t_critical_upper_group = wtypes.text
    "Represent the critical upper threshold of the analog isensorgroup"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                                                  six.integer_types)}
    "Represent meta data of the isensorgroup"

    suppress = types.boolean
    "Represent supress isensor if True, otherwise not suppress isensor"

    sensors = wtypes.text
    "Represent the sensors of the isensorgroup"

    host_id = int
    "Represent the host_id the isensorgroup belongs to"

    host_uuid = types.uuid
    "Represent the UUID of the host the isensorgroup belongs to"

    links = [link.Link]
    "Represent a list containing a self link and associated isensorgroup links"

    isensors = [link.Link]
    "Links to the collection of isensors on this isensorgroup"

    def __init__(self, **kwargs):
        self.fields = list(objects.sensorgroup.fields.keys())
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        # 'sensors' is not part of objects.SenorGroups.fields (it's an
        # API-only attribute)
        self.fields.append('sensors')
        setattr(self, 'sensors', kwargs.get('sensors', None))

    @classmethod
    def convert_with_links(cls, rsensorgroup, expand=True):

        sensorgroup = SensorGroup(**rsensorgroup.as_dict())

        sensorgroup_fields_common = ['uuid', 'host_id',
                                     'host_uuid',
                                     'sensortype', 'datatype',
                                     'sensorgroupname',
                                     'path',

                                     'state',
                                     'possible_states',
                                     'audit_interval_group',
                                     'algorithm',
                                     'actions_critical_choices',
                                     'actions_major_choices',
                                     'actions_minor_choices',
                                     'actions_minor_group',
                                     'actions_major_group',
                                     'actions_critical_group',
                                     'sensors',

                                     'suppress',
                                     'capabilities',
                                     'created_at', 'updated_at', ]

        sensorgroup_fields_analog = ['unit_base_group',
                                     'unit_modifier_group',
                                     'unit_rate_group',

                                     't_minor_lower_group',
                                     't_minor_upper_group',
                                     't_major_lower_group',
                                     't_major_upper_group',
                                     't_critical_lower_group',
                                     't_critical_upper_group', ]

        if rsensorgroup.datatype == 'discrete':
            sensorgroup_fields = sensorgroup_fields_common
        elif rsensorgroup.datatype == 'analog':
            sensorgroup_fields = sensorgroup_fields_common + sensorgroup_fields_analog
        else:
            LOG.error(_("Invalid datatype=%s" % rsensorgroup.datatype))

        if not expand:
            sensorgroup.unset_fields_except(sensorgroup_fields)

        if sensorgroup.host_id and not sensorgroup.host_uuid:
            host = objects.host.get_by_uuid(pecan.request.context,
                                            sensorgroup.host_id)
            sensorgroup.host_uuid = host.uuid

        # never expose the id attribute
        sensorgroup.host_id = wtypes.Unset
        sensorgroup.id = wtypes.Unset

        sensorgroup.links = [link.Link.make_link('self', pecan.request.host_url,
                                                 'isensorgroups',
                                                 sensorgroup.uuid),
                             link.Link.make_link('bookmark',
                                                 pecan.request.host_url,
                                                 'isensorgroups',
                                                 sensorgroup.uuid,
                                                 bookmark=True)]

        sensorgroup.isensors = [link.Link.make_link('self',
                                                    pecan.request.host_url,
                                                    'isensorgroups',
                                                    sensorgroup.uuid + "/isensors"),
                                link.Link.make_link('bookmark',
                                                    pecan.request.host_url,
                                                    'isensorgroups',
                                                    sensorgroup.uuid + "/isensors",
                                                    bookmark=True)]

        return sensorgroup


class SensorGroupCollection(collection.Collection):
    """API representation of a collection of SensorGroup objects."""

    isensorgroups = [SensorGroup]
    "A list containing SensorGroup objects"

    def __init__(self, **kwargs):
        self._type = 'isensorgroups'

    @classmethod
    def convert_with_links(cls, rsensorgroups, limit, url=None,
                           expand=False, **kwargs):
        collection = SensorGroupCollection()
        collection.isensorgroups = [SensorGroup.convert_with_links(p, expand)
                                    for p in rsensorgroups]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'SensorGroupController'


class SensorGroupController(rest.RestController):
    """REST controller for SensorGroups."""

    isensors = sensor_api.SensorController(from_isensorgroup=True)
    "Expose isensors as a sub-element of isensorgroups"

    _custom_actions = {
        'detail': ['GET'],
        'relearn': ['POST'],
    }

    def __init__(self, from_ihosts=False):
        self._from_ihosts = from_ihosts
        self._api_token = None
        self._hwmon_address = constants.LOCALHOST_HOSTNAME
        self._hwmon_port = constants.HWMON_PORT

    def _get_sensorgroups_collection(self, uuid,
                                     marker, limit, sort_key, sort_dir,
                                     expand=False, resource_url=None):

        if self._from_ihosts and not uuid:
            raise exception.InvalidParameterValue(_(
                "Host id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.sensorgroup.get_by_uuid(
                pecan.request.context,
                marker)

        if self._from_ihosts:
            sensorgroups = pecan.request.dbapi.isensorgroup_get_by_ihost(
                uuid, limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)
        else:
            if uuid:
                sensorgroups = pecan.request.dbapi.isensorgroup_get_by_ihost(
                    uuid, limit,
                    marker_obj,
                    sort_key=sort_key,
                    sort_dir=sort_dir)
            else:
                sensorgroups = pecan.request.dbapi.isensorgroup_get_list(
                    limit, marker_obj,
                    sort_key=sort_key,
                    sort_dir=sort_dir)

        return SensorGroupCollection.convert_with_links(sensorgroups, limit,
                                                        url=resource_url,
                                                        expand=expand,
                                                        sort_key=sort_key,
                                                        sort_dir=sort_dir)

    @wsme_pecan.wsexpose(SensorGroupCollection, types.uuid,
                         types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, uuid=None,
                marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of sensorgroups."""

        return self._get_sensorgroups_collection(uuid,
                                                 marker, limit,
                                                 sort_key, sort_dir)

    @wsme_pecan.wsexpose(SensorGroupCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of isensorgroups with detail."""

        # NOTE(lucasagomes): /detail should only work against collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "sensorgroups":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['sensorgroups', 'detail'])
        return self._get_sensorgroups_collection(uuid, marker, limit,
                                                 sort_key, sort_dir,
                                                 expand, resource_url)

    @wsme_pecan.wsexpose(SensorGroup, types.uuid)
    def get_one(self, sensorgroup_uuid):
        """Retrieve information about the given isensorgroup."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rsensorgroup = objects.sensorgroup.get_by_uuid(
            pecan.request.context, sensorgroup_uuid)

        if rsensorgroup.datatype == 'discrete':
            rsensorgroup = objects.sensorgroup_discrete.get_by_uuid(
                pecan.request.context, sensorgroup_uuid)
        elif rsensorgroup.datatype == 'analog':
            rsensorgroup = objects.sensorgroup_analog.get_by_uuid(
                pecan.request.context, sensorgroup_uuid)
        else:
            LOG.error(_("Invalid datatype=%s" %
                        rsensorgroup.datatype))

        return SensorGroup.convert_with_links(rsensorgroup)

    @staticmethod
    def _new_sensorgroup_semantic_checks(sensorgroup):
        datatype = sensorgroup.as_dict().get('datatype') or ""
        sensortype = sensorgroup.as_dict().get('sensortype') or ""
        if not (datatype and sensortype):
            raise wsme.exc.ClientSideError(_("sensorgroup-add:  Cannot "
                                             "add a sensorgroup "
                                             "without a valid datatype "
                                             "and sensortype."))

        if datatype not in constants.SENSOR_DATATYPE_VALID_LIST:
            raise wsme.exc.ClientSideError(_("sensorgroup datatype must be "
                                             "one of %s.") %
                                           constants.SENSOR_DATATYPE_VALID_LIST)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(SensorGroup, body=SensorGroup)
    def post(self, sensorgroup):
        """Create a new isensorgroup."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        self._new_sensorgroup_semantic_checks(sensorgroup)
        try:
            sensorgroup_dict = sensorgroup.as_dict()
            new_sensorgroup = _create(sensorgroup_dict)

        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data"))
        return sensorgroup.convert_with_links(new_sensorgroup)

    def _get_host_uuid(self, body):
        host_uuid = body.get('host_uuid') or ""
        try:
            host = pecan.request.dbapi.ihost_get(host_uuid)
        except exception.NotFound:
            raise wsme.exc.ClientSideError("_get_host_uuid lookup failed")
        return host.uuid

    @wsme_pecan.wsexpose('json', body=six.text_type)
    def relearn(self, body):
        """ Handle Sensor Model Relearn Request."""
        host_uuid = self._get_host_uuid(body)
        # LOG.info("Host UUID: %s - BM_TYPE: %s" % (host_uuid, bm_type ))

        # hwmon_sensorgroup = {'ihost_uuid': host_uuid}
        request_body = {'host_uuid': host_uuid}
        hwmon_response = hwmon_api.sensorgroup_relearn(
            self._api_token, self._hwmon_address, self._hwmon_port,
            request_body,
            constants.HWMON_DEFAULT_TIMEOUT_IN_SECS)

        if not hwmon_response:
            hwmon_response = {'status': 'fail',
                              'reason': 'no response',
                              'action': 'retry'}

        elif hwmon_response['status'] != 'pass':
            msg = _("HWMON has returned with "
                    "a status of %s, reason: %s, "
                    "recommended action: %s") % (
                hwmon_response.get('status'),
                hwmon_response.get('reason'),
                hwmon_response.get('action'))

            raise wsme.exc.ClientSideError(msg)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [SensorGroupPatchType])
    @wsme_pecan.wsexpose(SensorGroup, types.uuid,
                         body=[SensorGroupPatchType])
    def patch(self, sensorgroup_uuid, patch):
        """Update an existing sensorgroup."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rsensorgroup = objects.sensorgroup.get_by_uuid(
            pecan.request.context, sensorgroup_uuid)

        if rsensorgroup.datatype == 'discrete':
            rsensorgroup = objects.sensorgroup_discrete.get_by_uuid(
                pecan.request.context, sensorgroup_uuid)
        elif rsensorgroup.datatype == 'analog':
            rsensorgroup = objects.sensorgroup_analog.get_by_uuid(
                pecan.request.context, sensorgroup_uuid)
        else:
            raise wsme.exc.ClientSideError(_("Invalid datatype=%s" %
                                             rsensorgroup.datatype))

        host = pecan.request.dbapi.ihost_get(
            rsensorgroup['host_id']).as_dict()

        utils.validate_patch(patch)
        patch_obj = jsonpatch.JsonPatch(patch)
        my_host_uuid = None
        for p in patch_obj:
            # For Profile replace host_uuid with corresponding id
            if p['path'] == '/host_uuid':
                p['path'] = '/host_id'
                host = objects.host.get_by_uuid(pecan.request.context,
                                                p['value'])
                p['value'] = host.id
                my_host_uuid = host.uuid

            # update sensors if set
            sensors = None
            for s in patch:
                if '/sensors' in s['path']:
                    sensors = s['value']
                    patch.remove(s)
                    break

        if sensors:
            _update_sensors("modify", rsensorgroup, host, sensors)

        try:
            sensorgroup = SensorGroup(**jsonpatch.apply_patch(
                rsensorgroup.as_dict(),
                patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Update only the fields that have changed
        if rsensorgroup.datatype == 'discrete':
            fields = objects.sensorgroup_discrete.fields
        else:
            fields = objects.sensorgroup_analog.fields

        for field in fields:
            if rsensorgroup[field] != getattr(sensorgroup, field):
                rsensorgroup[field] = getattr(sensorgroup, field)

        delta = rsensorgroup.obj_what_changed()
        sensorgroup_suppress_attrs = ['suppress']
        if any(x in delta for x in sensorgroup_suppress_attrs):
            valid_suppress = [True, False]
            if rsensorgroup.suppress not in valid_suppress:
                raise wsme.exc.ClientSideError(_("Invalid suppress value, "
                                               "select 'True' or 'False'"))

        self._semantic_modifiable_fields(patch_obj)

        if not pecan.request.user_agent.startswith('hwmon'):
            hwmon_sensorgroup = cutils.removekeys_nonhwmon(
                rsensorgroup.as_dict())

            if not my_host_uuid:
                host = objects.host.get_by_uuid(pecan.request.context,
                                                rsensorgroup.host_id)
                my_host_uuid = host.uuid

            hwmon_sensorgroup.update({'host_uuid': my_host_uuid})

            hwmon_response = hwmon_api.sensorgroup_modify(
                self._api_token, self._hwmon_address, self._hwmon_port,
                hwmon_sensorgroup,
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

                raise wsme.exc.ClientSideError(msg)

        sensorgroup_prop_attrs = ['audit_interval_group',
                                  'actions_minor_group',
                                  'actions_major_group',
                                  'actions_critical_group',
                                  'suppress']

        if any(x in delta for x in sensorgroup_prop_attrs):
            # propagate to Sensors within this SensorGroup
            sensor_val = {'audit_interval': rsensorgroup.audit_interval_group,
                          'actions_minor': rsensorgroup.actions_minor_group,
                          'actions_major': rsensorgroup.actions_major_group,
                          'actions_critical': rsensorgroup.actions_critical_group}
            if 'suppress' in delta:
                    sensor_val.update({'suppress': rsensorgroup.suppress})
            pecan.request.dbapi.isensorgroup_propagate(rsensorgroup.uuid, sensor_val)

        rsensorgroup.save()

        return SensorGroup.convert_with_links(rsensorgroup)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, sensorgroup_uuid):
        """Delete a sensorgroup."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        pecan.request.dbapi.isensorgroup_destroy(sensorgroup_uuid)

    @staticmethod
    def _semantic_modifiable_fields(patch_obj, force_action=False):
        # Prevent auto populated fields from being updated
        state_rel_path = ['/uuid', '/id', '/host_id', '/datatype',
                          '/sensortype']

        if any(p['path'] in state_rel_path for p in patch_obj):
            raise wsme.exc.ClientSideError(_("The following fields can not be "
                                             "modified: %s ") % state_rel_path)

        if not (pecan.request.user_agent.startswith('hwmon') or force_action):
            state_rel_path = ['/sensorgroupname', '/path',
                              '/state', '/possible_states',
                              '/actions_critical_choices',
                              '/actions_major_choices',
                              '/actions_minor_choices',
                              '/unit_base_group',
                              '/unit_modifier_group',
                              '/unit_rate_group',
                              '/t_minor_lower_group',
                              '/t_minor_upper_group',
                              '/t_major_lower_group',
                              '/t_major_upper_group',
                              '/t_critical_lower_group',
                              '/t_critical_upper_group',
                              ]

            if any(p['path'] in state_rel_path for p in patch_obj):
                raise wsme.exc.ClientSideError(
                    _("The following fields are not remote-modifiable: %s") %
                    state_rel_path)


def _create(sensorgroup, from_profile=False):
    """ Create a sensorgroup through a non-HTTP request e.g. via profile.py
        while still passing through sensorgroup semantic checks.
        Hence, not declared inside a class.
        Param:
            sensorgroup - dictionary of sensorgroup values
            from_profile - Boolean whether from profile
    """

    if 'host_id' in sensorgroup and sensorgroup['host_id']:
        ihostid = sensorgroup['host_id']
    else:
        ihostid = sensorgroup['host_uuid']

    ihost = pecan.request.dbapi.ihost_get(ihostid)
    if uuidutils.is_uuid_like(ihostid):
        host_id = ihost['id']
    else:
        host_id = ihostid
    sensorgroup.update({'host_id': host_id})
    LOG.info("isensorgroup post sensorgroups ihostid: %s" % host_id)
    sensorgroup['host_uuid'] = ihost['uuid']

    # Assign UUID if not already done.
    if not sensorgroup.get('uuid'):
        sensorgroup['uuid'] = str(uuid.uuid4())

    # Get sensors
    sensors = None
    if 'sensors' in sensorgroup:
        sensors = sensorgroup['sensors']

    # Set defaults - before checks to allow for optional attributes
    # if not from_profile:
    #     sensorgroup = _set_defaults(sensorgroup)

    # Semantic checks
    # sensorgroup = _check("add",
    #                      sensorgroup,
    #                      sensors=sensors,
    #                      ifaces=uses_if,
    #                      from_profile=from_profile)

    if sensorgroup.get('datatype'):
        if sensorgroup['datatype'] == 'discrete':
            new_sensorgroup = pecan.request.dbapi.isensorgroup_discrete_create(
                ihost.id, sensorgroup)
        elif sensorgroup['datatype'] == 'analog':
            new_sensorgroup = pecan.request.dbapi.isensorgroup_analog_create(
                ihost.id, sensorgroup)
        else:
            raise wsme.exc.ClientSideError(_("Invalid datatype. %s" %
                                             sensorgroup.datatype))
    else:
        raise wsme.exc.ClientSideError(_("Unspecified datatype."))

    # Update sensors
    if sensors:
        try:
            _update_sensors("modify",
                            new_sensorgroup.as_dict(),
                            ihost,
                            sensors)
        except Exception as e:
            pecan.request.dbapi.isensorgroup_destroy(
                new_sensorgroup.as_dict()['uuid'])
            raise e

    # Update sensors
    # return new_sensorgroup
    return SensorGroup.convert_with_links(new_sensorgroup)


def _update_sensors(op, sensorgroup, ihost, isensors):
    sensors = isensors.split(',')

    this_sensorgroup_datatype = None
    this_sensorgroup_sensortype = None
    if op == "add":
        this_sensorgroup_id = 0
    else:
        this_sensorgroup_id = sensorgroup['id']
        this_sensorgroup_datatype = sensorgroup['datatype']
        this_sensorgroup_sensortype = sensorgroup['sensortype']

    if sensors:
        # Update Sensors' isensorgroup_uuid attribute
        isensors_list = pecan.request.dbapi.isensor_get_all(
            host_id=ihost['id'])
        for p in isensors_list:
            # if new sensor associated
            if (p.uuid in sensors or p.sensorname in sensors) \
                    and not p.sensorgroup_id:
                values = {'sensorgroup_id': sensorgroup['id']}
            # else if old sensor disassociated
            elif ((p.uuid not in sensors and p.sensorname not in sensors) and
                  p.sensorgroup_id and
                  p.sensorgroup_id == this_sensorgroup_id):
                values = {'sensorgroup_id': None}
            else:
                continue

            if p.datatype != this_sensorgroup_datatype:
                msg = _("Invalid datatype:  host %s sensor %s: Expected: %s "
                        "Received: %s." %
                        (ihost['hostname'], p.sensorname,
                         this_sensorgroup_datatype, p.datatype))
                raise wsme.exc.ClientSideError(msg)

            if p.sensortype != this_sensorgroup_sensortype:
                msg = _("Invalid sensortype:  host %s sensor %s: Expected: %s "
                        "Received: %s." %
                        (ihost['hostname'], p.sensorname,
                         this_sensorgroup_sensortype, p.sensortype))
                raise wsme.exc.ClientSideError(msg)

            try:
                pecan.request.dbapi.isensor_update(p.uuid, values)
            except exception.HTTPNotFound:
                msg = _("Sensor update of isensorgroup_uuid failed: host %s "
                        "sensor %s" % (ihost['hostname'], p.sensorname))
                raise wsme.exc.ClientSideError(msg)
