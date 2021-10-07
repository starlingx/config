#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan
from pecan import rest
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class PtpInstancePatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class PtpInstance(base.APIBase):
    """API representation of a PTP instance.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a PTP instance.
    """

    created_at = wtypes.datetime.datetime
    "Timestamp of creation of this PTP instance"

    id = int
    "Unique ID for this PTP instance"

    uuid = types.uuid
    "Unique UUID for this PTP instance"

    host_id = int
    "ID of host the PTP instance is associated to"

    host_uuid = types.uuid
    "UUID of the host the PTP instance is associated to"

    name = wtypes.text
    "Name given to the PTP instance"

    service = wtypes.Enum(str, 'ptp4l', 'phc2sys', 'ts2phc')
    "Type of service of the PTP instance"

    def __init__(self, **kwargs):
        self.fields = list(objects.ptp_instance.fields.keys())
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_ptp_instance, expand=True):
        ptp_instance = PtpInstance(**rpc_ptp_instance.as_dict())
        if not expand:
            ptp_instance.unset_fields_except(['uuid',
                                              'host_uuid',
                                              'name',
                                              'service',
                                              'created_at'])

        # do not expose the id attribute
        ptp_instance.host_id = wtypes.Unset

        LOG.debug("PtpInstance.convert_with_links: converted %s" %
                  ptp_instance.as_dict())
        return ptp_instance


class PtpInstanceCollection(collection.Collection):
    """API representation of a collection of PTP instances."""

    ptp_instances = [PtpInstance]
    "A list containing PTP instance objects"

    def __init__(self, **kwargs):
        self._type = 'ptp_instances'

    @classmethod
    def convert_with_links(cls, rpc_ptp_instances, limit, url=None,
                           expand=False, **kwargs):
        collection = PtpInstanceCollection()
        collection.ptp_instances = [PtpInstance.convert_with_links(p, expand)
                                    for p in rpc_ptp_instances]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'PtpInstanceController'


class PtpInstanceController(rest.RestController):
    """REST controller for PTP instance."""

    def __init__(self, from_ihosts=False):
        self._from_ihosts = from_ihosts

    def _get_ptp_instance_collection(
            self, host_uuid, marker=None, limit=None, sort_key=None,
            sort_dir=None, expand=False, resource_url=None):
        LOG.debug("PtpInstanceController._get_ptp_instance_collection: "
                  "from_ihosts %s host_uuid %s" % (self._from_ihosts,
                                                   host_uuid))
        if self._from_ihosts and not host_uuid:
            raise exception.InvalidParameterValue(_(
                  "Host id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        LOG.debug("PtpInstanceController._get_ptp_instance_collection: "
                  "marker %s, limit %s, sort_dir %s" % (marker, limit,
                                                        sort_dir))

        marker_obj = None
        if marker:
            marker_obj = objects.ptp_instance.get_by_uuid(
                pecan.request.context, marker)

        if self._from_ihosts or host_uuid:
            ptp_instances = pecan.request.dbapi.ptp_instances_get_by_ihost(
                                                    host_uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
        else:
            ptp_instances = pecan.request.dbapi.ptp_instances_get_list(
                                                    limit, marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

        return PtpInstanceCollection.convert_with_links(
            ptp_instances, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    @wsme_pecan.wsexpose(PtpInstanceCollection, types.uuid, types.uuid,
                         int, wtypes.text, wtypes.text)
    def get_all(self, uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of PTP instances."""
        LOG.debug("PtpInstanceController.get_all: uuid=%s" % uuid)
        return self._get_ptp_instance_collection(uuid, marker, limit,
                                                 sort_key=sort_key,
                                                 sort_dir=sort_dir)

    @wsme_pecan.wsexpose(PtpInstance, types.uuid)
    def get_one(self, ptp_instance_uuid):
        """Retrieve a single PTP instance."""
        LOG.debug("PtpInstanceController.get_one: uuid=%s" % ptp_instance_uuid)
        try:
            ptp_instance = objects.ptp_instance.get_by_uuid(
                pecan.request.context,
                ptp_instance_uuid)
        except exception.InvalidParameterValue:
            raise wsme.exc.ClientSideError(
                _("No PTP instance found for %s" % ptp_instance_uuid))

        return PtpInstance.convert_with_links(ptp_instance)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(PtpInstance, body=PtpInstance)
    def post(self, ptp_instance):
        """Create a new PTP instance."""
        ptp_instance_dict = ptp_instance.as_dict()
        LOG.debug("PtpInstanceController.post: %s" % ptp_instance_dict)

        # Replace host UUID by host ID
        host_uuid = ptp_instance_dict.pop('host_uuid')
        try:
            ihost_obj = pecan.request.dbapi.ihost_get(host_uuid)
        except exception.HostNotFound:
            msg = _("Host with uuid '%s' does not exist. " % host_uuid)
            raise wsme.exc.ClientSideError(msg)

        ptp_instance_dict['host_id'] = ihost_obj['id']
        result = pecan.request.dbapi.ptp_instance_create(ptp_instance_dict)
        return PtpInstance.convert_with_links(result)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, ptp_instance_uuid):
        """Delete a PTP instance."""
        LOG.debug("PtpInstanceController.delete: %s" % ptp_instance_uuid)
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        # Only allow delete if there are no associated interfaces and
        # parameters
        parameters = pecan.request.dbapi.ptp_parameters_get_by_foreign_uuid(
            ptp_instance_uuid)
        interfaces = pecan.request.dbapi.ptp_interfaces_get_by_instance(
            ptp_instance_uuid)
        if parameters or interfaces:
            raise wsme.exc.ClientSideError(
                _("PTP instance %s has still parameters or associated "
                  "interfaces. Check both ptp-interfaces and ptp-parameters.")
                % ptp_instance_uuid)

        pecan.request.dbapi.ptp_instance_destroy(ptp_instance_uuid)
