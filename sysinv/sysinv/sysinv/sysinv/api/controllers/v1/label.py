# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan
import wsme
import wsmeext.pecan as wsme_pecan
from pecan import rest
from sysinv import objects
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.api.controllers.v1 import vim_api
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.openstack.common import excutils
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common.rpc import common as rpc_common
from wsme import types as wtypes

LOG = log.getLogger(__name__)


class LabelPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class Label(base.APIBase):
    """API representation of host label Configuration.

    Kubernetes labels are assigned to nodes(ie. hosts)

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a host label.
    """

    uuid = types.uuid
    "Unique UUID for this label"

    label_key = wtypes.text
    "Represents a label key assigned to the host"

    label_value = wtypes.text
    "Represents a label value assigned to the host"

    host_id = int
    "Represent the host_id the label belongs to"

    host_uuid = types.uuid
    "The uuid of the host this label belongs to"

    def __init__(self, **kwargs):
        self.fields = objects.label.fields.keys()
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    @classmethod
    def convert_with_links(cls, rpc_label, expand=False):
        label = Label(**rpc_label.as_dict())
        if not expand:
            label.unset_fields_except(['uuid',
                                       'host_uuid',
                                       'label_key',
                                       'label_value'])

        # do not expose the id attribute
        label.host_id = wtypes.Unset

        return label


class LabelCollection(collection.Collection):
    """API representation of a collection of labels."""

    labels = [Label]
    "A list containing label objects"

    def __init__(self, **kwargs):
        self._type = 'labels'

    @classmethod
    def convert_with_links(cls, rpc_labels, limit, url=None,
                           expand=False, **kwargs):
        collection = LabelCollection()
        collection.labels = [Label.convert_with_links(p, expand)
                             for p in rpc_labels]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'LabelController'


class LabelController(rest.RestController):
    """REST controller for labels."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_ihosts=False):
        self._from_ihosts = from_ihosts

    def _get_labels_collection(self, host_uuid, marker, limit, sort_key,
                               sort_dir, expand=False, resource_url=None):
        if self._from_ihosts and not host_uuid:
            raise exception.InvalidParameterValue(_(
                  "Host id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        marker_obj = None
        if marker:
            marker_obj = objects.label.get_by_uuid(
                                        pecan.request.context,
                                        marker)
        if self._from_ihosts:
            host_label = pecan.request.dbapi.label_get_by_host(
                                                    host_uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
        else:
            if host_uuid:
                host_label = pecan.request.dbapi.label_get_by_host(
                                                    host_uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
            else:
                host_label = pecan.request.dbapi.label_get_list(
                                                    limit, marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

        return LabelCollection.convert_with_links(host_label, limit,
                                                  url=resource_url,
                                                  expand=expand,
                                                  sort_key=sort_key,
                                                  sort_dir=sort_dir)

    @wsme_pecan.wsexpose(LabelCollection, types.uuid, types.uuid,
                         int, wtypes.text, wtypes.text)
    def get_all(self, uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of labels."""
        return self._get_labels_collection(uuid,
                                           marker, limit, sort_key, sort_dir)

    @wsme_pecan.wsexpose(LabelCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of devices with detail."""

        # NOTE: /detail should only work against collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "labels":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['labels', 'detail'])
        return self._get_labels_collection(uuid, marker, limit, sort_key,
                                           sort_dir, expand, resource_url)

    @wsme_pecan.wsexpose(Label, types.uuid)
    def get_one(self, label_uuid):
        """Retrieve information about the given label."""

        try:
            sp_label = objects.label.get_by_uuid(
                pecan.request.context,
                label_uuid)
        except exception.InvalidParameterValue:
            raise wsme.exc.ClientSideError(
                _("No label found for %s" % label_uuid))

        return Label.convert_with_links(sp_label)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(LabelCollection, types.uuid,
                         body=types.apidict)
    def post(self, uuid, body):
        """Assign label(s) to a host.
        """
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        LOG.info("patch_data: %s" % body)
        host = objects.host.get_by_uuid(pecan.request.context, uuid)

        _check_host_locked(host)

        try:
            pecan.request.rpcapi.update_kubernetes_label(
                pecan.request.context,
                host.uuid,
                body
            )
        except rpc_common.RemoteError as e:
            raise wsme.exc.ClientSideError(str(e.value))
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(e)

        new_records = []
        for key, value in body.iteritems():
            values = {
                'host_id': host.id,
                'label_key': key,
                'label_value': value
            }

            try:
                new_label = pecan.request.dbapi.label_create(uuid, values)
                new_records.append(new_label)
            except exception.HostLabelAlreadyExists:
                pass

        try:
            vim_api.vim_host_update(
                None,
                uuid,
                host.hostname,
                constants.VIM_DEFAULT_TIMEOUT_IN_SECS)
        except Exception as e:
            LOG.warn(_("No response vim_api host:%s e=%s" %
                     (host.hostname, e)))
            pass

        return LabelCollection.convert_with_links(
            new_records, limit=None, url=None, expand=False,
            sort_key='id', sort_dir='asc')

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, uuid):
        """Delete a host label."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        lbl_obj = objects.label.get_by_uuid(pecan.request.context, uuid)
        host = objects.host.get_by_uuid(pecan.request.context, lbl_obj.host_id)
        label_dict = {lbl_obj.label_key: None}

        _check_host_locked(host)

        try:
            pecan.request.rpcapi.update_kubernetes_label(
                pecan.request.context,
                host.uuid,
                label_dict)
        except rpc_common.RemoteError as e:
            raise wsme.exc.ClientSideError(str(e.value))
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(e)

        try:
            pecan.request.dbapi.label_destroy(lbl_obj.uuid)
        except exception.HostLabelNotFound:
            msg = _("Delete host label failed: host %s label %s=%s"
                    % (host.hostname, lbl_obj.label_key, lbl_obj.label_value))
            raise wsme.exc.ClientSideError(msg)

        try:
            vim_api.vim_host_update(
                None,
                host.uuid,
                host.hostname,
                constants.VIM_DEFAULT_TIMEOUT_IN_SECS)
        except Exception as e:
            LOG.warn(_("No response vim_api host:%s e=%s" %
                     (host.hostname, e)))
            pass


###########
# UTILS
###########
def _check_host_locked(host):

    # TODO(ksmith):
    # turn this on later
    return

    if (utils.is_aio_simplex_host_unlocked(host) or
            host.administrative != constants.ADMIN_LOCKED):
        raise wsme.exc.ClientSideError(_("Host must be locked."))
