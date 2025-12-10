# Copyright (c) 2018-2024,2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import os
import pecan
from pecan import rest
import re
import wsme
import wsmeext.pecan as wsme_pecan
from wsme import types as wtypes

from contextlib import suppress
from oslo_log import log
from oslo_utils import excutils
from sysinv._i18n import _
from sysinv import objects
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.api.controllers.v1 import vim_api
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.helm import common
from sysinv.openstack.common.rpc import common as rpc_common

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
        self.fields = list(objects.label.fields.keys())
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

    def _apply_manifest_after_label_operation(self, host_uuid, keys):
        if (common.LABEL_DISABLE_NOHZ_FULL in keys or
                constants.KUBE_POWER_MANAGER_LABEL in keys):
            pecan.request.rpcapi.update_grub_config(
                pecan.request.context, host_uuid)

        if constants.KUBE_POWER_MANAGER_LABEL in keys:
            pecan.request.rpcapi.configure_power_manager(
                pecan.request.context)

        if _check_if_stalld_label_modified(keys):
            pecan.request.rpcapi.configure_stalld(
                pecan.request.context, host_uuid)

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
    @wsme_pecan.wsexpose(LabelCollection, types.uuid, types.boolean,
                         body=types.apidict)
    def post(self, host_uuid, overwrite=False, body=None):
        """Assign label(s) to a host.
        """
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        LOG.info("patch_data: %s" % body)
        host = objects.host.get_by_uuid(pecan.request.context, host_uuid)

        # Probably will never happen, but add an extra guard to be absolutely
        # sure no null values make it into the database.
        for key, value in body.items():
            if value is None:
                raise wsme.exc.ClientSideError(
                    _("Null input detected for Label %s for host %s. Input invalid." % (
                        key, host.hostname)))

        _check_host_locked(host, body.keys())

        _semantic_check_worker_labels(body)

        _semantic_check_k8s_plugins_labels(host, body)

        _semantic_check_stalld_labels(host, body)

        existing_labels = {}
        for label_key in body.keys():
            label = None
            with suppress(exception.HostLabelNotFoundByKey):
                label = pecan.request.dbapi.label_query(host.id, label_key)
            if label:
                if overwrite:
                    existing_labels.update({label_key: label.uuid})
                else:
                    raise wsme.exc.ClientSideError(
                        _("Label %s exists for host %s. Use overwrite option to assign a new value." % (
                            label_key, host.hostname)))

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
        for key, value in body.items():

            values = {
                'host_id': host.id,
                'label_key': key,
                'label_value': value
            }

            try:
                if existing_labels.get(key, None):
                    # Update the value
                    label_uuid = existing_labels.get(key)
                    new_label = pecan.request.dbapi.label_update(label_uuid, {'label_value': value})
                else:
                    new_label = pecan.request.dbapi.label_create(host_uuid, values)
                new_records.append(new_label)
            except exception.HostLabelAlreadyExists:
                # We should not be here
                raise wsme.exc.ClientSideError(_("Error creating label %s") % label_key)

        try:
            vim_api.vim_host_update(
                None,
                host_uuid,
                host.hostname,
                constants.VIM_DEFAULT_TIMEOUT_IN_SECS)
            self._apply_manifest_after_label_operation(
                host_uuid, body.keys())
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

        _check_host_locked(host, [lbl_obj.label_key])

        label_dict = {lbl_obj.label_key: None}

        try:
            pecan.request.dbapi.label_destroy(lbl_obj.uuid)
        except exception.HostLabelNotFound:
            msg = _("Delete host label failed: host %s label %s=%s"
                    % (host.hostname, lbl_obj.label_key, lbl_obj.label_value))
            raise wsme.exc.ClientSideError(msg)

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
            vim_api.vim_host_update(
                None,
                host.uuid,
                host.hostname,
                constants.VIM_DEFAULT_TIMEOUT_IN_SECS)
            self._apply_manifest_after_label_operation(
                host.uuid, [lbl_obj.label_key])
        except Exception as e:
            LOG.warn(_("No response vim_api host:%s e=%s" %
                     (host.hostname, e)))
            pass


###########
# UTILS
###########
def _check_host_locked(host, host_labels):
    if host.administrative != constants.ADMIN_LOCKED:
        # check if host has any labels which require host-lock
        labels_requiring_lock = \
            [common.LABEL_CONTROLLER,
             common.LABEL_COMPUTE_LABEL,
             common.LABEL_DISABLE_NOHZ_FULL,
             common.LABEL_OPENVSWITCH,
             common.LABEL_REMOTE_STORAGE,
             common.LABEL_SRIOVDP,
             common.LABEL_SRIOVDP_ISRDMA,
             common.LABEL_SRIOVDP_VHOSTNET,
             constants.KUBE_TOPOLOGY_MANAGER_LABEL,
             constants.KUBE_CPU_MANAGER_LABEL,
             constants.KUBE_MEMORY_MANAGER_LABEL]

        lock_required_labels = [x for x in host_labels
                                if x in labels_requiring_lock]

        if lock_required_labels:
            raise wsme.exc.ClientSideError(
                "Host %s must be locked for label(s)=%s." %
                (host.hostname, lock_required_labels))


def _case_agnostic_check(policy_value, allowed_values, policy_name):
    """
    Helper function to check if a policy value is among the allowed values,
    case-insensitively.
    """
    if policy_value.casefold() not in \
                       [allowed_value.casefold() for allowed_value in allowed_values]:
        raise wsme.exc.ClientSideError(
            _(
                "Invalid value for %s label." % policy_name))


def evaluate_case_agnostic_policy_name(policy_name, policy_value):
    """
    Enable case-agnostic policy name validation for the given policy.
    """
    if policy_name == constants.KUBE_TOPOLOGY_MANAGER_LABEL:
        _case_agnostic_check(policy_value, constants.KUBE_TOPOLOGY_MANAGER_VALUES, policy_name)
    elif policy_name == 'kube-cpu-mgr-policy' and policy_value.casefold() == 'none':
        raise wsme.exc.ClientSideError(
            _(
                "Setting kube-cpu-mgr-policy to 'none' is not supported"))
    else:
        _case_agnostic_check(policy_value, constants.KUBE_CPU_MEMORY_MANAGER_VALUES, policy_name)


def _check_if_stalld_label_modified(keys: list[str]) -> bool:
    # check for starlingx.io/stalld substring in any of the labels
    return any(constants.LABEL_STALLD in label_key for label_key in keys)


def _is_stalld_enabled(host, body: dict) -> bool:

    def _is_enabled_in_db(host) -> tuple[bool, bool]:
        # default value if missing from db
        found_in_db, stalld_enabled = False, constants.LABEL_VALUE_STALLD_DISABLED
        with suppress(exception.HostLabelNotFoundByKey):
            label_key = constants.LABEL_STALLD
            label = pecan.request.dbapi.label_query(host.id, label_key)
            stalld_enabled = label.label_value
            found_in_db = True
        return found_in_db, (stalld_enabled == constants.LABEL_VALUE_STALLD_ENABLED)

    def _is_enabled_in_body(body: dict) -> tuple[bool, bool]:
        label_key = constants.LABEL_STALLD
        found = label_key in body.keys()
        stalld_enabled = body.get(label_key, constants.LABEL_VALUE_STALLD_DISABLED)
        return found, (stalld_enabled == constants.LABEL_VALUE_STALLD_ENABLED)

    found_in_body, stalld_enabled_in_body = _is_enabled_in_body(body)
    found_in_db, stalld_enabled_in_db = _is_enabled_in_db(host)

    if found_in_body:
        # user input highest priority
        return stalld_enabled_in_body
    elif found_in_db:
        # check database
        return stalld_enabled_in_db

    # otherwise use the default value 'disabled'
    return False


def _semantic_check_stalld_cpu_list_is_not_empty(host, body: dict) -> None:
    """ Check that stalld will not be started with an empty cpu list.

    Args:
        host: host
        body (dict): dictionary of label key values being updated
    """
    keys = body.keys()
    if not _check_if_stalld_label_modified(keys):
        return None

    if not _is_stalld_enabled(host, body):
        return None

    label_key = constants.LABEL_STALLD_CPU_FUNCTIONS
    supported_values = constants.VALID_STALLD_CPU_FUNCTION_VALUES

    cpu_function = body.get(label_key, None)
    if not cpu_function:
        # default value if missing from db
        cpu_function = constants.LABEL_VALUE_CPU_DEFAULT
        with suppress(exception.HostLabelNotFoundByKey):
            label_key = constants.LABEL_STALLD_CPU_FUNCTIONS
            label = pecan.request.dbapi.label_query(host.id, label_key)
            cpu_function = label.label_value

    if cpu_function.lower() == constants.LABEL_VALUE_CPU_ALL:
        # all cpus - assume there will be at least 1 cpu on the node
        return None

    if cpu_function.lower() == constants.LABEL_VALUE_CPU_APPLICATION_ISOLATED:
        functions = {
            constants.ISOLATED_FUNCTION
        }
    elif cpu_function.lower() == constants.LABEL_VALUE_CPU_APPLICATION:
        functions = {
            constants.APPLICATION_FUNCTION,
            constants.ISOLATED_FUNCTION
        }
    else:
        # should not get here
        msg = \
            f"{host.hostname} invalid value {label_key}={cpu_function}. "\
            f"Supported values are {supported_values}"
        LOG.error(msg)
        raise wsme.exc.ClientSideError(_(msg))

    cpu_count = 0
    for cpu in pecan.request.dbapi.icpu_get_by_ihost(host.uuid):
        if cpu.allocated_function in functions or not functions:
            cpu_count += 1
    if cpu_count == 0:
        msg = \
            f"{host.hostname} stalld cpu list empty,"\
            f" update cpu core assignments for {functions}"
        raise wsme.exc.ClientSideError(_(msg))


def _semantic_check_custom_stalld_label_format(host, body: dict) -> None:
    """Check that custom stalld labels have the correct format
        starlingx.io/stalld.<paramater>=<value>
    """
    keys = body.keys()
    stalld_labels = [label for label in keys if constants.LABEL_STALLD in label]
    for label_key in stalld_labels:
        # skip supported labels they are validated elsewhere
        if label_key in constants.SUPPORTED_STALLD_LABELS:
            continue
        if not re.match(constants.REGEX_STALLD_CUSTOM_LABEL, label_key):
            msg = \
                f"{host.hostname} '{label_key}' invalid format,"\
                f" format example 'starlingx.io/stalld.<paramater>'"
            raise wsme.exc.ClientSideError(_(msg))


def _semantic_check_stalld_labels(host, body: dict) -> None:
    """
    Perform semantic checks to ensure the stalld labels have supported values
    """
    keys = body.keys()
    stalld_labels = [label for label in keys if constants.LABEL_STALLD in label]
    if not stalld_labels:
        return None

    if constants.WORKER not in host.subfunctions:
        msg = f"{stalld_labels} can only be modified on worker nodes."
        raise wsme.exc.ClientSideError(_(msg))

    # tuple format ( label_key, supported_values)
    label_tuples = [
        # starlingx.io/stalld=[enabled|disabled]
        (constants.LABEL_STALLD,
         constants.VALID_STALLD_VALUES),
        # starlingx.io/stalld_cpu_functions=[all|application|application_isolated]
        (constants.LABEL_STALLD_CPU_FUNCTIONS,
         constants.VALID_STALLD_CPU_FUNCTION_VALUES)]

    for (label_key, supported_values) in label_tuples:
        label_value = body.get(label_key, None)
        if label_value:
            label_value = label_value.lower()
        if label_value and label_value not in supported_values:
            msg = \
                f"{host.hostname} invalid value {label_key}={label_value}. "\
                f"Supported values are {supported_values}"
            raise wsme.exc.ClientSideError(_(msg))

    _semantic_check_stalld_cpu_list_is_not_empty(host, body)
    _semantic_check_custom_stalld_label_format(host, body)


def _semantic_check_worker_labels(body):
    """
    Perform semantic checks to ensure the worker labels are valid.
    """
    for label_key, label_value in body.items():
        if label_key == constants.KUBE_POWER_MANAGER_LABEL:
            if label_value != constants.KUBE_POWER_MANAGER_VALUE:
                raise wsme.exc.ClientSideError(
                    _(
                        "Invalid value for %s label." % constants.KUBE_POWER_MANAGER_LABEL))
        elif label_key in [constants.KUBE_MEMORY_MANAGER_LABEL, constants.KUBE_CPU_MANAGER_LABEL,
                           constants.KUBE_TOPOLOGY_MANAGER_LABEL]:
            evaluate_case_agnostic_policy_name(label_key, label_value)


def _get_system_enabled_k8s_plugins():
    if not os.path.isfile(constants.ENABLED_KUBE_PLUGINS):
        return None

    with open(constants.ENABLED_KUBE_PLUGINS) as f:
        return json.loads(f.read())


def _semantic_check_intel_gpu_plugins_labels(host):
    pci_devices = pecan.request.dbapi.pci_device_get_by_host(host.id)
    for pci_device in pci_devices:
        if ("VGA" in pci_device.pclass and pci_device.driver == "i915"):
            return

    raise wsme.exc.ClientSideError("Host %s does not support Intel GPU device plugin." % (host.hostname))


def _semantic_check_k8s_plugins_labels(host, body):
    """
    Perform hardware checks to ensure k8s plugins labels are valid on particular node.
    """
    plugins = _get_system_enabled_k8s_plugins()
    if plugins is None:
        return

    for label_key, label_value in body.items():
        label = label_key + "=" + label_value
        if label in plugins.values():
            if label == constants.KUBE_INTEL_GPU_DEVICE_PLUGIN_LABEL:
                _semantic_check_intel_gpu_plugins_labels(host)
