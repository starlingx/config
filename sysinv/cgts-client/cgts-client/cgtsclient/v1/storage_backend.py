#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient.common import constants
from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ceph_mon as ceph_mon_utils
from cgtsclient.v1 import storage_ceph  # noqa
from cgtsclient.v1 import storage_external  # noqa
from cgtsclient.v1 import storage_file  # noqa
from cgtsclient.v1 import storage_lvm  # noqa
from oslo_serialization import jsonutils

CREATION_ATTRIBUTES = ['forisystemid', 'backend']


class StorageBackend(base.Resource):
    def __repr__(self):
        return "<storage_backends %s>" % self._info


class StorageBackendManager(base.Manager):
    resource_class = StorageBackend

    @staticmethod
    def _path(id=None):
        return '/v1/storage_backend/%s' % id if id else '/v1/storage_backend'

    def list(self):
        return self._list(self._path(), "storage_backends")

    def get(self, storage_backend_id):
        try:
            return self._list(self._path(storage_backend_id))[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
                if key == 'services':
                    new[key] = [value]
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(self._path(), new)

    def update(self, storage_backend_id, patch):
        # path = '/v1/storage_backend/%s' % storage_backend_id
        return self._update(self._path(storage_backend_id), patch)

    def delete(self, storage_backend_id):
        # path = '/v1/storage_backend/%s' % storage_backend_id
        return self._delete(self._path(storage_backend_id))

    def usage(self):
        return self._list(self._path("usage"))


def has_backend(cc, target):
    backend_list = cc.storage_backend.list()
    for backend in backend_list:
        if backend.backend == target:
            return True
    return False


def has_backend_configured(cc, target):
    backend_list = cc.storage_backend.list()
    for backend in backend_list:
        if backend.state == constants.SB_STATE_CONFIGURED and \
                backend.backend == target:
            return True
    return False


# BACKEND SHOW

def _show_backend(backend_obj, extra_fields=None):
    fields = ['backend', 'name', 'state', 'task', 'services',
              'capabilities']
    fields += extra_fields
    fields += ['created_at', 'updated_at']

    data = [(f, getattr(backend_obj, f)) for f in fields]
    utils.print_tuple_list(data)


def backend_show(cc, backend_name_or_uuid):
    db_backends = cc.storage_backend.list()
    db_backend = next((b for b in db_backends
                       if ((b.name == backend_name_or_uuid) or
                           (b.uuid == backend_name_or_uuid))),
                      None)
    if not db_backend:
        raise exc.CommandError("Backend %s is not found."
                               % backend_name_or_uuid)

    backend_client = getattr(cc, 'storage_' + db_backend.backend)
    backend_obj = backend_client.get(db_backend.uuid)
    extra_fields = getattr(eval('storage_' + db_backend.backend),
                           'DISPLAY_ATTRIBUTES')
    _show_backend(backend_obj, extra_fields)


# BACKEND ADD


def _display_next_steps():
    print "\nSystem configuration has changed.\nPlease follow the " \
        "administrator guide to complete configuring the system.\n"


def backend_add(cc, backend, args):

    # add ceph mons to controllers
    if backend == constants.SB_TYPE_CEPH:
        ceph_mon_utils.ceph_mon_add(cc, args)

    # allowed storage_backend fields
    allowed_fields = ['name', 'services', 'confirmed']

    # allowed backend specific backends
    if backend in constants.SB_SUPPORTED:
        backend_attrs = getattr(eval('storage_' + backend),
                                'CREATION_ATTRIBUTES')
        allowed_fields = list(set(allowed_fields + backend_attrs))

    # filter the args passed to backend creation
    fields = dict((k, v) for (k, v) in vars(args).items()
                  if k in allowed_fields and not (v is None))

    # Load command line attributes to pass to backend creation
    # REST API will ignore the cruft
    attr_dict = dict(s.split('=') for s in vars(args).get('attributes', [])
                     if '=' in s)

    fields['capabilities'] = {}
    for k, v in attr_dict.iteritems():
        fields['capabilities'][k] = v

    if not fields['capabilities']:
        del fields['capabilities']

    backend_client = getattr(cc, 'storage_' + backend)
    backend_client.create(**fields)
    _display_next_steps()


# BACKEND MODIFY

def backend_modify(cc, args):

    db_backends = cc.storage_backend.list()
    backend_entry = next(
        (b for b in db_backends
         if ((b.name == args.backend_name_or_uuid) or
             (b.uuid == args.backend_name_or_uuid))),
        None)
    if not backend_entry:
        raise exc.CommandError("Backend %s is not found."
                               % args.backend_name_or_uuid)

    # filter out arg noise: Only relevant fields
    allowed_fields = ['services']

    # filter the args.passed to backend creation
    fields = dict((k, v) for (k, v) in vars(args).items()
                  if k in allowed_fields and not (v is None))

    # Load command line attributes to pass to backend modify
    # REST API will ignore the cruft
    attr_dict = dict(s.split('=') for s in vars(args).get('attributes', [])
                     if '=' in s)

    # non-capability, backend specific attributes
    backend = backend_entry.backend
    if backend in constants.SB_SUPPORTED:
        backend_attrs = getattr(eval('storage_' + backend),
                                'PATCH_ATTRIBUTES')
        allowed_fields += backend_attrs
        for k, v in attr_dict.iteritems():
            if k in backend_attrs:
                fields[k] = v

    # Move tha rest of the attributes to the capabilities, used for hiera data
    # overrides
    capabilities = {}
    for k, v in attr_dict.iteritems():
        if k not in allowed_fields:
            capabilities[k] = v

    patch = []
    patch = utils.dict_to_patch(fields)
    patch.append({'path': '/capabilities',
                  'value': jsonutils.dumps(capabilities),
                  'op': 'replace'})

    try:
        backend_client = getattr(cc, 'storage_' + backend)
        backend_entry = backend_client.update(backend_entry.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('Storage %s not found: %s'
                               % (backend,
                                  backend_entry.uuid))

    backend_show(cc, backend_entry.uuid)


# BACKEND DELETE

def backend_delete(cc, backend_name_or_uuid):
    db_backends = cc.storage_backend.list()
    db_backend = next((b for b in db_backends
                       if ((b.name == backend_name_or_uuid) or
                           (b.uuid == backend_name_or_uuid))),
                      None)
    if not db_backend:
        raise exc.CommandError("Backend %s is not found."
                               % backend_name_or_uuid)

    backend_client = getattr(cc, 'storage_' + db_backend.backend)
    backend_client.delete(db_backend.uuid)
