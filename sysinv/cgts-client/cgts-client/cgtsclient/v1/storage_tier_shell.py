#
# Copyright (c) 2017-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import cluster as cluster_utils
from cgtsclient.v1 import storage_tier as storage_tier_utils


def _print_tier_show(tier):
    fields = ['uuid', 'name', 'type', 'status', 'backend_uuid', 'cluster_uuid',
              'stors', 'created_at', 'updated_at']
    labels = ['uuid', 'name', 'type', 'status', 'backend_uuid', 'cluster_uuid',
              'OSDs', 'created_at', 'updated_at']
    data = [(f, getattr(tier, f, '')) for f in fields]
    utils.print_tuple_list(data, labels)


@utils.arg('cluster_or_uuid',
           metavar='<cluster name or uuid>',
           help="Name or UUID of cluster")
@utils.arg('storage_tier_or_uuid',
           metavar='<storage tier name or uuid>',
           help="Name or UUID of the storage tier")
def do_storage_tier_show(cc, args):
    """Show storage tier attributes."""

    cluster = cluster_utils._find_cluster(cc, args.cluster_or_uuid)
    tier = storage_tier_utils._find_storage_tier(cc, cluster,
                                                 args.storage_tier_or_uuid)
    _print_tier_show(tier)


@utils.arg('cluster_or_uuid',
           metavar='<cluster name or uuid>',
           help="Name or UUID of cluster")
def do_storage_tier_list(cc, args):
    """List storage tiers."""

    cluster = cluster_utils._find_cluster(cc, args.cluster_or_uuid)
    tiers = cc.storage_tier.list(cluster.uuid)

    fields = ['uuid', 'name', 'status', 'backend_uuid']
    labels = ['uuid', 'name', 'status', 'backend_using']

    utils.print_list(tiers, fields, labels, sortby=1)


@utils.arg('cluster_or_uuid',
           metavar='<cluster name or uuid>',
           help="Name or UUID of cluster to which the storage tier will be "
           "added. [REQUIRED]")
@utils.arg('storage_tier_name',
           metavar='<storage tier name>',
           help="Name of the storage tier to add to the cluster. [REQUIRED]")
def do_storage_tier_add(cc, args):
    """Add a storage tier to a disk of a specified cluster."""

    # Get the cluster object
    cluster = cluster_utils._find_cluster(cc, args.cluster_or_uuid)

    # default values
    fields = {'cluster_uuid': cluster.uuid,
              'name': args.storage_tier_name}

    try:
        tier = cc.storage_tier.create(**fields)
    except exc.HTTPNotFound:
        raise exc.CommandError('Storage tier create failed: cluster %s: '
                               'fields %s' % (args.cluster_or_uuid, fields))

    tier_uuid = getattr(tier, 'uuid', '')
    try:
        tier = cc.storage_tier.get(tier_uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created storage_tier UUID not found: '
                               '%s' % tier_uuid)

    _print_tier_show(tier)


@utils.arg('cluster_or_uuid',
           metavar='<cluster name or uuid>',
           help="Name or UUID of cluster to which the storage tier will be "
           "deleted. [REQUIRED]")
@utils.arg('storage_tier_or_uuid',
           metavar='<storage tier name or uuid>',
           help="Name of the storage tier to delete from the cluster. "
           "[REQUIRED]")
def do_storage_tier_delete(cc, args):
    """Delete a storage tier."""

    # Get the cluster object
    cluster = cluster_utils._find_cluster(cc, args.cluster_or_uuid)
    tier = storage_tier_utils._find_storage_tier(cc, cluster,
                                                 args.storage_tier_or_uuid)
    try:
        cc.storage_tier.delete(tier.uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Storage Tier delete failed for cluster %s: '
                               ' %s' % (cluster.name,
                                        args.storage_tier_or_uuid))


@utils.arg('cluster_or_uuid',
           metavar='<cluster name or uuid>',
           help="Name or UUID of cluster to which the storage tier will be "
           "added. [REQUIRED]")
@utils.arg('storage_tier_or_uuid',
           metavar='<storage tier name or uuid>',
           help="Name of the storage tier to delete from the cluster. "
           "[REQUIRED]")
@utils.arg('-n', '--name',
           metavar='<storage tier name>',
           help=("Update the name of the storage tier"))
def do_storage_tier_modify(cc, args):
    """Modify the attributes of a storage tier."""

    # Get all the fields from the command arguments
    field_list = ['name']
    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in field_list and not (v is None))

    if not user_specified_fields:
        raise exc.CommandError('No update parameters specified, '
                               'storage tier is unchanged.')

    # Get the cluster object
    cluster = cluster_utils._find_cluster(cc, args.cluster_or_uuid)

    # Get the storage tier
    tier = storage_tier_utils._find_storage_tier(cc, cluster,
                                                 args.storage_tier_or_uuid)
    patch = []
    for (k, v) in user_specified_fields.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})

    # Update the storage tier attributes
    try:
        updated_tier = cc.storage_tier.update(tier.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError(
            "ERROR: Storage tier update failed: "
            "cluster %s tier %s : update %s"
            % (args.cluster_or_uuid, args.storage_tier_or_uuid, patch))

    _print_tier_show(updated_tier)
