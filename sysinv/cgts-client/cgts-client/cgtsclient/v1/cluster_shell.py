#
# Copyright (c) 2016-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import cluster as cluster_utils
import os


def _peer_formatter(values):
    result = []
    for value in values:
        name = value.get('name')
        hosts = value.get('hosts')
        hosts = [x.decode('unicode_escape').encode('ascii', 'ignore')
                 for x in hosts]
        result.append(str(name) + ":" + str(hosts))

    return result


def _peer_pool_formatter(pool):
    return _peer_formatter(pool.peers)


def _tier_formatter(values):
    result = []
    for value in values:
        name = value.get('name')
        status = value.get('status')
        result.append("%s (%s)" % (str(name), str(status)))

    return result


def _print_cluster_show(obj):
    fields = ['uuid', 'cluster_uuid', 'type', 'name', 'peers', 'tiers', 'deployment_model']
    labels = ['uuid', 'cluster_uuid', 'type', 'name', 'replication_groups',
              'storage_tiers', 'deployment_model']
    data = [(f, getattr(obj, f, '')) for f in fields]
    utils.print_tuple_list(
        data, labels, formatters={'peers': _peer_formatter,
                                  'tiers': _tier_formatter})


@utils.arg('cluster_or_uuid',
           metavar='<cluster_or_uuid>',
           help="Cluster name or UUID")
def do_cluster_show(cc, args):
    """Show Cluster attributes."""
    cluster = cluster_utils._find_cluster(cc, args.cluster_or_uuid)
    cluster_obj = cc.cluster.get(cluster.uuid)
    _print_cluster_show(cluster_obj)


def do_cluster_list(cc, args):
    """List Clusters."""
    clusters = cc.cluster.list()

    fields = ['uuid', 'cluster_uuid', 'type', 'name', 'deployment_model']
    utils.print_list(clusters, fields, fields, sortby=1)


# The following are for internal testing only.
if os.path.exists('/var/run/.sysinv_running_in_lab'):
    def _get_peer_tuples(data):
        """
        Split the peers field from a comma separated list of name-status to a
        real list of (name, status) tuples.
        """
        peers = []
        for r in data['peers'].split(',') or []:
            name, status = r.split('~')
            peers.append((name, status))
        return peers

    @utils.arg('name',
               metavar='<name>',
               help='Name of the Cluster [REQUIRED]')
    @utils.arg('--peers',
               metavar='<peers>',
               help='The inclusive range of peers to allocate '
               "<name~status>[,<name~status>,...]")
    def do_cluster_add(cc, args):
        """Add Cluster."""

        field_list = ['name', 'peers']

        # Prune input fields down to required/expected values
        data = dict((k, v) for (k, v) in vars(args).items()
                    if k in field_list and not (v is None))

        if 'peers' in data:
            data['peers'] = _get_peer_tuples(data)

        cluster = cc.cluster.create(**data)
        uuid = getattr(cluster, 'uuid', '')
        try:
            cluster = cc.cluster.get(uuid)
        except exc.HTTPNotFound:
            raise exc.CommandError('Created cluster UUID not found: %s' % uuid)
        _print_cluster_show(cluster)

    @utils.arg('cluster_uuid',
               metavar='<cluster uuid>',
               help="UUID of the Cluster")
    @utils.arg('--name',
               metavar='<name>',
               help="Name of the Cluster")
    @utils.arg('--peers',
               metavar='<peers>',
               help="The inclusive range of peers to allocate "
               "<name~status>[,<name~status>,...]")
    def do_cluster_modify(cc, args):
        """Modify Cluster attributes."""

        rwfields = ['name', 'peers']

        data = dict((k, v) for (k, v) in vars(args).items()
                    if k in rwfields and not (v is None))

        if 'peers' in data:
            data['peers'] = _get_peer_tuples(data)

        patch = []
        for (k, v) in data.items():
            patch.append({'op': 'replace', 'path': '/' + k, 'value': v})

        cluster = cc.cluster.update(args.cluster_uuid, patch)
        _print_cluster_show(cluster)

    @utils.arg('cluster_uuid',
               metavar='<cluster uuid>',
               help="UUID of the Cluster")
    def do_cluster_delete(cc, args):
        """Delete a Cluster."""
        cc.cluster.delete(args.cluster_uuid)
        print('Deleted cluster: %s' % args.cluster_uuid)
