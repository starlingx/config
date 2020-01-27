#
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

from cgtsclient.common import constants
from cgtsclient.common import utils
from cgtsclient import exc
from six.moves import input


def _print_isystem_show(isystem):
    fields = ['name', 'system_type', 'system_mode', 'description', 'location',
              'contact', 'timezone', 'software_version', 'uuid',
              'created_at', 'updated_at', 'region_name', 'service_project_name',
              'security_feature']
    if isystem.capabilities.get('region_config'):
        fields.append('shared_services')
        setattr(isystem, 'shared_services',
                isystem.capabilities.get('shared_services'))
    if isystem.capabilities.get('sdn_enabled') is not None:
        fields.append('sdn_enabled')
        setattr(isystem, 'sdn_enabled',
                isystem.capabilities.get('sdn_enabled'))

    if isystem.capabilities.get('https_enabled') is not None:
        fields.append('https_enabled')
        setattr(isystem, 'https_enabled',
                isystem.capabilities.get('https_enabled'))

    if isystem.distributed_cloud_role:
        fields.append('distributed_cloud_role')
        setattr(isystem, 'distributed_cloud_role',
                isystem.distributed_cloud_role)

    if isystem.capabilities.get('vswitch_type') is not None:
        fields.append('vswitch_type')
        setattr(isystem, 'vswitch_type',
                isystem.capabilities.get('vswitch_type'))

    data = dict(list([(f, getattr(isystem, f, '')) for f in fields]))
    utils.print_dict(data)


def do_show(cc, args):
    """Show system attributes."""
    isystems = cc.isystem.list()
    _print_isystem_show(isystems[0])


@utils.arg('-n', '--name',
           metavar='<name>',
           help='The name of the system')
@utils.arg('-s', '--sdn_enabled',
           metavar='<sdn_enabled>',
           choices=['true', 'false', 'True', 'False'],
           help='The SDN enabled or disabled flag')
@utils.arg('-t', '--timezone',
           metavar='<timezone>',
           help='The timezone of the system')
@utils.arg('-m', '--system_mode',
           metavar='<system_mode>',
           help='The system mode of the system')
@utils.arg('-d', '--description',
           metavar='<description>',
           help='The description of the system')
@utils.arg('-c', '--contact',
           metavar='<contact>',
           help='The contact of the system')
@utils.arg('-l', '--location',
           metavar='<location>',
           help='The location of the system')
@utils.arg('-p', '--https_enabled',
           metavar='<https_enabled>',
           choices=['true', 'false', 'True', 'False'],
           help='The HTTPS enabled or disabled flag')
@utils.arg('-v', '--vswitch_type',
           metavar='<vswitch_type>',
           help='The vswitch type for the system')
@utils.arg('-S', '--security_feature',
           metavar='<security_feature>',
           choices=['spectre_meltdown_v1', 'spectre_meltdown_all'],
           help='Use spectre_meltdown_v1 to add linux bootargs "nopti '
                'nospectre_v2 nospectre_v1", or spectre_meltdown_all to not '
                'add any mitigation disabling bootargs')
def do_modify(cc, args):
    """Modify system attributes."""
    isystems = cc.isystem.list()
    isystem = isystems[0]

    # Validate system_mode value if its passed in
    if args.system_mode is not None:
        system_mode_options = [constants.SYSTEM_MODE_DUPLEX,
                               constants.SYSTEM_MODE_DUPLEX_DIRECT]

        if isystem.system_type != constants.TS_AIO:
            raise exc.CommandError("system_mode can only be modified on an "
                                   "AIO system")
        if isystem.system_mode == constants.SYSTEM_MODE_SIMPLEX:
            raise exc.CommandError("system_mode can not be modified if it is "
                                   "currently set to '%s'" %
                                   constants.SYSTEM_MODE_SIMPLEX)
        mode = args.system_mode
        if isystem.system_mode == mode:
            raise exc.CommandError("system_mode value already set to '%s'" %
                                   mode)
        if mode not in system_mode_options:
            raise exc.CommandError("Invalid value for system_mode, it can only"
                                   " be modified to '%s' or '%s'" %
                                   (constants.SYSTEM_MODE_DUPLEX,
                                    constants.SYSTEM_MODE_DUPLEX_DIRECT))

        mode_text = "duplex"
        if mode == constants.SYSTEM_MODE_DUPLEX_DIRECT:
            mode_text = "direct connect"

        warning_message = (
            '\n'
            'The system will be reconfigured to AIO %s.\n'
            'The controllers need to be physically accessed to reconnect '
            'network cables. Please check the admin guide for prerequisites '
            'before continue.\n'
            'Are you sure you want to continue [yes/N]: ' % mode_text)

        confirm = input(warning_message)
        if confirm != 'yes':
            print("Operation cancelled.")
            return
        print('Please follow the admin guide to complete the reconfiguration.')

    field_list = ['name', 'system_mode', 'description', 'location', 'contact',
                  'timezone', 'sdn_enabled', 'https_enabled', 'vswitch_type', 'security_feature']

    # use field list as filter
    user_fields = dict((k, v) for (k, v) in vars(args).items()
                       if k in field_list and not (v is None))
    configured_fields = isystem.__dict__
    configured_fields.update(user_fields)

    print_https_warning = False

    patch = []
    for (k, v) in user_fields.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})

        if k == "https_enabled" and v == "true":
            print_https_warning = True

    try:
        isystem = cc.isystem.update(isystem.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('system not found: %s' % isystem.uuid)
    _print_isystem_show(isystem)

    if print_https_warning:
        print("HTTPS enabled with a self-signed certificate.\nThis should be "
              "changed to a CA-signed certificate with 'system certificate-install'. ")
