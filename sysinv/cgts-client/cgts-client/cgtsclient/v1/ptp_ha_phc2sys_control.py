########################################################################
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

import socket

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ptp_instance as ptp_instance_utils


def _get_phc2sys_com_socket(cc, nameoruuid):
    # Get the ha_phc2sys_com_socket parameter for the instance
    phc2sys_com_socket = None
    phc2sys_instance = ptp_instance_utils._find_ptp_instance(cc, nameoruuid)
    phc2sys_instance_name = phc2sys_instance.name

    if phc2sys_instance.service != 'phc2sys':
        raise exc.CommandError(
            'Instance %s is not a phc2sys instance' % phc2sys_instance_name)
    elif 'ha_enabled=1' not in phc2sys_instance.parameters:
        raise exc.CommandError(
            'Instance %s is not enabled for HA phc2sys' % phc2sys_instance_name)

    for parameter in phc2sys_instance.parameters:
        if parameter.split("=")[0] == 'ha_phc2sys_com_socket':
            phc2sys_com_socket = parameter.split("=")[-1]

    if phc2sys_com_socket is None:
        raise exc.CommandError('Instance %s does not have a ha_phc2sys_com_socket path configured'
                               % phc2sys_instance_name)
    return phc2sys_com_socket


def _run_phc2sys_command(phc2sys_com_socket, command):
    try:
        client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_socket.connect(phc2sys_com_socket)
        client_socket.send(command.encode())
        response = client_socket.recv(1024)
        response = response.decode()
        if response == "None":
            response = None
        return response
    except ConnectionRefusedError as err:
        raise exc.CommunicationError("Error connecting to phc2sys socket %s: %s"
                                     % (phc2sys_com_socket, err))
    except FileNotFoundError as err:
        raise exc.CommandError("Error connecting to phc2sys socket %s: %s"
                               % (phc2sys_com_socket, err))
    except PermissionError:
        raise exc.CommandError(
            "Permission denied connecting to socket, try using 'sudo -E'")
    finally:
        if hasattr(client_socket, 'close'):
            client_socket.close()


@utils.arg('nameoruuid',
           metavar='<name or UUID',
           help="Name or UUID of HA enabled phc2sys instance")
@utils.arg('phc2sys_ha_command',
           metavar='<phc2sys control command>',
           choices=['clock source', 'forced lock', 'status'])
def do_phc2sys_ha_query(cc, args):
    phc2sys_com_socket = _get_phc2sys_com_socket(cc, args.nameoruuid)
    response = _run_phc2sys_command(
        phc2sys_com_socket, args.phc2sys_ha_command)
    print(response)


@utils.arg('nameoruuid',
           metavar='<name or UUID',
           help="Name or UUID of HA enabled phc2sys instance")
@utils.arg('interface',
           metavar='<phc2sys interface>',
           help="Name of a phc2sys NIC interface")
def do_phc2sys_ha_force_lock(cc, args):
    phc2sys_com_socket = _get_phc2sys_com_socket(cc, args.nameoruuid)
    # The interface name will be rejected by phc2sys if it is not valid
    command = 'enable lock ' + args.interface
    response = _run_phc2sys_command(phc2sys_com_socket, command)
    print(response)


@utils.arg('nameoruuid',
           metavar='<name or UUID',
           help="Name or UUID of HA enabled phc2sys instance")
def do_phc2sys_ha_disable_lock(cc, args):
    phc2sys_com_socket = _get_phc2sys_com_socket(cc, args.nameoruuid)
    command = 'disable lock'
    response = _run_phc2sys_command(phc2sys_com_socket, command)
    print(response)


@utils.arg('nameoruuid',
           metavar='<name or UUID',
           help="Name or UUID of HA enabled phc2sys instance")
@utils.arg('interface',
           metavar='<phc2sys interface>',
           help="Name of a phc2sys NIC interface")
def do_phc2sys_ha_disable_source(cc, args):
    phc2sys_com_socket = _get_phc2sys_com_socket(cc, args.nameoruuid)
    # The interface name will be rejected by phc2sys if it is not valid
    command = 'disable source ' + args.interface
    response = _run_phc2sys_command(phc2sys_com_socket, command)
    print(response)


@utils.arg('nameoruuid',
           metavar='<name or UUID',
           help="Name or UUID of HA enabled phc2sys instance")
@utils.arg('interface',
           metavar='<phc2sys interface>',
           help="Name of a phc2sys NIC interface")
def do_phc2sys_ha_enable_source(cc, args):
    phc2sys_com_socket = _get_phc2sys_com_socket(cc, args.nameoruuid)
    command = 'enable source ' + args.interface
    response = _run_phc2sys_command(phc2sys_com_socket, command)
    print(response)
