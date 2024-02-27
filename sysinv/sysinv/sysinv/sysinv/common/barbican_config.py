#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import utils
from sysinv.conductor import keystone_listener
from sysinv.puppet import puppet


BARBICAN_CONFIG_FILEPATH = '/etc/barbican/barbican.conf'
GUNICORN_SCRIPT_FILEPATH = '/etc/barbican/gunicorn-config.py'


def update_gunicorn_bind(bind):
    with open(GUNICORN_SCRIPT_FILEPATH, 'r') as file:
        lines = file.readlines()
    for i, line in enumerate(lines):
        if 'bind = ' in line:
            lines[i] = f"bind = '{bind}'\n"
            break
    with open(GUNICORN_SCRIPT_FILEPATH, 'w') as file:
        file.writelines(lines)


@puppet.puppet_context
def barbican_bootstrap_config(puppet_operator: puppet.PuppetOperator):
    """Apply the barbican config changes since initial puppet apply"""
    puppet_plugins = puppet_operator.puppet_plugins
    puppet_plugins_dict = {plugin.name[4:]: plugin for plugin in puppet_plugins}
    barbican_plugin = puppet_plugins_dict['barbican'].obj

    host = (constants.CONTROLLER_FQDN
            if utils.is_fqdn_ready_to_use()
            else None)

    sql_connection = barbican_plugin._format_database_connection(
        barbican_plugin.SERVICE_NAME
    )
    transport_url = keystone_listener.get_transport_url()
    bind_host = utils.format_url_address(
        barbican_plugin._get_address_by_name(
            constants.CONTROLLER_HOSTNAME, constants.NETWORK_TYPE_MGMT
        ).address
    )
    region_name = barbican_plugin._get_service_region_name(
        barbican_plugin.SERVICE_NAME
    )
    auth_url = barbican_plugin._keystone_identity_uri(host)
    database_connection = sql_connection.replace('postgresql://', 'postgresql+psycopg2://')
    service_port = barbican_plugin.SERVICE_PORT
    gunicorn_config_bind = f'{bind_host}:{service_port}'

    values_to_update = [
        {'section': 'DEFAULT', 'key': 'sql_connection', 'value': sql_connection},
        {'section': 'DEFAULT', 'key': 'transport_url', 'value': transport_url},
        {'section': 'DEFAULT', 'key': 'bind_host', 'value': bind_host},
        {'section': 'keystone_authtoken', 'key': 'region_name', 'value': region_name},
        {'section': 'keystone_authtoken', 'key': 'auth_url', 'value': auth_url},
        {'section': 'database', 'key': 'connection', 'value': database_connection},
    ]
    utils.update_config_file(BARBICAN_CONFIG_FILEPATH, values_to_update)
    update_gunicorn_bind(gunicorn_config_bind)
