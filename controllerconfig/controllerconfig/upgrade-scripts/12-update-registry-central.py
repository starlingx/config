#!/usr/bin/python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import os
import sys
import subprocess
import logging as LOG
import psycopg2
from netaddr import valid_ipv4
from netaddr import valid_ipv6
from cgtsclient import client as cgts_client
from sysinv.common import constants as sysinv_constants

DEFAULT_POSTGRES_PORT = 5432
LOG_FILE = "/var/log/software.log"


# CgtsClient class to handle API interactions
class CgtsClient(object):
    SYSINV_API_VERSION = 1

    def __init__(self):
        self.conf = {}
        self._sysinv = None

        # Loading credentials and configurations from environment variables
        # typically set in OpenStack
        source_command = 'source /etc/platform/openrc && env'

        with open(os.devnull, "w") as fnull:
            proc = subprocess.Popen(
                ['bash', '-c', source_command],
                stdout=subprocess.PIPE, stderr=fnull,
                universal_newlines=True)

        # Strip the configurations starts with 'OS_' and change
        # the value to lower
        for line in proc.stdout:
            key, _, value = line.partition("=")
            if key.startswith('OS_'):
                self.conf[key[3:].lower()] = value.strip()

        proc.communicate()

    @property
    def sysinv(self):
        if not self._sysinv:
            self._sysinv = cgts_client.get_client(
                self.SYSINV_API_VERSION,
                os_username=self.conf['username'],
                os_password=self.conf['password'],
                os_auth_url=self.conf['auth_url'],
                os_project_name=self.conf['project_name'],
                os_project_domain_name=self.conf['project_domain_name'],
                os_user_domain_name=self.conf['user_domain_name'],
                os_region_name=self.conf['region_name'],
                os_service_type='platform',
                os_endpoint_type='internal')
        return self._sysinv


def main():
    action = None
    from_release = None
    to_release = None
    postgres_port = DEFAULT_POSTGRES_PORT
    arg = 1

    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            # optional port parameter for USM upgrade
            postgres_port = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    LOG.basicConfig(filename=LOG_FILE, format=log_format, level=LOG.INFO,
                    datefmt="%FT%T")

    LOG.info("%s invoked from_release = %s to_release = %s action = %s"
             % (sys.argv[0], from_release, to_release, action))

    if action == "activate" and from_release == "24.09":
        LOG.info("Create service parameter dns host record "
                 "for registry.central")

        try:
            client = CgtsClient()
            virtual_system = check_virtual_system(client)

            floating_address_id = get_floating_sc_address_id(
                postgres_port, virtual_system
            )
            if not floating_address_id:
                LOG.info("System controller address ID not found, exiting.")
                return 0

            registry_central_ip = get_address_by_id(
                postgres_port, floating_address_id
            )
            if not registry_central_ip:
                LOG.info("System controller address not found, exiting.")
                return 0

            if virtual_system:
                registry_local_ip = get_controller_mgmt_address(postgres_port)
                update_dns_registry(
                    client, registry_central_ip, registry_local_ip)
            else:
                update_dns_registry(client, registry_central_ip)

            if not check_dns_resolution(registry_central_ip):
                return 1

        except Exception as ex:
            LOG.exception("Error: %s" % ex)
            print(ex)
            return 1

    return 0


def update_dns_registry(client, registry_central_ip, registry_local_ip=None):
    try:
        parameters = client.sysinv.service_parameter.list()
        for param in parameters:
            if param.name in ['registry.central', 'registry.local']:
                client.sysinv.service_parameter.delete(param.uuid)
                LOG.info("Deleted existing DNS host record: %s" % param.name)

        values = {
            'service': sysinv_constants.SERVICE_TYPE_DNS,
            'section': (
                sysinv_constants.SERVICE_PARAM_SECTION_DNS_HOST_RECORD
            ),
            'personality': None,
            'resource': None,
            'parameters': {
                'registry.central':
                    "registry.central,%s" % registry_central_ip
            }
        }

        if registry_local_ip:
            values['parameters']['registry.local'] = (
                "registry.local,%s" % registry_local_ip
            )

        client.sysinv.service_parameter.create(**values)
        LOG.info("DNS host records for registry created successfully.")

    except Exception as e:
        LOG.exception(
            "Failed to update DNS records via sysinv client: %s" % e)
        raise


def check_virtual_system(client):
    parameters = client.sysinv.service_parameter.list()

    for parameter in parameters:
        if (parameter.name ==
                sysinv_constants.SERVICE_PARAM_NAME_PLAT_CONFIG_VIRTUAL):
            return True

    return False


def get_floating_sc_address_id(postgres_port, virtual_system):
    if virtual_system:
        query = (
            "SELECT floating_address_id "
            "FROM address_pools "
            "WHERE name = 'system-controller-subnet';"
        )
    else:
        query = (
            "SELECT floating_address_id "
            "FROM address_pools "
            "WHERE name = 'system-controller-oam-subnet';"
        )

    try:
        res = db_query(postgres_port, query)
        if res:
            return res
        else:
            return None
    except Exception as e:
        LOG.exception("Failed to get floating_address_id: %s" % e)
        raise


def get_controller_mgmt_address(postgres_port):
    query = "SELECT address FROM addresses WHERE name = 'controller-mgmt';"
    try:
        res = db_query(postgres_port, query)
        if res:
            return res
        else:
            return None
    except Exception as e:
        LOG.exception("Failed to fetch controller-mgmt address: %s" % e)
        raise


def get_address_by_id(postgres_port, floating_address_id):
    query = (
        "SELECT address FROM addresses WHERE id = %s;" %
        floating_address_id
    )
    try:
        res = db_query(postgres_port, query)
        if res:
            return res
        else:
            return None
    except Exception as e:
        LOG.exception("Failed to fetch address: %s" % e)
        raise


def get_db_credentials():
    import re
    import configparser

    configparser = configparser.ConfigParser()
    configparser.read('/etc/sysinv/sysinv.conf')
    conn_string = configparser['database']['connection']
    match = re.match(r'postgresql\+psycopg2://([^:]+):([^@]+)@', conn_string)
    if match:
        username = match.group(1)
        password = match.group(2)
        return username, password

    LOG.error("Failed to get database credentials from sysinv.conf")
    return None, None


def db_query(postgres_port, query):
    username, password = get_db_credentials()

    try:
        conn = psycopg2.connect(
            dbname="sysinv",
            user=username,
            password=password,
            host="localhost",
            port=postgres_port
        )
    except Exception as e:
        LOG.exception("Failed to connect to the database: %s" % e)
        raise

    try:
        with conn.cursor() as cursor:
            cursor.execute(query)
            result = cursor.fetchone()
            if result:
                return result[0]
            else:
                return None
    except Exception as e:
        LOG.exception("Error executing query: %s" % e)
        raise
    finally:
        conn.close()


def check_dns_resolution(ip_address):
    if valid_ipv4(ip_address):
        record_type = "A"
        ip_type = "IPv4"
    elif valid_ipv6(ip_address):
        record_type = "AAAA"
        ip_type = "IPv6"
    else:
        LOG.error("Invalid IP address: %s" % ip_address)
        return False

    LOG.info("Checking resolution to registry.central")

    result = subprocess.run(
        ["dig", "registry.central", record_type, "+short"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True
    )

    if result.returncode != 0 or not result.stdout.strip():
        LOG.error(
            "Failed to resolve %s address %s to a name associated with "
            "the domain (registry.central). No valid DNS record found." %
            (ip_type, ip_address)
        )
        return False

    return True


if __name__ == "__main__":
    sys.exit(main())
