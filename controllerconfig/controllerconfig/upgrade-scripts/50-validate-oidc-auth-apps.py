#!/usr/bin/env python

# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

# Conversion of oidc-auth-apps configuration
#
# Verify the supported configuration during health-query-upgrade.
# Backup overrides at upgrade start.
# Convert the configuration during upgrade activate.

from controllerconfig.common import log
import copy
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import sys
import yaml

LOG = log.get_logger(__name__)
log.configure()

# This script is only valid for to/from releases:
ACCEPTED_FROM = ['21.12']
ACCEPTED_TO = ['22.12']
ACCEPTED_ACTIONS = ['health-check', 'start', 'migrate']

# this path should have been created by stx-oidc-auth-helm package
# with ownership assigned to postgres:postgres
BACKUP_PATH = '/var/opt/oidc-auth-apps'

# list of charts in oidc-auth-apps; for sanity check only
oidc_charts = ['dex', 'oidc-client', 'secret-observer']

# Hard-coded chart values; matching the fluxcd manifest defaults
DEFAULT_HTTPSTLS_MOUNT = '/etc/dex/tls'
DEFAULT_HTTPSTLS_MODE = 420
DEFAULT_HTTPSTLS_SECRET = 'local-dex.tls'

# A dictionary of values selected from the overrides yaml during
# validate_overrides().  The selected values are used to convert
# the yaml from old dex to new dex
DEFINES = {}

# validate yaml, instructions for what configurations accepted
validation_yaml = """
name: "supported"
validation: "children"
optional: False
accepted: ["extraVolumeMounts", "extraVolumes", "config", "certs"]
children:
- name: "extraVolumeMounts"
  validation: "any"
  optional: True
  define: "volumeMounts"
- name: "extraVolumes"
  validation: "any"
  optional: True
  define: "volumes"
- name: "config"
  validation: "children"
  optional: False
  define: "dex_config"
  children:
  - name: "web"
    validation: "children"
    optional: True
    children:
    - name: "tlsCert"
      validation: "exact"
      optional: True
      define: "dex_https_tlsCert"
    - name: "tlsKey"
      validation: "exact"
      optional: True
      define: "dex_https_tlsKey"
- name: "certs"
  validation: "children"
  optional: True
  accepted: ["grpc", "web"]
  children:
  - name: "grpc"
    validation: "children"
    optional: True
    accepted: ["secret"]
    children:
    - name: "secret"
      validation: "children"
      optional: False
      accepted: ["caName", "clientTlsName", "serverTlsName"]
      children:
      - name: "caName"
        validation: "exact"
        optional: False
        define: "tls_secret"
      - name: "clientTlsName"
        validation: "exact"
        optional: False
        define: "tls_secret"
      - name: "serverTlsName"
        validation: "exact"
        optional: False
        define: "tls_secret"
  - name: "web"
    validation: "children"
    optional: False
    accepted: ["secret"]
    children:
    - name: "secret"
      validation: "children"
      optional: False
      accepted: ["caName", "tlsName"]
      children:
      - name: "caName"
        validation: "exact"
        optional: False
        define: "tls_secret"
      - name: "tlsName"
        validation: "exact"
        optional: False
        define: "tls_secret"

"""

# sql to fetch the user_overrides from DB for oidc-auth-apps
sql_overrides = ("SELECT helm_overrides.name, user_overrides"
                 " FROM helm_overrides"
                 " LEFT OUTER JOIN kube_app"
                 " ON helm_overrides.app_id = kube_app.id"
                 " WHERE kube_app.name = 'oidc-auth-apps'")

sql_update = ("UPDATE helm_overrides"
              " SET user_overrides = '%s'"
              " FROM kube_app"
              " WHERE helm_overrides.app_id = kube_app.id"
              " AND kube_app.name = 'oidc-auth-apps'"
              " AND helm_overrides.name = 'dex'")


def get_overrides(conn):
    """Fetch helm overrides from DB"""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql_overrides)
        return cur.fetchall()


def backup_overrides(overrides, action='debug'):
    """Dump helm overrides from DB to files in BACKUP_PATH"""
    backup_path = os.path.join(BACKUP_PATH, action)
    if not os.path.exists(backup_path):
        os.makedirs(backup_path)
    field = 'user_overrides'
    for chart in overrides:
        name = chart['name']
        if name not in oidc_charts:
            LOG.warning("oidc-auth-apps: mismatch chart name '%s'", name)
        if chart[field]:
            document = yaml.safe_load(chart[field])
            if not document:
                LOG.debug("oidc-auth-apps: %s empty document", name)
                continue
            backup_f = '_'.join([name, field])
            backup_f = '.'.join([backup_f, 'yaml'])
            backup_f = os.path.join(backup_path, backup_f)
            try:
                with open(backup_f, 'w') as file:
                    yaml.dump(document, file, default_flow_style=False)
            except IOError as e:
                LOG.error("oidc-auth-apps: IOError: %s; file: %s", e, backup_f)
                return 1
    LOG.info("oidc-auth-apps: user_overrides backed up to %s", backup_path)
    return 0


def validate_value(instruction, value):
    """Verify a value"""
    if instruction['validation'] == 'exact':
        if type(value) not in [str, bool, int, float]:
            LOG.error("oidc-auth-apps: value type %s not supported",
                      type(value))
            return False
        if 'define' in instruction:
            if instruction['define'] in DEFINES:
                if DEFINES[instruction['define']] != value:
                    LOG.error("oidc-auth-apps: defined value is"
                              " mismatched '%s': '%s' != '%s'",
                              instruction['define'],
                              DEFINES[instruction['define']],
                              value)
                    LOG.error("oidc-auth-apps: instruction: %s", instruction)
                    return False
            else:
                DEFINES[instruction['define']] = value
                LOG.debug("oidc-auth-apps: define: '%s' == '%s'",
                          instruction['define'], value)
        if 'values' in instruction:
            LOG.error("oidc-auth-apps: validation exact values"
                      " not implemented")
            return False
    else:
        LOG.error("oidc-auth-apps: validation %s not supported",
                  instruction['validation'])
        return False
    LOG.debug("oidc-auth-apps: accept %s: %s: %s",
              instruction['validation'], instruction, value)
    return True


def printable_item(item):
    """remove children from item to make it printable"""
    printable = {}
    printable['validation'] = item['validation']
    printable['name'] = item['name']
    printable['optional'] = item['optional']
    if 'define' in item:
        printable['define'] = item['define']
    return printable


def define_complex_value(item, yaml_doc):
    """Subroutine to fill DEFINES for complex values"""
    if 'define' in item and item['validation'] != 'exact':
        # Handle saving of complex values
        if item['define'] in DEFINES:
            LOG.error("oidc-auth-apps: complex values comparison"
                      " is not supported: %s", printable_item(item))
            return False
        else:
            DEFINES[item['define']] = copy.deepcopy(yaml_doc[item['name']])
            LOG.debug("oidc-auth-apps: define: '%s'",
                      item['define'])
    return True


def validate_item(item, yaml_doc):
    """Handle one list item from instruction"""
    print_item = printable_item(item)
    # If neither present nor optional: fail
    # If not present, but optional: pass
    optional = True
    if 'optional' in item:
        optional = item['optional']
    present = item['name'] in yaml_doc
    if not (present or optional):
        LOG.error("oidc-auth-apps: overrides omit required value:"
                  " %s", print_item)
        return False
    elif not present:
        # pass
        return True
    if not define_complex_value(item, yaml_doc):
        return False

    if item['validation'] == 'any':
        # pass
        LOG.debug("oidc-auth-apps: accept instruction: %s", print_item)
    elif item['validation'] == 'exact':
        if not validate_value(item, yaml_doc[item['name']]):
            return False
    elif item['validation'] == 'children':
        accepted_keys = ['*']
        if 'accepted' in item:
            if not validate_accepted(item['accepted'], yaml_doc[item['name']]):
                return False
            else:
                accepted_keys = [x for x in yaml_doc[item['name']]]
        if not recurse_validate_document(item['children'],
                                         yaml_doc[item['name']]):
            LOG.error("oidc-auth-apps: instruction: %s", print_item)
            return False
        else:
            LOG.debug("oidc-auth-apps: accept instruction: %s: %s",
                      print_item, accepted_keys)
    else:
        LOG.error("oidc-auth-apps: instruction %s not implemented",
                  item['validation'])
        return False
    return True


def validate_accepted(accepted, yaml_doc):
    """Check that each item in yaml is expected"""
    if type(yaml_doc) is not dict:
        LOG.error("oidc-auth-apps: accepting from list not implemented")
        return False
    error = False
    for key in yaml_doc:
        if key not in accepted:
            error = True
            LOG.error("oidc-auth-apps: key is not accepted: %s", key)
    return not error


def recurse_validate_document(instruction, yaml_doc):
    """Recursively verify the document against validation yaml"""
    if type(instruction) is not list:
        LOG.error("oidc-auth-apps: non-list instruction not implemented")
        return False
    for item in instruction:
        if type(item) is not dict:
            LOG.error("oidc-auth-apps: non-dict instruction item"
                      " not implemented")
            return False
        elif 'validation' not in item:
            LOG.error("oidc-auth-apps: instruction missing validation")
            return False
        elif 'name' not in item:
            LOG.error("oidc-auth-apps: instruction missing name")
            return False
        elif not validate_item(item, yaml_doc):
            return False
    return True


def validate_document(validation, document):
    """Top level, verify the document against validation yaml"""
    LOG.info("oidc-auth-apps: validating %s", validation['name'])
    if validation['validation'] != 'children':
        LOG.warning("oidc-auth-apps: root validation should be"
                    " children not %s", validation['validation'])
    result = recurse_validate_document(validation['children'], document)
    if 'accepted' in validation:
        if not validate_accepted(validation['accepted'], document):
            return False
    if validation['optional']:
        LOG.warning("oidc-auth-apps: root validation is optional")
        return True
    return result


def get_chart_override(overrides, chart):
    """Get a specific set of overrides from the db value"""
    chart_ov = None
    for chart_ov in overrides:
        if 'name' in chart_ov and chart_ov['name'] == chart:
            break
    else:
        chart_ov = None
    if not (chart_ov and 'user_overrides' in chart_ov):
        return None
    if not chart_ov['user_overrides']:
        # A sanity check. Really shouldn't see this if oidc-auth-apps
        # does not have dex overrides - either because the app is not
        # applied, or because it failed to apply without overrides
        return None
    # convert the string to python structures
    return yaml.safe_load(chart_ov['user_overrides'])


def validate_overrides(overrides):
    """Check if the user_overrides are supported"""
    DEFINES.clear()
    if not overrides:
        # dex without overrides isn't configured correctly
        LOG.error("oidc-auth-apps: no overrides to validate")
        return False
    elif type(overrides) is not list:
        # this shouldn't happen
        LOG.error("oidc-auth-apps: overrides not list type")
        return False
    # Find dex; only dex helm needs conversion
    document = get_chart_override(overrides, 'dex')
    if not document:
        LOG.error("oidc-auth-apps: no dex user_overrides to validate")
        return False
    validate = yaml.safe_load(validation_yaml)
    return validate_document(validate, document)


def get_httpstls_mount():
    """Use the default unless the end-user had overridden it"""
    if 'dex_https_tlsCert' in DEFINES:
        return os.path.dirname(DEFINES['dex_https_tlsCert'])
    # The default matches oic-auth-apps flucd manifest defaults
    return DEFAULT_HTTPSTLS_MOUNT


def get_httpstls_secret():
    """Use the default unless the end-user had overridden it"""
    if 'tls_secret' in DEFINES:
        return DEFINES['tls_secret']
    # The default matches oic-auth-apps flucd manifest defaults
    return DEFAULT_HTTPSTLS_SECRET


def merge_new_overrides():
    """Read DEFINES and prepare new overrides yaml"""
    # Take the dex config as is:
    new_doc = {'config': copy.deepcopy(DEFINES['dex_config'])}
    # Convert old dex certs.web.secret to https-tls volume/volumeMounts
    mount = {'mountPath': get_httpstls_mount(), 'name': 'https-tls'}
    vol = {'secret': {'secretName': get_httpstls_secret(),
                      'defaultMode': DEFAULT_HTTPSTLS_MODE},
           'name': 'https-tls'}
    # Take 'extra' volumes and mounts that may exist in old dex
    # This is expected to be the WAD certificate
    volumes = []
    volumeMounts = []
    if 'volumes' in DEFINES:
        volumes = copy.deepcopy(DEFINES['volumes'])
    if 'volumeMounts' in DEFINES:
        volumeMounts = copy.deepcopy(DEFINES['volumeMounts'])

    # only add volumes/mounts if 'extra' was specified, or
    # if there was non-default mount
    if volumes or 'tls_secret' in DEFINES:
        volumes.append(vol)
    if volumeMounts or 'dex_https_tlsCert' in DEFINES:
        volumeMounts.append(mount)
    if volumes:
        new_doc['volumes'] = volumes
    if volumeMounts:
        new_doc['volumeMounts'] = volumeMounts
    return new_doc


def convert_overrides(overrides, conn):
    """Convert the user_overrides from old dex to new"""
    LOG.info("oidc-auth-apps: converting dex overrides")
    if not validate_overrides(overrides):
        return 1
    new_doc = merge_new_overrides()
    res = backup_overrides(overrides, action='migrate')
    if res != 0:
        return res
    # replace the dex user overrides
    new_str = yaml.dump(new_doc, default_flow_style=False)
    for override in overrides:
        if override['name'] == 'dex':
            override['user_overrides'] = new_str
    res = backup_overrides(overrides, action='converted')
    return res


def main():
    action = None
    from_release = None
    to_release = None
    arg = 1
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1
    if action not in ACCEPTED_ACTIONS:
        LOG.debug("oidc-auth-apps: omit %s, %s, %s",
                  from_release, to_release, action)
        return 0
    elif from_release not in ACCEPTED_FROM:
        LOG.warning("oidc-auth-apps: not valid from release %s",
                    from_release)
        return 0
    elif to_release not in ACCEPTED_TO:
        LOG.warning("oidc-auth-apps: not valid to release %s",
                    to_release)
        return 0

    try:
        conn = psycopg2.connect("dbname=sysinv user=postgres")
        overrides = get_overrides(conn)
    except Exception as ex:
        LOG.exception("oidc-auth-apps: %s", ex)
        return 1
    if not overrides:
        LOG.error("oidc-auth-apps: failed to fetch overrides")
        return 1
    elif not get_chart_override(overrides, 'dex'):
        LOG.info("oidc-auth-apps: no dex overrides to convert")
        return 0

    if action == 'health-check':
        if validate_overrides(overrides):
            LOG.info("oidc-auth-apps: upgrade script health-check: success")
            return 0
        return 1
    elif action == 'start':
        return backup_overrides(overrides, action='start')
    elif action == 'migrate':
        convert_overrides(overrides, conn)
        # A failure of oidc-auth-apps overrides conversion is unhandled.
        # A patch for 21.12 release is needed to pre-test the
        # compatibility of user overrides with expected configurations.
        # 22.06 version of oidc-auth-apps will fail to apply if overrides
        # are not converted.
        return 0


if __name__ == "__main__":
    sys.exit(main())
