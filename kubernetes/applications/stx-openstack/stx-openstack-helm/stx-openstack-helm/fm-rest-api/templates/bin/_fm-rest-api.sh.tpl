#!/bin/bash

{{/*
#
# SPDX-License-Identifier: Apache-2.0
#
*/}}

set -ex

export SQL_CONNECTION=$(awk -F '=' '/sql_connection/{print $2}' /etc/fm/fm.conf)
echo $SQL_CONNECTION > /var/log/sql_connection
python /usr/local/bin/fm_db_sync_event_suppression.py $SQL_CONNECTION
python /var/lib/openstack/bin/fm-api --config-file /etc/fm/fm.conf
