#!/bin/bash
#
# Copyright (c) 2016-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# Migrates ceilometer pipeline file.

. /usr/bin/tsconfig

NAME=$(basename $0)

# The migration scripts are passed these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

OLD_PIPELINE_FILE="${CGCS_PATH}/ceilometer/${FROM_RELEASE}/pipeline.yaml"
NEW_PIPELINE_DIR="${CGCS_PATH}/ceilometer/${TO_RELEASE}"
NEW_PIPELINE_FILE="${NEW_PIPELINE_DIR}/pipeline.yaml"
PIPELINE_SOURCE_FILE=/etc/ceilometer/controller.yaml

function do_escape {
    local val=$1
    local val_escaped="${val//\//\\/}"
    val_escaped="${val_escaped//\&/\\&}"
    echo $val_escaped
}

if [ "$ACTION" == "migrate" ]; then
    log "Creating new $NEW_PIPELINE_FILE file for release $TO_RELEASE"
    if [ ! -d "$NEW_PIPELINE_DIR" ]; then
        mkdir $NEW_PIPELINE_DIR
    fi
    cp $PIPELINE_SOURCE_FILE $NEW_PIPELINE_FILE

    # Currently, the user can only modify the vswitch.csv and pm.csv paths.
    default_value=$(do_escape "$(awk '/vswitch.csv/ {print $0}' $NEW_PIPELINE_FILE)")
    custom_value=$(do_escape "$(awk '/vswitch.csv/ {print $0}' $OLD_PIPELINE_FILE)")
    sed -i  "s/$default_value/$custom_value/" $NEW_PIPELINE_FILE

    default_value=$(do_escape "$(awk '/pm.csv/ {print $0}' $NEW_PIPELINE_FILE)")
    custom_value=$(do_escape "$(awk '/pm.csv/ {print $0}' $OLD_PIPELINE_FILE)")
    sed -i "s/$default_value/$custom_value/" $NEW_PIPELINE_FILE

    chmod 640 $NEW_PIPELINE_FILE

fi

exit 0
