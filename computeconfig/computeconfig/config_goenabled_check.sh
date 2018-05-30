#!/bin/bash
#
# Copyright (c) 2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# Configuration "goenabled" check.
# If configuration failed, prevent the node from going enabled.

NAME=$(basename $0)
VOLATILE_CONFIG_FAIL="/var/run/.config_fail"

logfile=/var/log/patching.log

if [ -f $VOLATILE_CONFIG_FAIL ]
then
    logger "$NAME: Node configuration has failed. Failing goenabled check."
    exit 1
fi

exit 0
