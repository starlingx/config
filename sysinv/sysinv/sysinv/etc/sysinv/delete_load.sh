#!/bin/bash
# Copyright (c) 2015-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# This script is remove a load from a controller.
# The load version is passed in as the first variable.

: ${1?"Usage $0 VERSION"}
VERSION=$1

FEED_DIR=/var/www/pages/feed/rel-$VERSION
PRESTAGE_DIR=/opt/platform/deploy/$VERSION
PLAYBOOKS_DIR=/opt/dc-vault/playbooks/$VERSION

rm -f /var/pxeboot/pxelinux.cfg.files/*-$VERSION
rm -rf /var/pxeboot/rel-$VERSION

rm -f /usr/sbin/pxeboot-update-$VERSION.sh

rm -rf $FEED_DIR

if [ -d $PRESTAGE_DIR ]; then
    rm -rf $PRESTAGE_DIR
fi

if [ -d $PLAYBOOKS_DIR ]; then
    rm -rf $PLAYBOOKS_DIR
fi
