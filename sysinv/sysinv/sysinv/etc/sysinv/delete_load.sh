#!/bin/bash
# Copyright (c) 2015-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# This script is remove a load from a controller.
# The load version is passed in as the first variable.

: ${1?"Usage $0 VERSION"}
VERSION=$1

FEED_DIR=/www/pages/feed/rel-$VERSION

rm -f /pxeboot/pxelinux.cfg.files/*-$VERSION
rm -rf /pxeboot/rel-$VERSION

rm -f /usr/sbin/pxeboot-update-$VERSION.sh

rm -rf $FEED_DIR
