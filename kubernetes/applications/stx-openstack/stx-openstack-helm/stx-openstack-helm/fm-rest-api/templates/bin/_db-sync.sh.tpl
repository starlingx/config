#!/bin/bash

{{/*
#
# SPDX-License-Identifier: Apache-2.0
#
*/}}

set -ex

fm-dbsync --config-file /etc/fm/fm.conf
