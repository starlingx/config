#!/bin/bash

{{/*
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
*/}}

set -ex

nova-api-proxy --config-file=/etc/proxy/nova-api-proxy.conf
