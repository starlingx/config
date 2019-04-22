#!/bin/bash

{{/*
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
*/}}

set -ex

dcorch-api-proxy --config-file=/etc/dcorch/dcorch.conf --type identity
