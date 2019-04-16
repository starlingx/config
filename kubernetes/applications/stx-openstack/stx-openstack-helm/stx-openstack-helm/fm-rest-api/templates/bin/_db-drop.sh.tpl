#!/bin/bash

{{/*
#
# SPDX-License-Identifier: Apache-2.0
#
*/}}

set -ex

dropdb -h 127.0.0.1 -Uroot fm
