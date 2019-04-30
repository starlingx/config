#!/bin/bash

{{/*
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
*/}}

set -ex

# Get service id
OS_SERVICE_ID=$( openstack service list -c Type -c ID -f value | \
                 grep ${OS_SERVICE_TYPE} | cut -f1 -d" " )

# Check if endpoint exists
OS_ENDPOINT_ID=$( openstack endpoint list --service ${OS_SERVICE_TYPE} \
                  --region ${OS_SERVICE_REGION} \
                  --interface ${OS_SVC_ENDPOINT} -c ID -f value )

# Delete the old endpoint
if [[ -v $OS_ENDPOINT_ID ]]; then
  openstack endpoint delete ${OS_ENDPOINT_ID}
fi

# Create the new endpoint
OS_ENDPOINT_ID=$( openstack endpoint create -f value -c id \
    --region=${OS_SERVICE_REGION} \
    "${OS_SERVICE_ID}" \
    ${OS_SVC_ENDPOINT} \
    "${OS_SERVICE_ENDPOINT}" )

# Display the Endpoint
openstack endpoint show ${OS_ENDPOINT_ID}
