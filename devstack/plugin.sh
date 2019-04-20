#!/bin/bash
#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2019 Intel Corporation
#
# devstack/plugin.sh
# Triggers stx_config specific functions to install and configure stx_config

echo_summary "sysinv devstack plugin.sh called: $1/$2"

# check for service enabled
if is_service_enabled config; then
    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        # Perform installation of source
        echo_summary "Installing stx-config"
        install_config
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # Configure after the other layer 1 and 2 services have been configured
        echo_summary "Configure sysinv"
        configure_config
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        # Initialize and start the sysinv service
        echo_summary "Initialize and start sysinv "
        init_config
        start_config
    elif [[ "$1" == "stack" && "$2" == "test-config" ]]; then
        # do sanity test for sysinv
        echo_summary "do test-config"
        # check sysinv services status
        echo_summary "do check sysinv services"
        check_sysinv_services
    fi

    if [[ "$1" == "unstack" ]]; then
        # Shut down sysinv services
        echo_summary "Stop Sysinv service"
        stop_config
    fi

    if [[ "$1" == "clean" ]]; then
        cleanup_config
    fi
fi
