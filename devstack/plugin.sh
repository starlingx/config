#!/bin/bash

# devstack/plugin.sh
# Triggers stx_config specific functions to install and configure stx_config

echo_summary "sysinv devstack plugin.sh called: $1/$2"

# check for service enabled
if is_service_enabled stx-config; then
    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        # Perform installation of source
        echo_summary "Installing cgts_client"
        install_cgtsclient
        echo_summary "Installing depends"
        install_sysinv_depends
        echo_summary "Installing sysinv service"
        install_sysinv
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # Configure after the other layer 1 and 2 services have been configured
        echo_summary "Configure sysinv"
        configure_sysinv
        create_sysinv_user_group
        create_sysinv_accounts
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        # Initialize and start the sysinv service
        echo_summary "Initialize and start sysinv "
        init_sysinv
        start_sysinv
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
        stop_sysinv
    fi

    if [[ "$1" == "clean" ]]; then
        cleanup_sysinv
    fi
fi
