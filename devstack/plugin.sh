#!/bin/bash

# devstack/plugin.sh
# Triggers stx_config specific functions to install and configure stx_config

# Dependencies:
#
# - ``functions`` file
# - ``DATA_DIR`` must be defined

# ``stack.sh`` calls the entry points in this order:
#
echo_summary "sysinv devstack plugin.sh called: $1/$2"
source $DEST/stx-config/devstack/lib/stx-config
# check for service enabled

if is_service_enabled sysinv-api sysinv-cond; then
    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        # Perform installation of sysinv source
        echo_summary "Installing cgts_client"
        install_cgtsclient
        echo_summary "Installing depends"
        install_sysinv_depends
        echo_summary "Installing sysinv service"
        install_sysinv

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # Configure after the other layer 1 and 2 services have been configured
        echo_summary "Configuring sysinv"
        configure_sysinv
        create_sysinv_user_group
        create_sysinv_accounts
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        # Initialize and start the sysinv service
        echo_summary "Initializing and start sysinv "
        init_sysinv
        start_sysinv
    elif [[ "$1" == "stack" && "$2" == "test-config" ]]; then
        # do sanity test for sysinv
        echo_summary "do test-config"
    fi

    if [[ "$1" == "unstack" ]]; then
        # Shut down sysinv services
        echo_summary "Stop Sysinv service"
        stop_sysinv
        :
    fi

    if [[ "$1" == "clean" ]]; then
        cleanup_sysinv
        :
    fi
fi
