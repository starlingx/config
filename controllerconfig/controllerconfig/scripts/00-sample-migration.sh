#!/bin/bash
#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# Sample upgrade migration script. Important notes:
# - The script should exit 0 on success and exit non-0 on fail. Note that
#   failing will result in the upgrade of controller-1 failing, so don't fail
#   unless it is a real failure.
# - Your logic should only check the FROM_RELEASE to determine if migration is
#   required. Checking the TO_RELEASE is dangerous because we do not know
#   the exact value the TO_RELEASE will hold until we reach final compile.
#   The TO_RELEASE is here for logging reasons and in case of some unexpected
#   emergency where we may need it.
# - The script will be passed one of the following actions:
#     start: Prepare for upgrade on release N side. Called during
#            "system upgrade-start".
#     migrate: Perform data migration on release N+1 side. Called while
#              controller-1 is performing its upgrade. At this point in the
#              upgrade of controller-1, the databases have been migrated from
#              release N to release N+1 (data migration scripts have been
#              run). Postgres is running and is using the release N+1
#              databases. The platform filesystem is mounted at /opt/platform
#              and has data populated for both release N and release N+1.
# - You can do the migration work here in a bash script. There are other
#   options:
#   - Invoke another binary from this script to do the migration work.
#   - Instead of using a bash script, create a symlink in this directory, to
#     a binary of your choice.
#   - The migration scripts are executed in alphabetical order. Please prefix
#     your script name with a two digit number (e.g. 01-my-script-name.sh). The
#     order of migrations usually shouldn't matter, so pick an unused number
#     near the middle of the range.

NAME=$(basename $0)

# The migration scripts are passed these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

log "$NAME: performing sample migration from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"


if [ "$FROM_RELEASE" == "17.06" ] && [ "$ACTION" == "migrate" ]
then
    log "Sample migration from release $FROM_RELEASE"
fi

exit 0
