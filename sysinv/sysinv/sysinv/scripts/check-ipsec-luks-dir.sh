#!/bin/bash

FIRST_BOOT="/etc/platform/.first_boot"
LUKS_MOUNT="/var/luks/stx/luks_fs"
SLEEP_INTERVAL=1

# Exit if the system is in the first boot state
if [ -e "${FIRST_BOOT}" ]; then
    echo "First boot detected. Exiting script."
    exit 0
fi

# Check if the mount point is already mounted
if /usr/bin/mountpoint -q "$LUKS_MOUNT"; then
    echo "Mount point is already mounted: $LUKS_MOUNT"
    exit 0
else
    echo "Mount point is not mounted: $LUKS_MOUNT"
fi

# Loop to wait for the mount point
while ! /usr/bin/mountpoint -q "$LUKS_MOUNT"; do
    echo "Waiting for mount point to be mounted: $LUKS_MOUNT"
    sleep $SLEEP_INTERVAL
done

echo "Mount point is now mounted: $LUKS_MOUNT"
exit 0
