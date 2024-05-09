#!/bin/bash

FIRST_BOOT="/etc/platform/.first_boot"
LUKS_DIR="/var/luks/stx/luks_fs/ipsec"

if [ -e ${FIRST_BOOT} ]; then
    exit 0
fi

test -d $LUKS_DIR
while [ $? != 0 ]; do
    sleep 1
    test -d $LUKS_DIR
done
