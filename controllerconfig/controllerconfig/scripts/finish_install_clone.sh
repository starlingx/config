#! /bin/bash
########################################################################
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

NOVAOPENRC="/etc/nova/openrc"
if [ -e ${NOVAOPENRC} ] ; then
   source  ${NOVAOPENRC} &>/dev/null
else
   echo "Admin credentials not found"
   exit
fi

# Delete all the servers
echo "Deleting all servers [`openstack server list --all`]"
found=false
for i in $(openstack server list --all -c ID -f value); do
    `openstack server delete $i &> /dev/null`
    echo $i deleted
    found=true
done
if $found; then
    sleep 30
fi
echo "Deleted all servers [`openstack server list --all`]"
# Delete all the volumes
echo "Deleting all volumes [`openstack volume list --all`]"
found=false
for i in $(openstack volume list --all -c ID -f value); do
    `openstack volume delete $i &> /dev/null`
    echo $i deleted
    found=true
done
if $found; then
    sleep 30
fi
echo "Deleted all volumes [`openstack volume list --all`]"

