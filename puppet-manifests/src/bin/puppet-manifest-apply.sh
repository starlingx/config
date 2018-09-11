#!/usr/bin/env bash

# Grab a lock before doing anything else
LOCKFILE=/var/lock/.puppet.applyscript.lock
LOCK_FD=200
LOCK_TIMEOUT=60

eval "exec ${LOCK_FD}>$LOCKFILE"

while :; do
    flock -w $LOCK_TIMEOUT $LOCK_FD && break
    logger -t $0 "Failed to get lock for puppet applyscript after $LOCK_TIMEOUT seconds. Trying again"
    sleep 1
done

HIERADATA=$1
HOST=$2
PERSONALITY=$3
MANIFEST=${4:-$PERSONALITY}
RUNTIMEDATA=$5


PUPPET_MODULES_PATH=/usr/share/puppet/modules:/usr/share/openstack-puppet/modules
PUPPET_MANIFEST=/etc/puppet/manifests/${MANIFEST}.pp
PUPPET_TMP=/tmp/puppet

# Setup log directory and file
DATETIME=$(date -u +"%Y-%m-%d-%H-%M-%S")
LOGDIR="/var/log/puppet/${DATETIME}_${PERSONALITY}"
LOGFILE=${LOGDIR}/puppet.log

mkdir -p ${LOGDIR}
rm -f /var/log/puppet/latest
ln -s ${LOGDIR} /var/log/puppet/latest

touch ${LOGFILE}
chmod 600 ${LOGFILE}


# Remove old log directories
declare -i NUM_DIRS=`ls -d1 /var/log/puppet/[0-9]* 2>/dev/null | wc -l`
declare -i MAX_DIRS=20
if [ ${NUM_DIRS} -gt ${MAX_DIRS} ]; then
    let -i RMDIRS=${NUM_DIRS}-${MAX_DIRS}
    ls -d1 /var/log/puppet/[0-9]* | head -${RMDIRS} | xargs --no-run-if-empty rm -rf
fi


# Setup staging area and hiera data configuration
# (must match hierarchy defined in hiera.yaml)
rm -rf ${PUPPET_TMP}
mkdir -p ${PUPPET_TMP}/hieradata
cp /etc/puppet/hieradata/global.yaml ${PUPPET_TMP}/hieradata/global.yaml
cp /etc/puppet/hieradata/${PERSONALITY}.yaml ${PUPPET_TMP}/hieradata/personality.yaml

# When the compute node is first booted and goes online, sysinv-agent reports 
# host CPU inventory which triggers the first runtime manifest apply that updates
# the grub. At this time, copying the host file failed due to a timing issue that
# has not yet been fully understood. Subsequent retries worked. 
if [ "${PERSONALITY}" = "compute" ]; then
    n=0
    until [ $n -ge 3 ]; do
        cp -f ${HIERADATA}/${HOST}.yaml ${PUPPET_TMP}/hieradata/host.yaml && break
        n=$(($n+1))
        logger -t $0 "Failed to copy /etc/puppet/hieradata/${HOST}.yaml"
        sleep 15
    done
else
    cp -f ${HIERADATA}/${HOST}.yaml ${PUPPET_TMP}/hieradata/host.yaml
fi
cp -f ${HIERADATA}/system.yaml \
    ${HIERADATA}/secure_system.yaml \
    ${HIERADATA}/static.yaml \
    ${HIERADATA}/secure_static.yaml \
    ${PUPPET_TMP}/hieradata/

if [ -n "${RUNTIMEDATA}" ]; then
    cp -f ${RUNTIMEDATA} ${PUPPET_TMP}/hieradata/runtime.yaml
fi


# Exit function to save logs from initial apply
function finish {
    local SAVEDLOGS=/var/log/puppet/first_apply.tgz
    if [ ! -f ${SAVEDLOGS} ]; then
        # Save the logs
        tar czf ${SAVEDLOGS} ${LOGDIR} 2>/dev/null
    fi
}
trap finish EXIT


# Set Keystone endpoint type to internal to prevent SSL cert failures during config
export OS_ENDPOINT_TYPE=internalURL
export CINDER_ENDPOINT_TYPE=internalURL
# Suppress stdlib deprecation warnings until all puppet modules can be updated
export STDLIB_LOG_DEPRECATIONS=false

echo "Applying puppet ${MANIFEST} manifest..."
flock /var/run/puppet.lock \
    puppet apply --debug --trace --modulepath ${PUPPET_MODULES_PATH} ${PUPPET_MANIFEST} \
        < /dev/null 2>&1 | awk ' { system("date -u +%FT%T.%3N | tr \"\n\" \" \""); print $0; fflush(); } ' > ${LOGFILE}
if [ $? -ne 0 ]; then
    echo "[FAILED]"
    echo "See ${LOGFILE} for details"
    exit 1
else
    grep -qE '^(.......)?Warning|^....-..-..T..:..:..([.]...)?(.......)?.Warning|^(.......)?Error|^....-..-..T..:..:..([.]...)?(.......)?.Error' ${LOGFILE}
    if [ $? -eq 0 ]; then
        echo "[WARNING]"
        echo "Warnings found. See ${LOGFILE} for details"
        exit 1
    fi
    echo "[DONE]"
fi

exit 0
