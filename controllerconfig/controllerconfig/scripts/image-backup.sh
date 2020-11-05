#!/bin/bash
#
# Copyright (c) 2016-2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
backup_dir="/opt/backups"
tmp_dir="${backup_dir}/image_temp"

function usage {
    cat <<"EOF"
Helper tool for backing up Glance images
Usage:
image-backup export <uuid>           - export the image with <uuid> into backup file /opt/backups/image_<uuid>.tgz
image-backup import image_<uuid>.tgz - import the image from the backup source file at /opt/backups/image_<uuid>.tgz
into the corresponding image.

Temporary files are stored in /opt/backups/image_temp

Please consult the OpenStack application backup and restore section of the Backup and Restore Guide.
EOF
}

function create_tmp {
    if [ ! -d ${backup_dir} ]; then
        echo "Error: backup directory ${backup_dir} does not exist"
        exit 1
    fi
    # Create temporary directory
    if [ ! -d ${tmp_dir} ]; then
        mkdir ${tmp_dir}
    fi

}

function remove_tmp {
    # Remove temporary files and directory if not empty
    local uuid=$1
    rm -f ${tmp_dir}/${uuid}*
    rmdir --ignore-fail-on-non-empty ${tmp_dir} &>/dev/null
}

function export_file_from_rbd_image {
    local file=$1
    rbd export -p images ${file} ${tmp_dir}/${file}
    if [ $? -ne 0 ]; then
        echo "Error: Failed to export image ${file} from Ceph images pool, please check status of storage cluster"
        remove_tmp; exit 1
    fi
}

function export_image {
    local uuid=$1

    # Check if the corresponding image is present in the RBD pool
    rbd -p images ls | grep -q -e "^${uuid}$"
    if [ $? -ne 0 ]; then
        echo "Error: Corresponding file for image with id: ${uuid} was not found in the RBD images pool"
        remove_tmp; exit 1
    fi

    # Export original image
    export_file_from_rbd_image ${uuid}

    # Export raw cache if present
    rbd -p images ls | grep -q ${uuid}_raw
    if [ $? -eq 0 ]; then
        export_file_from_rbd_image ${uuid}_raw
        raw="${uuid}_raw"
    fi

    echo -n "Creating backup archive..."
    archive="${backup_dir}/image_${uuid}.tgz"
    tar czf ${archive} -C ${tmp_dir} ${uuid} ${raw}
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create archive ${archive}"
        remove_tmp; exit 1
    else
        echo "done"
    fi

    echo "Backup archive ${archive} created"
}

function import_file_to_rbd_image {
    local file=$1
    local snap="images/${file}@snap"
    rbd import --image-format 2 ${tmp_dir}/${file} images/${file}
    if [ $? -ne 0 ]; then
        echo "Error: Failed to import image ${file} into Ceph images pool, please check status of storage cluster"
        remove_tmp; exit 1
    fi
    rbd snap create ${snap} 1>/dev/null
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create snapshot ${snap}, please check status of storage cluster"
        remove_tmp; exit 1
    fi
    rbd snap protect ${snap} 1>/dev/null
    if [ $? -ne 0 ]; then
        echo "Error: Failed to protect snapshot ${snap}, please check status of storage cluster"
        remove_tmp; exit 1
    fi
}

function import_image {
    local uuid=$1

    # Storage cluster must be healthy before starting the import
    if [ ! "$(ceph health)" = "HEALTH_OK" ]; then
        echo "Error: The storage cluster health must be HEALTH_OK before proceding"
        remove_tmp; exit 1
    fi

    # Check if the corresponding image is already present in the RBD pool
    rbd -p images ls | grep -q -e "^${uuid}$"
    if [ $? -eq 0 ]; then
        echo "Error: Image with id: ${uuid} is already imported"
        remove_tmp; exit 1
    fi

    # Import original image
    import_file_to_rbd_image ${uuid}

    # Import raw cache
    if [ -f "${tmp_dir}/${uuid}_raw" ]; then
        import_file_to_rbd_image ${uuid}_raw
    fi
}

if [ $EUID -ne 0 ]; then
    echo "This script must be executed as root"
    exit 1
fi

if [ $# -ne 2 ]; then
    usage
    exit 0
fi

source /etc/platform/openrc
export OS_AUTH_URL=http://keystone.openstack.svc.cluster.local/v3

if [ "$1" = "export" ]; then
    # Check that glance image is present in glance
    openstack image list -f value -c ID | grep -q $2
    if [ $? -ne 0 ]; then
        echo "Error: Glance image with id: $2 not found. Please try with an existing image id."
        remove_tmp; exit 1
    fi

    # Only allow backup of images that use rbd as backend.
    openstack image show $2 -c properties | grep -q -F "direct_url='rbd://"
    if [ $? -ne 0 ]; then
        echo "Image with id: $2 is not stored in Ceph RBD. Backup using image-backup tool is not needed."
        echo "Please consult the Software Management Manual for more details."
        remove_tmp; exit 1
    fi

    create_tmp
    export_image $2
    remove_tmp

elif [ "$1" = "import" ]; then
    # Check that the input file format is correct
    if [[ ! $2 =~ ^image_.*\.tgz$ ]]; then
        echo "Error: Source file name must conform to image_<uuid>.tgz format and exist in /opt/backups"
        exit 1
    fi

    # Check that the source file exists
    if [ ! -f ${backup_dir}/$2 ]; then
        echo "Error: File $2 does not exists in ${backup_dir}"
        exit 1
    fi

    # Get glance uuid from filename
    uuid=$(echo $2 | sed "s/^image_\(.*\)\.tgz/\1/g")

    # Check that glance has this image in the database
    openstack image show $uuid
    if [ $? -ne 0 ]; then
        echo "Error: Glance image with id: ${uuid} not found. Please try with an existing image id."
        exit 1
    fi

    create_tmp

    # Extract the files that need to be imported into the temp directory
    echo -n "Extracting files..."
    tar xfz ${backup_dir}/$2 -C ${tmp_dir} 1>/dev/null
    if [ $? -ne 0 ]; then
        echo "Error: Failed to extract archive ${backup_dir}/$2 into ${tmp_dir}."
        remove_tmp; exit 1
    fi
    echo "done"

    # Importing images into RBD
    import_image $uuid
    remove_tmp
else
    usage
fi
