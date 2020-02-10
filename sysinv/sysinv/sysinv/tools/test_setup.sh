#!/bin/bash

# This script allows a developer to setup their DB for opportunistic tests
# openstack_citest is used by oslo_db for opportunistic db tests.
# This method is based on code in neutron/tools

# Set env variable for MYSQL_PASSWORD
MYSQL_PASSWORD=${MYSQL_PASSWORD:-stackdb}

function _install_mysql {
    echo "Installing MySQL database"


    # Set up the 'openstack_citest' user and database in postgres
    tmp_dir=$(mktemp -d)
    trap "rm -rf $tmp_dir" EXIT

    cat << EOF > $tmp_dir/mysql.sql
DROP DATABASE IF EXISTS openstack_citest;
CREATE DATABASE openstack_citest;
CREATE USER 'openstack_citest'@'localhost' IDENTIFIED BY 'openstack_citest';
CREATE USER 'openstack_citest' IDENTIFIED BY 'openstack_citest';
GRANT ALL PRIVILEGES ON *.* TO 'openstack_citest'@'localhost';
GRANT ALL PRIVILEGES ON *.* TO 'openstack_citest';
FLUSH PRIVILEGES;
EOF
    /usr/bin/mysql -u root -p"$MYSQL_PASSWORD" < $tmp_dir/mysql.sql

}

function _install_postgres {
    echo "Installing Postgres database"

    tmp_dir=$(mktemp -d)
    trap "rm -rf $tmp_dir" EXIT

    cat << EOF > $tmp_dir/postgresql.sql
CREATE USER openstack_citest WITH CREATEDB LOGIN PASSWORD 'openstack_citest';
CREATE DATABASE openstack_citest WITH OWNER openstack_citest;
EOF
    chmod 777 $tmp_dir/postgresql.sql
    sudo -u postgres /usr/bin/psql --file=$tmp_dir/postgresql.sql
}

echo "TODO:  Add getopts support to select which DB you want to install"

echo "MYSQL"
_install_mysql

echo "POSTGRES"
_install_postgres
