#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import setuptools

setuptools.setup(
    name='cgtsclient',
    description='CGCS System Client and CLI',
    version='1.0.0',
    license='Apache-2.0',
    packages=['cgtsclient', 'cgtsclient.v1', 'cgtsclient.openstack',
              'cgtsclient.openstack.common',
              'cgtsclient.openstack.common.config',
              'cgtsclient.openstack.common.rootwrap',
              'cgtsclient.common'],
    entry_points={
         'console_scripts': [
             'system = cgtsclient.shell:main'
         ]}
)
