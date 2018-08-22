#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import setuptools



setuptools.setup(
    name='cgtsclient',
    description='Titanium Cloud System Client and CLI',
    classifiers=[
        'Environment :: OpenStack',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: windriver',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 2.6',
    ],
    include_package_data=True,
    setup_requires=['pbr>=0.5'],
    pbr=True,
    packages=setuptools.find_packages()
)
