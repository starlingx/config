#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2019 Intel Corporation
#

BINDIR ?= /usr/local/bin
CONFIGDIR ?= /etc/puppet
MODULEDIR ?= /usr/share/puppet/modules

install:
	install -m 755 -D bin/puppet-manifest-apply.sh $(BINDIR)/puppet-manifest-apply.sh
	install -m 755 -D bin/apply_network_config.sh $(BINDIR)/apply_network_config.sh
	install -d -m 0755 $(CONFIGDIR)
	install -m 640 etc/hiera.yaml $(CONFIGDIR)/
	cp -R hieradata $(CONFIGDIR)/
	cp -R manifests $(CONFIGDIR)/
	install -d -m 0755 $(MODULEDIR)
	cp -R modules/platform $(MODULEDIR)/
	cp -R modules/openstack $(MODULEDIR)/
