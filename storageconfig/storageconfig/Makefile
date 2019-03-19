#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2019 Intel Corporation
#

INITDDIR ?= /etc/init.d/
GOENABLEDDIR ?= /etc/goenabled.d/
SYSTEMDDIR ?= /etc/systemd/system/

install:
	install -d -m 755 $(INITDDIR)
	install -p -D -m 700 storage_config $(INITDDIR)/storage_config
	install -d -m 755 $(GOENABLEDDIR)
	install -p -D -m 755 config_goenabled_check.sh $(GOENABLEDDIR)/config_goenabled_check.sh
	install -d -m 755 $(SYSTEMDDIR)
	install -p -D -m 664 storageconfig.service $(SYSTEMDDIR)/storageconfig.service
