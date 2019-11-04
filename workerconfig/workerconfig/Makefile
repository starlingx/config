#
# SPDX-License-Identifier: Apache-2.0
#

INITDDIR ?= /etc/init.d/
GOENABLEDDIR ?= /etc/goenabled.d/
SYSTEMDDIR ?= /etc/systemd/system/

install:
	install -d -m 755 $(INITDDIR)
	install -d -m 755 $(GOENABLEDDIR)
	install -d -m 755 $(SYSTEMDDIR)
	install -d -m 755 $(SYSTEMDDIR)/config
	install -p -D -m 700 worker_config $(INITDDIR)/worker_config
	install -p -D -m 755 config_goenabled_check.sh $(GOENABLEDDIR)/config_goenabled_check.sh
	install -p -D -m 664 workerconfig.service $(SYSTEMDDIR)/config/workerconfig-standalone.service
	install -p -D -m 664 workerconfig-combined.service $(SYSTEMDDIR)/config/workerconfig-combined.service
