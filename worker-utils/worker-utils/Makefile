#
# SPDX-License-Identifier: Apache-2.0
#

BINDIR ?= /usr/bin
INITDDIR ?= /etc/init.d/
GOENABLEDDIR ?= /etc/goenabled.d/
PLATFORMCONFDIR ?= /etc/platform
SYSTEMDDIR ?= /usr/lib/systemd/system/

all:
	python -m compileall topology.py

install:
	install -d -m 755 $(BINDIR)
	install -d -m 755 $(INITDDIR)
	install -d -m 755 $(GOENABLEDDIR)
	install -d -m 755 $(PLATFORMCONFDIR)
	install -d -m 755 $(SYSTEMDDIR)
	install -p -D -m 755 affine-platform.sh $(INITDDIR)/affine-platform.sh
	install -p -D -m 755 affine-tasks.sh $(INITDDIR)/affine-tasks.sh
	install -p -D -m 755 cpumap_functions.sh $(INITDDIR)/cpumap_functions.sh
	install -p -D -m 755 task_affinity_functions.sh $(INITDDIR)/task_affinity_functions.sh
	install -p -D -m 755 ps-sched.sh $(BINDIR)/ps-sched.sh
	install -p -D -m 755 topology.py $(BINDIR)/topology.py
	install -p -D -m 755 topology.pyc $(BINDIR)/topology.pyc
	install -p -D -m 755 affine-interrupts.sh $(BINDIR)/affine-interrupts.sh
	install -p -D -m 755 set-cpu-wakeup-latency.sh $(BINDIR)/set-cpu-wakeup-latency.sh
	install -p -D -m 755 topology $(BINDIR)/topology
	install -p -D -m 755 worker_reserved.conf $(PLATFORMCONFDIR)/worker_reserved.conf
	install -p -D -m 755 worker-goenabled.sh $(GOENABLEDDIR)/worker-goenabled.sh
	install -p -D -m 664 affine-platform.sh.service $(SYSTEMDDIR)/affine-platform.sh.service
	install -p -D -m 664 affine-tasks.service $(SYSTEMDDIR)/affine-tasks.service
