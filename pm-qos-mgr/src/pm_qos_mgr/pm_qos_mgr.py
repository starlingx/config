#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Purpose:
# This manager watches for changes in /var/lib/kubelet/cpu_manager_state file.
# This sets appropriate PM QoS resume latency constraints for CPUs
# when kubelet cpu-manager is configured with 'static' policy.
#
# This parses the cpu_manager_state file, deduces the cpu-manager policy,
# and CPU lists of Guaranteed pods versus the remaining Default CPUs.
# Guaranteed pods with exclusive CPUs get "low" cpu wakeup latency policy.
# Default CPUs get "high" cpu wakeup latency policy.

import itertools as it
import json
import logging
import logging.handlers
import os
import pyinotify
import subprocess
import sys

# Global variables
statefile = '/var/lib/kubelet/cpu_manager_state'
pm_script = '/usr/bin/set-cpu-wakeup-latency.sh'

LOG = logging.getLogger(__name__)

def configure_logging(logger, level=logging.DEBUG):
    """ Configure logger streams and format. """
    LOG.setLevel(level)

    syslog_facility = logging.handlers.SysLogHandler.LOG_DAEMON
    ch = logging.handlers.SysLogHandler(address='/dev/log',
                                        facility=syslog_facility)
    ch.setLevel(level)
    formatter = logging.Formatter('%(module)s[%(process)d]: %(message)s')
    ch.setFormatter(formatter)
    LOG.addHandler(ch)


def format_range_set(items):
    """ Generate pretty-printed value of ranges, such as 3-6,12-17. """
    ranges = []
    for k, iterable in it.groupby(enumerate(sorted(items)),
                                  lambda x: x[1] - x[0]):
        rng = list(iterable)
        if len(rng) == 1:
            s = str(rng[0][1])
        else:
            s = "%s-%s" % (rng[0][1], rng[-1][1])
        ranges.append(s)
    return ','.join(ranges)


def range_to_list(csv_range=None):
    """ Convert a string of comma separate ranges into an expanded list
        of integers. e.g., '1-3,8-9,15' is converted to [1,2,3,8,9,15].
    """
    if not csv_range:
        return []
    ranges = [(lambda L: range(L[0], L[-1] + 1))(map(int, r.split('-')))
              for r in csv_range.split(',')]
    return [y for x in ranges for y in x]


class ProcessTransientFile(pyinotify.ProcessEvent):
    def __init__(self, *args, **kw):
        self.policy = None
        self.cpusets = {'default': set(),
                        'guaranteed': set()}
        self.update_pm_qos_cpu_latency()

    def update_pm_qos_cpu_latency(self, event=None):
        if self.policy is not None and self.policy != 'static':
            return
        if event is not None:
            LOG.debug('%s, %s', event.pathname, event.maskname)

        # Read JSON formatted state file dictionary
        state = {}
        try:
            with open(statefile, 'r') as f:
                state = json.load(f)
        except Exception as e:
            LOG.error('Could not load: %s, error: %s.', statefile, e)
            return

        self.policy = str(state['policyName'])
        if self.policy != 'static':
            return

        # Determine default cpuset
        if 'defaultCpuSet' not in state:
            LOG.error('Missing defaultCpuSet.', statefile)
            return
        default_cpuranges = str(state['defaultCpuSet'])
        default_cpuset = set(range_to_list(csv_range=default_cpuranges))

        # Determine guaranteed cpuset
        guaranteed_cpuset = set()
        if 'entries' in state:
            for pod, cpus in state['entries'].items():
                cpulist = range_to_list(csv_range=cpus)
                guaranteed_cpuset.update(cpulist)
        guaranteed_cpuranges = format_range_set(guaranteed_cpuset)

        # Update PM QoS resume latency if the set of cpus have changed
        if default_cpuset != self.cpusets['default']:
            self.cpusets['default'] = default_cpuset.copy()
            if default_cpuset:
                pm_policy = 'high'
                LOG.info('Set PM policy: %s, CPUs: %s',
                         pm_policy, default_cpuranges)
                command = [pm_script, pm_policy, default_cpuranges]
                proc = subprocess.Popen(command, stdout=subprocess.PIPE)
                output, errors = proc.communicate()
                if errors:
                    LOG.error('Problem with command: %s, error: %s',
                              command, errors)

        if guaranteed_cpuset != self.cpusets['guaranteed']:
            self.cpusets['guaranteed'] = guaranteed_cpuset.copy()
            if guaranteed_cpuset:
                pm_policy = 'low'
                LOG.info('Set PM policy: %s, CPUs: %s',
                         pm_policy, guaranteed_cpuranges)
                command = [pm_script, pm_policy, guaranteed_cpuranges]
                proc = subprocess.Popen(command, stdout=subprocess.PIPE)
                output, errors = proc.communicate()
                if errors:
                    LOG.error('Problem with command: %s, error: %s',
                              command, errors)

    def process_IN_MOVED_TO(self, event):
        """ Handler for watched IN_MOVED_TO events.

        kubelet cpu-manager overwrites state-file by moving a temp file,
        so this is the expected handler.
        """
        self.update_pm_qos_cpu_latency(event)


def main():
    """ A shell command for pm-qos-daemon. """
    configure_logging(LOG, level=logging.INFO)
    if os.geteuid() != 0:
        LOG.error('Require sudo/root.')
        sys.exit(1)

    LOG.info('Watching: %s', statefile)
    watch_manager = pyinotify.WatchManager()
    notifier = pyinotify.Notifier(watch_manager)
    flags = pyinotify.IN_MOVED_TO
    watch_manager.watch_transient_file(statefile, flags, ProcessTransientFile)

    try:
        notifier.loop()
    except pyinotify.NotifierError, err:
        LOG.error('Problem with notifier.loop(), error: %s', err)

if __name__ == "__main__":
    main()
