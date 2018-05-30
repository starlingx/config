import sys

from common import log

LOG = log.get_logger(__name__)


class ProgressRunner(object):
    steps = []

    def add(self, action, message):
        self.steps.append((action, message))

    def run(self):
        total = len(self.steps)
        for i, step in enumerate(self.steps, start=1):
            action, message = step
            LOG.info("Start step: %s" % message)
            sys.stdout.write(
                "\n%.2u/%.2u: %s ... " % (i, total, message))
            sys.stdout.flush()
            try:
                action()
                sys.stdout.write('DONE')
                sys.stdout.flush()
            except Exception:
                sys.stdout.flush()
                raise
            LOG.info("Finish step: %s" % message)
        sys.stdout.write("\n")
        sys.stdout.flush()
