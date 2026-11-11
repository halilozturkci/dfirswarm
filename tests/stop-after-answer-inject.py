#!/usr/bin/env python3
"""Run a pack tool or recipe as __main__ in this process, and send a stop signal to this process the moment the first write to its standard
output has gone out (the first byte of its answer), so that the moment a loaded runner reaches only by luck is reached every time
(tests/pack-stop-after-answer.test.ts). The signal is sent with os.kill(getpid()): a handler that is still in runs at the next bytecode.

    INJECT_SIGNAL=SIGTERM python3 stop-after-answer-inject.py <run.py> [argument ...]   (a tool's arguments on stdin, as for the tool)

A tool that writes its answer with os.write on descriptor 1 (the mobile pack's) gets no signal from here: the test sends it one from outside
as well, the moment it has read a whole document.
"""
import os
import runpy
import signal
import sys

tool = sys.argv[1]
signum = getattr(signal, os.environ.get("INJECT_SIGNAL", "SIGTERM"))


class After:
    """A standard output that sends the signal once its first write has gone out."""

    def __init__(self, inner):
        self.inner, self.sent = inner, False

    def write(self, text):
        written = self.inner.write(text)
        if not self.sent:
            self.sent = True
            try:
                self.inner.flush()
            except (OSError, ValueError):
                pass
            os.kill(os.getpid(), signum)
        return written

    def __getattr__(self, name):
        if name == "inner":
            raise AttributeError(name)
        return getattr(self.inner, name)


sys.stdout = After(sys.stdout)
sys.argv = [tool] + sys.argv[2:]
sys.path.insert(0, os.path.dirname(os.path.abspath(tool)))
runpy.run_path(tool, run_name="__main__")
