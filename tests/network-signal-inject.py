#!/usr/bin/env python3
"""Run one of the network scripts as __main__ in this process and deliver a stop signal to it at an exact point, so a test can hit the windows a timer
hits only by luck (tests/pack-network-stop-signals.test.ts).

    INJECT_TOOL=<run.py> INJECT_POINT=<point> python3 network-signal-inject.py   (the tool's arguments on stdin, as for the tool)

The signal is sent with os.kill(getpid()), so the tool's handler runs at the next bytecode, which is the point named. Points:

    during_imports   the first import the script makes after its early stop handler is installed (the heavy imports are still to come)
    second_signal    the same, and a SECOND signal (SIGINT) arrives while the early answer is being written
    during_args      the arguments are being read (json.load): network_log_summary only
    after_makedirs   the output directory was just made: network_log_summary only
    after_tmp_open   the hidden temporary file of a paging object was just created, nothing has registered it yet
    before_replace   the finished hidden file is about to be moved onto its final name
    fsize            no signal: the file size limit (INJECT_FSIZE bytes, default 4096) is set, SIGXFSZ is ignored, and a write past it fails
                     with EFBIG, so a paging object has to give up its file

INJECT_SIGNAL (default SIGTERM) names the signal.
"""
import builtins
import os
import runpy
import signal
import sys

tool, point = os.environ["INJECT_TOOL"], os.environ["INJECT_POINT"]
signum = getattr(signal, os.environ.get("INJECT_SIGNAL", "SIGTERM"))
state = {"done": False}
real_open, real_replace, real_import, real_makedirs = os.open, os.replace, builtins.__import__, os.makedirs
EARLY = ("atexit", "json", "os", "signal", "sys")   # (atexit: the shared ENDS block, before the tool's own early handler)


def kill():
    state["done"] = True
    os.kill(os.getpid(), signum)


def from_tool(namespace):
    return namespace is not None and namespace.get("__file__") == tool


if point in ("during_imports", "second_signal"):
    def hooked(name, globals=None, locals=None, fromlist=(), level=0):
        if not state["done"] and from_tool(globals) and name.split(".")[0] not in EARLY:
            kill()
        return real_import(name, globals, locals, fromlist, level)
    builtins.__import__ = hooked
    if point == "second_signal":
        class Writer:
            """A stdout that takes a second stop signal in the middle of the first answer."""

            def __init__(self, inner):
                self.inner, self.sent = inner, False

            def write(self, text):
                if not self.sent:
                    self.sent = True
                    os.kill(os.getpid(), signal.SIGINT)
                return self.inner.write(text)

            def __getattr__(self, name):
                return getattr(self.inner, name)
        sys.stdout = Writer(sys.stdout)
elif point == "second_in_answer":
    # the first signal (INJECT_SIGNAL) is sent once main() has installed its own handlers (the HUP handler is the last of the three); the second
    # (INJECT_SECOND) arrives while the answer to the first is being written
    real_signal = signal.signal
    second = getattr(signal, os.environ.get("INJECT_SECOND", "SIGINT"))

    def watching(sig, handler):
        previous = real_signal(sig, handler)
        # not the early handlers: the tool's own _before_start, and the shared ENDS block's (its handler before the tool's own, and the one
        # that does nothing once an answer is held)
        if (not state["done"] and sig == signal.SIGHUP and callable(handler)
                and getattr(handler, "__name__", "") not in ("_before_start", "_stopped_without_handler", "_ending_nothing")
                and getattr(handler, "__module__", None) != "builtins"):
            kill()
        return previous
    signal.signal = watching

    class Writer2:
        def __init__(self, inner):
            self.inner, self.sent = inner, False

        def write(self, text):
            if state["done"] and not self.sent:
                self.sent = True
                os.kill(os.getpid(), second)
            return self.inner.write(text)

        def __getattr__(self, name):
            return getattr(self.inner, name)
    sys.stdout = Writer2(sys.stdout)
elif point == "after_values_open":
    def values_opened(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        if not state["done"] and os.path.basename(str(path)) == "network-log-values.jsonl":
            kill()
        return fd
    os.open = values_opened
elif point == "isfile_true":
    # no signal: os.path.isfile says yes for the paths that end with INJECT_ISFILE_SUFFIX (all of them when it is empty), as it would for a name that was a regular
    # file when it was checked and a pipe by the time it is opened
    suffix = os.environ.get("INJECT_ISFILE_SUFFIX", "")
    real_isfile = os.path.isfile
    os.path.isfile = lambda p: True if str(p).endswith(suffix) else real_isfile(p)
elif point == "during_args":
    import json
    real_load = json.load

    def load(*args, **kwargs):
        if not state["done"]:
            kill()
        return real_load(*args, **kwargs)
    json.load = load
elif point == "after_makedirs":
    def made(*args, **kwargs):
        result = real_makedirs(*args, **kwargs)
        if not state["done"]:
            kill()
        return result
    os.makedirs = made
elif point == "after_tmp_open":
    def opened(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        if not state["done"] and os.path.basename(str(path)).startswith(".") and args and args[0] & os.O_CREAT:
            kill()
        return fd
    os.open = opened
elif point == "before_replace":
    def before(source, target):
        if not state["done"] and os.path.basename(str(source)).startswith(".") and not os.path.basename(str(target)).startswith("."):
            kill()
        return real_replace(source, target)
    os.replace = before
elif point == "fsize":
    import resource
    limit = int(os.environ.get("INJECT_FSIZE", "4096"))
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
else:
    raise SystemExit("unknown point " + point)

sys.argv = [tool] + sys.argv[1:]
runpy.run_path(tool, run_name="__main__")
