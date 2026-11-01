"""The peak resident size of a process, for the tests that bound a tool's memory.

Why not getrusage(...).ru_maxrss: on Linux it keeps the size of the process image
that was REPLACED by exec. A child forked (or vfork-ed) from a parent that holds
160 MB is counted at 160 MB although the tool it becomes needs 20, and which
parent that is depends on the host and on what the test was holding. VmHWM in
/proc/<pid>/status is the high-water mark of the image the process runs now.

  self_peak_bytes()            this process's own peak (VmHWM; ru_maxrss where /proc is not there)
  run_peak(args, ...)          subprocess.run, which also returns the child's own peak in bytes
                               (VmHWM sampled while it runs; the child's rusage where /proc is not there)

On macOS there is no /proc and no inherited-image peak, so ru_maxrss (bytes there) is
used. The sample is taken every millisecond: the mark only rises, so a sample is
never above the true peak, and a peak reached in the last millisecond of a run can
be missed (the reading is then low, never high; a child that ends before its first
sample reads 0).

Only the direct child is sampled: the memory of a grandchild it starts (an engine behind a
wrapper) is not counted, where ru_maxrss of children counted every descendant that was waited for.

Used two ways: imported by name (tests/fixtures is on sys.path when a script of it
runs), or prepended as text to a `python3 -c` wrapper (tests/peak-rss.ts: peakRssPrelude()).
"""
import os
import subprocess
import sys
import threading

HAVE_PROC = os.path.exists("/proc/self/status")


def _vmhwm(pid):
    """VmHWM of a live process in bytes, or None (no /proc, no such process, a zombie)."""
    try:
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def _rusage_bytes(who):
    import resource

    raw = resource.getrusage(who).ru_maxrss
    return raw if sys.platform == "darwin" else raw * 1024


def self_peak_bytes():
    """The peak of this process's own image."""
    peak = _vmhwm(os.getpid())
    if peak is not None:
        return peak
    import resource

    return _rusage_bytes(resource.RUSAGE_SELF)


class _Sampler(threading.Thread):
    def __init__(self, pid):
        super().__init__(daemon=True)
        self.pid = pid
        self.peak = None
        self.halt = threading.Event()

    def run(self):
        while True:
            v = _vmhwm(self.pid)
            if v is not None and (self.peak is None or v > self.peak):
                self.peak = v
            if self.halt.wait(0.001):
                return


def _peak_of(sampler):
    sampler.halt.set()
    sampler.join(2)
    if sampler.peak is not None:
        return sampler.peak
    if HAVE_PROC:
        return 0
    import resource

    return _rusage_bytes(resource.RUSAGE_CHILDREN)


def run_peak(args, input=None, capture_output=False, timeout=None, **kw):
    """subprocess.run(...) -> (CompletedProcess, the child's own peak in bytes).

    Popen returns once the child has exec-ed, so every sample is of the new image.
    On a timeout the child is killed and subprocess.TimeoutExpired is raised as run()
    does, with the peak on the exception as .peak_bytes.
    """
    if capture_output:
        kw["stdout"] = subprocess.PIPE
        kw["stderr"] = subprocess.PIPE
    if input is not None:
        kw["stdin"] = subprocess.PIPE
    with subprocess.Popen(args, **kw) as proc:
        sampler = _Sampler(proc.pid)
        sampler.start()
        try:
            stdout, stderr = proc.communicate(input, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            proc.kill()
            exc.stdout, exc.stderr = proc.communicate()
            exc.peak_bytes = _peak_of(sampler)
            raise
        except BaseException:
            proc.kill()
            sampler.halt.set()
            raise
        code = proc.poll()
    return subprocess.CompletedProcess(proc.args, code, stdout, stderr), _peak_of(sampler)
