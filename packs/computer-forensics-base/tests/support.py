"""Helpers the tests share: run a tool the way the harness does, and build stand-ins.

A tool is a script that reads its arguments as one JSON object on stdin and
prints a JSON result on stdout, run from the run's directory. `run_tool` does
that in a throwaway directory, with a PATH that puts any stand-in programs in
front.
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

PACK_DIR = os.path.abspath(os.environ.get("PACK_DIR") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def tool_path(name):
    return os.path.join(PACK_DIR, "tools", name, "run.py")


def recipe_path(name, entry):
    return os.path.join(PACK_DIR, "recipes", name, entry)


def manifest(name):
    with open(os.path.join(PACK_DIR, "tools", name, "manifest.json"), encoding="utf-8") as fh:
        return json.load(fh)


class Run:
    def __init__(self, proc):
        self.code = proc.returncode
        self.stdout = proc.stdout
        self.stderr = proc.stderr
        try:
            self.json = json.loads(proc.stdout) if proc.stdout.strip() else None
        except ValueError:
            self.json = None


def run_tool(name, args, cwd, path_dirs=(), env=None, timeout=120, raw_input=None, only_path=None):
    """Run tools/<name>/run.py with `args` as JSON on stdin, from `cwd`.
    `path_dirs` go in front of PATH; `only_path` replaces PATH altogether."""
    e = dict(os.environ)
    e["PATH"] = only_path if only_path is not None else os.pathsep.join(list(path_dirs) + [e.get("PATH", "")])
    for k in ("JOB_ID", "OUT", "AGENT_ID"):
        e.pop(k, None)
    e.update(env or {})
    data = raw_input if raw_input is not None else json.dumps(args)
    # TOOL_TEST_TIMEOUT shortens the wait when a test is pointed at code that never answers.
    timeout = min(timeout, int(os.environ.get("TOOL_TEST_TIMEOUT", timeout)))
    try:
        proc = subprocess.run([sys.executable, tool_path(name)], input=data, capture_output=True, text=True,
                              cwd=cwd, env=e, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        proc = subprocess.CompletedProcess(exc.cmd, 124, exc.stdout or "", "timed out after %ds" % timeout)
    return Run(proc)


def stand_in(directory, name, body):
    """A program named `name` in `directory`, a /bin/sh script with `body`."""
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\n" + body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def have(program):
    from shutil import which
    return which(program) is not None


class Case(unittest.TestCase):
    """A test case with a scratch run directory."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def path(self, *parts):
        return os.path.join(self.dir, *parts)

    def read(self, rel, mode="r"):
        """A file's content (a path relative to the scratch directory, or absolute), closed again."""
        with open(rel if os.path.isabs(rel) else self.path(rel), mode) as fh:
            return fh.read()

    def write(self, rel, data):
        full = self.path(rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        return full
