#!/usr/bin/env python3
"""Run one of the memory tools in this process and deliver SIGTERM to it at an exact point of its ending, so a test can hit the
windows a timer hits only by luck (tests/pack-memory-signal-windows.test.ts).

    INJECT_TOOL=<run.py> INJECT_POINT=<point> python3 memory-signal-inject.py   (the tool's arguments on stdin, as for the tool)

The tool's own signal handlers are the ones installed by run_guarded(); the signal is sent with os.kill(getpid()), so it is handled at the
next bytecode, which is the point named. Points:

    after_tmp_open   the hidden temporary file was just created; nothing has wrapped it yet
    before_replace   the hit list is closed and its final name is taken (an empty file), the move onto it has not run
    after_replace    the hit list is under its final name; the object that placed it still thinks it is the temporary
    after_finish     the rows are placed and the paging object has returned
    after_answer     the one answer has been printed
"""
import builtins
import importlib.util
import os
import signal
import sys

tool, point = os.environ["INJECT_TOOL"], os.environ["INJECT_POINT"]
spec = importlib.util.spec_from_file_location("injected_tool", tool)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

state = {"done": False}
real_replace, real_open, real_print = os.replace, os.open, builtins.print


def kill():
    state["done"] = True
    os.kill(os.getpid(), signal.SIGTERM)


def is_final_move(source, target):
    """The move of the finished hidden file onto the name an answer will print (not the move onto a .partial name)."""
    return os.path.basename(str(source)).startswith(".") and not str(target).endswith(".partial") and not os.path.basename(str(target)).startswith(".")


if point == "after_tmp_open":
    def opened(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        if not state["done"] and os.path.basename(str(path)).startswith(".") and args and args[0] & os.O_CREAT:
            kill()
        return fd
    os.open = opened
elif point == "before_replace":
    def before(source, target):
        if not state["done"] and is_final_move(source, target):
            kill()
        return real_replace(source, target)
    os.replace = before
elif point == "after_replace":
    def after(source, target):
        result = real_replace(source, target)
        if not state["done"] and is_final_move(source, target):
            kill()
        return result
    os.replace = after
elif point == "after_finish":
    finish = module.LosslessPage.finish

    def finished(self):
        result = finish(self)
        if not state["done"] and "all_results" in result:
            kill()
        return result
    module.LosslessPage.finish = finished
elif point == "after_answer":
    def printed(*args, **kwargs):
        result = real_print(*args, **kwargs)
        if not state["done"] and args and isinstance(args[0], str) and '"status"' in args[0]:
            kill()
        return result
    module.print = printed
else:
    raise SystemExit("unknown point " + point)

module.run_guarded()
