#!/usr/bin/env python3
"""Run one of the cloud tools in this process with a clock already out, so a test reaches the time-limit path whatever the speed of the
machine it runs on (tests/pack-cloud-cloudtrail-parse.test.ts, pack-cloud-ual-parse.test.ts, pack-cloud-signin-analyse.test.ts).

    INJECT_TOOL=<run.py> python3 cloud-clock-inject.py     (the tool's arguments on stdin, as for the tool)

The read's clock (the default). The tool's `start_clock` is replaced, in the tool's own globals, by one that also sets the deadline a second
in the past, and its `out_of_time` answers true from then on: after the directory has been listed, when the tool lists one (the listing is
under the clock too, and a clock that is out before the listing is another case), and before the first file is read. The tool's own later
resets of its deadline do not matter: the clock has run out before the first file, so the answer is the one a tool gives when its own limit
ended the read, not one that depends on how much a runner reads in a second.

The analysis clock (signin_analyse, which analyses after the read, under a clock of its own: ANALYSIS_DEADLINE and analysis_out_of_time).
The read runs on its own clock, untouched; INJECT_ANALYSIS says when the analysis clock runs out:

    INJECT_ANALYSIS=expired     the analysis clock is out when `analyse` starts (the database's sort is under it too)
    INJECT_ANALYSIS=after:N     the analysis clock is out after N accounts have had their turn
"""
import importlib.util
import os
import time

tool = os.environ["INJECT_TOOL"]
spec = importlib.util.spec_from_file_location("injected_tool", tool)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

g = module.main.__globals__
analysis = os.environ.get("INJECT_ANALYSIS")

if analysis:
    if analysis == "expired":
        real_analyse = g["analyse"]

        def analyse_with_the_clock_out(*args, **kwargs):
            module.ANALYSIS_DEADLINE[0] = time.monotonic() - 1.0
            return real_analyse(*args, **kwargs)

        g["analyse"] = analyse_with_the_clock_out
    elif analysis.startswith("after:"):
        turns = {"left": int(analysis.split(":", 1)[1])}

        def analysis_out_of_time():
            if turns["left"] > 0:
                turns["left"] -= 1
                return False
            return True

        g["analysis_out_of_time"] = analysis_out_of_time
    else:
        raise SystemExit("INJECT_ANALYSIS is expired or after:N")
else:
    armed = {"on": False}
    real_start_clock = g["start_clock"]
    real_out_of_time = g["out_of_time"]
    real_walk = g.get("walk_inputs")

    def start_clock_in_the_past(args, *rest, **kwargs):
        seconds = real_start_clock(args, *rest, **kwargs)   # the arguments are still checked as the tool checks them
        module.DEADLINE[0] = time.monotonic() - 1.0
        if real_walk is None:
            armed["on"] = True                              # a tool that lists nothing: out from the start
        return seconds

    def out_of_time():
        return armed["on"] or real_out_of_time()

    g["start_clock"] = start_clock_in_the_past
    g["out_of_time"] = out_of_time

    if real_walk is not None:
        def walk_then_expire(top, wanted, skipped):
            armed["on"] = False
            saved = module.DEADLINE[0]
            module.DEADLINE[0] = time.monotonic() + 3600.0  # the listing runs on a clock that has not run out
            try:
                return real_walk(top, wanted, skipped)
            finally:
                module.DEADLINE[0] = saved
                armed["on"] = True                          # and the clock is out when the first file is to be read
        g["walk_inputs"] = walk_then_expire

try:
    module.main()
except SystemExit:
    raise
except Exception as exc:  # the tool's own wrapper says the same
    module.fail("unexpected failure: %s: %s" % (type(exc).__name__, module.scrub(str(exc))))
