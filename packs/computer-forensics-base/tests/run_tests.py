"""Run every test_*.py beside this file with unittest and say what ran.

The tests are stdlib unittest so a pack's tests need nothing installed. Each
module reaches the tools through support.py, which reads PACK_DIR.
"""
import os
import sys
import unittest

here = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)
suite = unittest.defaultTestLoader.discover(here, pattern="test_*.py")
result = unittest.TextTestRunner(verbosity=1, stream=sys.stderr).run(suite)
if not result.wasSuccessful():
    print("FAIL: %d failures, %d errors" % (len(result.failures), len(result.errors)), file=sys.stderr)
    sys.exit(1)
print("ok - %d base pack tests passed (%d skipped)" % (result.testsRun, len(result.skipped)))
