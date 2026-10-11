"""Acceptance runner: failed, errored or skipped tests fail the gate."""
from pathlib import Path
import sys
import unittest

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
suite = unittest.defaultTestLoader.discover(str(root / "tests"))
result = unittest.TextTestRunner(verbosity=2).run(suite)
if result.skipped:
    print("Acceptance requires zero skipped tests", file=sys.stderr)
raise SystemExit(0 if result.wasSuccessful() and not result.skipped else 1)
