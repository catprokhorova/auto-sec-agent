"""Auto-sec-agent root package."""

import sys
from pathlib import Path

_deps_dir = Path(__file__).resolve().parent.parent / ".deps"
if _deps_dir.is_dir() and str(_deps_dir) not in sys.path:
    sys.path.insert(0, str(_deps_dir))
