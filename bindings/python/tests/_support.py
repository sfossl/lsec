import os
import sys
import unittest
from pathlib import Path

# make the in-tree package importable without installing it
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

import lsec  # noqa: E402

try:
    lsec.load_library()
    LIB_ERROR = None
except lsec.LibraryNotFoundError as exc:
    LIB_ERROR = exc

if LIB_ERROR is not None and os.environ.get("LSEC_REQUIRE_LIB") == "1":
    raise RuntimeError(f"LSEC_REQUIRE_LIB=1 but the native library is unavailable: {LIB_ERROR}")

requires_lib = unittest.skipIf(LIB_ERROR is not None, f"lsec_ffi not available: {LIB_ERROR}")
