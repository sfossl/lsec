from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
import threading
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from .errors import LibraryNotFoundError

ENV_LIB_PATH = "LSEC_LIB_PATH"
LIB_STEM = "lsec_ffi"
FFI_CRATE_DIR = ("crates", "lsec-ffi")

_lock = threading.Lock()
_lib: Optional[ctypes.CDLL] = None
_lib_path: Optional[str] = None


def library_names(platform: Optional[str] = None) -> List[str]:
    """Shared library file names lsec_ffi may be built as on ``platform``."""
    platform = platform or sys.platform
    if platform.startswith("win"):
        # msvc targets emit lsec_ffi.dll, some gnu setups add the lib prefix
        return [f"{LIB_STEM}.dll", f"lib{LIB_STEM}.dll"]
    if platform == "darwin":
        return [f"lib{LIB_STEM}.dylib"]
    return [f"lib{LIB_STEM}.so"]


def _files_in(directory: Path, names: Sequence[str]) -> List[Path]:
    return [Path(directory) / name for name in names]


def _source_workspace_root(package_dir: Path) -> Optional[Path]:
    """The lsec repo root when running from a source checkout, else None.

    Only the fixed checkout layout (<root>/bindings/python/lsec) is accepted, and the
    root must be lsec's own cargo workspace with the lsec-ffi crate in it. Walking
    further up would let any unrelated workspace above an installed package supply
    the native library. Other layouts (strict editable installs, a venv inside the
    repo) should point LSEC_LIB_PATH at the build output.
    """
    # case-insensitive so a checkout reached via e.g. .../Bindings/Python still counts
    if (
        package_dir.parent.name.lower() != "python"
        or package_dir.parent.parent.name.lower() != "bindings"
    ):
        return None
    root = package_dir.parents[2]
    try:
        is_workspace = "[workspace]" in (root / "Cargo.toml").read_text(encoding="utf-8")
    except OSError:
        return None
    if not is_workspace or not root.joinpath(*FFI_CRATE_DIR, "Cargo.toml").is_file():
        return None
    return root


def candidate_paths(names: Optional[Sequence[str]] = None) -> List[Path]:
    """Ordered file paths to try: env override (exclusive), else bundled then dev tree."""
    names = names or library_names()

    override = os.environ.get(ENV_LIB_PATH)
    if override:
        override_path = Path(override)
        if override_path.is_dir():
            return _files_in(override_path, names)
        return [override_path]

    package_dir = Path(__file__).resolve().parent
    candidates = _files_in(package_dir / "_lib", names)

    root = _source_workspace_root(package_dir)
    if root is not None:
        target_dirs = []
        cargo_target = os.environ.get("CARGO_TARGET_DIR")
        if cargo_target:
            # cargo resolves a relative CARGO_TARGET_DIR against the working directory
            target_dir = Path(os.path.abspath(cargo_target))
            target_dirs.append(target_dir)
        target_dirs.append(root / "target")
        for target_dir in target_dirs:
            for profile in ("release", "debug"):
                candidates.extend(_files_in(target_dir / profile, names))

    return candidates


def _load_file(path: Path) -> ctypes.CDLL:
    # python 3.8+ resolves an absolute dll's own dependencies from its directory
    return ctypes.CDLL(str(path))


def find_and_load() -> Tuple[ctypes.CDLL, str]:
    """Locate and load lsec_ffi, raising LibraryNotFoundError with every path tried."""
    names = library_names()
    tried = []

    for path in candidate_paths(names):
        if not path.is_file():
            tried.append(f"{path} (missing)")
            continue
        try:
            return _load_file(path), str(path)
        except OSError as exc:
            tried.append(f"{path} ({exc})")

    if os.environ.get(ENV_LIB_PATH):
        # an explicit override that failed must not silently fall back to another copy
        raise LibraryNotFoundError(tried=tried)

    system_names = []
    found = ctypes.util.find_library(LIB_STEM)
    if found:
        system_names.append(found)
    system_names.extend(names)

    for name in system_names:
        try:
            return ctypes.CDLL(name), name
        except OSError as exc:
            tried.append(f"{name} via system search path ({exc})")

    raise LibraryNotFoundError(tried=tried)


def load_library() -> ctypes.CDLL:
    """Return the process-wide lsec_ffi handle, loading it on first use."""
    global _lib, _lib_path
    if _lib is None:
        with _lock:
            if _lib is None:
                lib, path = find_and_load()
                from ._ffi import declare_signatures

                declare_signatures(lib)
                _lib_path = path
                _lib = lib
    return _lib


def library_path() -> str:
    """Path of the loaded library (loads it if needed)."""
    load_library()
    assert _lib_path is not None
    return _lib_path
