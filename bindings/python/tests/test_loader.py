import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests._support import LIB_ERROR, lsec, requires_lib
from lsec import _loader


class LibraryNameTests(unittest.TestCase):
    def test_windows_names(self):
        self.assertEqual(_loader.library_names("win32"), ["lsec_ffi.dll", "liblsec_ffi.dll"])

    def test_macos_names(self):
        self.assertEqual(_loader.library_names("darwin"), ["liblsec_ffi.dylib"])

    def test_linux_names(self):
        self.assertEqual(_loader.library_names("linux"), ["liblsec_ffi.so"])


class CandidatePathTests(unittest.TestCase):
    def test_dev_tree_target_dirs_are_searched(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(_loader.ENV_LIB_PATH, None)
            os.environ.pop("CARGO_TARGET_DIR", None)
            paths = [str(p) for p in _loader.candidate_paths(["x.lib"])]
        repo_root = Path(_loader.__file__).resolve().parents[3]
        self.assertIn(str(repo_root / "target" / "release" / "x.lib"), paths)
        self.assertIn(str(repo_root / "target" / "debug" / "x.lib"), paths)
        self.assertLess(
            paths.index(str(repo_root / "target" / "release" / "x.lib")),
            paths.index(str(repo_root / "target" / "debug" / "x.lib")),
        )

    def test_env_override_directory_is_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {_loader.ENV_LIB_PATH: tmp}):
                paths = _loader.candidate_paths(["x.lib", "y.lib"])
        self.assertEqual(paths, [Path(tmp) / "x.lib", Path(tmp) / "y.lib"])

    def test_env_override_file_is_exclusive(self):
        target = os.path.join(tempfile.gettempdir(), "custom", "lsec.so")
        with mock.patch.dict(os.environ, {_loader.ENV_LIB_PATH: target}):
            self.assertEqual(_loader.candidate_paths(["x.lib"]), [Path(target)])

    def test_cargo_target_dir_is_searched(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"CARGO_TARGET_DIR": tmp}):
                os.environ.pop(_loader.ENV_LIB_PATH, None)
                paths = _loader.candidate_paths(["x.lib"])
        self.assertIn(Path(tmp) / "release" / "x.lib", paths)

    def test_relative_cargo_target_dir_uses_working_directory(self):
        with mock.patch.dict(os.environ, {"CARGO_TARGET_DIR": "rel-target"}):
            os.environ.pop(_loader.ENV_LIB_PATH, None)
            paths = _loader.candidate_paths(["x.lib"])
        self.assertIn(Path(os.path.abspath("rel-target")) / "release" / "x.lib", paths)


class SourceWorkspaceRootTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name).resolve()

    def _package_dir(self, *parts):
        package_dir = self.tmp.joinpath(*parts)
        package_dir.mkdir(parents=True)
        return package_dir

    def _workspace(self, root, members='["crates/*"]', ffi_crate=True):
        (root / "Cargo.toml").write_text(f"[workspace]\nmembers = {members}\n", encoding="utf-8")
        if ffi_crate:
            crate = root / "crates" / "lsec-ffi"
            crate.mkdir(parents=True)
            (crate / "Cargo.toml").write_text('[package]\nname = "lsec-ffi"\n', encoding="utf-8")

    def test_lsec_checkout_is_accepted(self):
        self._workspace(self.tmp)
        package_dir = self._package_dir("bindings", "python", "lsec")
        self.assertEqual(_loader._source_workspace_root(package_dir), self.tmp)

    def test_checkout_layout_is_case_insensitive(self):
        self._workspace(self.tmp)
        package_dir = self._package_dir("Bindings", "Python", "lsec")
        self.assertEqual(_loader._source_workspace_root(package_dir), self.tmp)

    def test_foreign_workspace_in_checkout_position_is_rejected(self):
        self._workspace(self.tmp, members='["crates/other"]', ffi_crate=False)
        package_dir = self._package_dir("bindings", "python", "lsec")
        self.assertIsNone(_loader._source_workspace_root(package_dir))

    def test_non_workspace_manifest_is_rejected(self):
        self._workspace(self.tmp)
        (self.tmp / "Cargo.toml").write_text('[package]\nname = "x"\n', encoding="utf-8")
        package_dir = self._package_dir("bindings", "python", "lsec")
        self.assertIsNone(_loader._source_workspace_root(package_dir))

    def test_missing_manifest_is_rejected(self):
        package_dir = self._package_dir("bindings", "python", "lsec")
        self.assertIsNone(_loader._source_workspace_root(package_dir))

    def test_installed_package_does_not_walk_up_to_any_workspace(self):
        # even an lsec-looking workspace above site-packages must not be used
        self._workspace(self.tmp)
        package_dir = self._package_dir("venv", "Lib", "site-packages", "lsec")
        self.assertIsNone(_loader._source_workspace_root(package_dir))
        with mock.patch.object(_loader, "__file__", str(package_dir / "_loader.py")):
            with mock.patch.dict(os.environ, {"CARGO_TARGET_DIR": str(self.tmp / "out")}):
                os.environ.pop(_loader.ENV_LIB_PATH, None)
                paths = _loader.candidate_paths(["x.lib"])
        self.assertEqual(paths, [package_dir / "_lib" / "x.lib"])


class FindAndLoadTests(unittest.TestCase):
    def test_bogus_override_raises_with_tried_paths(self):
        bogus = os.path.join(tempfile.gettempdir(), "definitely-not-lsec", "lsec_ffi.dll")
        with mock.patch.dict(os.environ, {_loader.ENV_LIB_PATH: bogus}):
            with self.assertRaises(lsec.LibraryNotFoundError) as ctx:
                _loader.find_and_load()
        self.assertTrue(any("definitely-not-lsec" in entry for entry in ctx.exception.tried))

    @requires_lib
    def test_override_directory_loads_copied_library(self):
        source = Path(lsec.library_path())
        # windows keeps a loaded dll locked, so cleanup is best effort
        tmp = tempfile.mkdtemp(prefix="lsec-loader-")
        self.addCleanup(shutil.rmtree, tmp, True)
        copy = Path(tmp) / source.name
        shutil.copy2(source, copy)
        with mock.patch.dict(os.environ, {_loader.ENV_LIB_PATH: tmp}):
            lib, path = _loader.find_and_load()
        self.assertEqual(Path(path), copy)
        self.assertEqual(lib.lsec_version_major(), lsec.version()[0])

    @requires_lib
    def test_override_file_path(self):
        source = lsec.library_path()
        with mock.patch.dict(os.environ, {_loader.ENV_LIB_PATH: source}):
            _, path = _loader.find_and_load()
        self.assertEqual(path, source)


@requires_lib
class LoadedLibraryTests(unittest.TestCase):
    def test_load_is_cached(self):
        self.assertIs(lsec.load_library(), lsec.load_library())

    def test_version_matches_workspace(self):
        self.assertEqual(lsec.version(), (0, 2, 0))

    def test_harden_process(self):
        lsec.harden_process()


if __name__ == "__main__":
    unittest.main()
