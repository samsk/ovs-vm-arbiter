"""Tests for src.tests runner."""
import contextlib
import io
import types
import importlib
import pkgutil
from unittest.mock import patch

from src import tests as tests_mod
from src.test import _test_assert


def test_run_tests_prefers_package_test_on_name_collision() -> None:
    """run_tests keeps package test when local test_* has same name."""
    fake_pkg = types.SimpleNamespace(__file__="/tmp/fake_pkg/__init__.py")
    package_calls: list[str] = []

    def package_test() -> None:
        package_calls.append("package")

    def local_test() -> None:
        package_calls.append("local")

    fake_mod = types.SimpleNamespace(test_dup=package_test)
    setattr(tests_mod, "test_dup", local_test)
    called_names: list[str] = []

    def fake_run_one(name: str, fn: object) -> tuple[bool, str | None]:
        called_names.append(name)
        return True, None

    real_import_module = importlib.import_module

    def fake_import_module(name: str) -> object:
        if name == "src.test":
            return fake_pkg
        if name == "src.test.fake_mod":
            return fake_mod
        return real_import_module(name)

    try:
        with patch("pkgutil.iter_modules", return_value=[(None, "fake_mod", False)]):
            with patch("importlib.import_module", side_effect=fake_import_module):
                with patch("src.tests._run_one", side_effect=fake_run_one):
                    rc = tests_mod.run_tests()
    finally:
        delattr(tests_mod, "test_dup")
    _test_assert(rc == 0, "run_tests return code")
    _test_assert("fake_mod.test_dup" in called_names, "package test selected")
    _test_assert("test_dup" not in called_names, "local duplicate skipped")


def test_run_tests_fails_when_test_submodule_import_fails() -> None:
    """Broken src.test.<mod> import fails discovery with rc=1."""
    import importlib

    real_import = importlib.import_module

    def fake_import(name: str) -> object:
        if name == "src.test.broken_mod":
            raise ImportError("splode")
        return real_import(name)

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        with patch("importlib.import_module", side_effect=fake_import):
            with patch.object(pkgutil, "iter_modules", return_value=[(None, "broken_mod", False)]):
                rc = tests_mod.run_tests()
    _test_assert(rc == 1, "non-zero when submodule import fails")
    _test_assert("broken_mod" in buf.getvalue(), "stdout mentions broken module")
