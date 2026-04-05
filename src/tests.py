import os
import sys
from typing import Callable, Optional

# --- Built-in test framework (--test) -----------------------------------------

def _test_assert(cond: bool, msg: str) -> None:
    """Raise AssertionError if cond is False."""
    if not cond:
        raise AssertionError(msg)


def _run_one(name: str, fn: Callable[[], None]) -> tuple[bool, Optional[str]]:
    """Run single test; return (ok, error_msg)."""
    try:
        fn()
        return True, None
    except Exception as e:
        return False, str(e)


def run_tests() -> int:
    """Run all test_* from this module and from src.test.*; return 0 if all pass else 1."""
    import importlib
    import pkgutil

    tests: list[tuple[str, Callable[[], None]]] = []
    package_test_names: set[str] = set()
    discovery_errors: list[str] = []

    # test/*.py first (preferred over this legacy module).
    try:
        test_pkg = importlib.import_module("src.test")
        pkgdir = os.path.dirname(test_pkg.__file__ or "")
        for _importer, modname, _ispkg in pkgutil.iter_modules([pkgdir]):
            if modname.startswith("_"):
                continue
            fqname = f"src.test.{modname}"
            try:
                module = importlib.import_module(fqname)
            except Exception as e:
                discovery_errors.append(f"{fqname}: {e}")
                continue
            for name in dir(module):
                if not name.startswith("test_") or name == "run_tests":
                    continue
                obj = getattr(module, name)
                if callable(obj):
                    tests.append((f"{modname}.{name}", obj))
                    package_test_names.add(name)
    except Exception as e:
        print(f"  DISCOVER FAIL src.test: {e}")
        return 1

    if discovery_errors:
        for msg in discovery_errors:
            print(f"  DISCOVER FAIL {msg}")
        print(f"\n{len(discovery_errors)} test module(s) failed to import")
        return 1

    # This module fallback tests (only non-colliding names).
    for name in dir(sys.modules[__name__]):
        if not name.startswith("test_") or name == "run_tests":
            continue
        if name in package_test_names:
            continue
        obj = getattr(sys.modules[__name__], name)
        if callable(obj):
            tests.append((name, obj))

    tests.sort(key=lambda x: x[0])
    passed = 0
    failed: list[tuple[str, str]] = []
    for name, fn in tests:
        ok, err = _run_one(name, fn)
        if ok:
            passed += 1
            print(f"  OK  {name}")
        else:
            failed.append((name, err or "?"))
            print(f"  FAIL {name}: {err}")
    print(f"\n{passed} passed, {len(failed)} failed")
    return 0 if not failed else 1

if __name__ == "__main__":
    sys.exit(run_tests())
