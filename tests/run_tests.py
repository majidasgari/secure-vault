#!/usr/bin/env python3
"""Secure Vault test runner (SPEC/06 §1).

Discovers ``tests/test_*.py`` suites with the stdlib ``unittest`` framework, runs each
suite separately (so the final table can report per-suite timings), and exits non-zero
when anything fails. ``src/``, the repo root and ``tests/`` are put on ``sys.path``.
"""

from __future__ import annotations

import argparse
import importlib
import sys
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = REPO_ROOT / "tests"

for entry in (str(REPO_ROOT / "src"), str(REPO_ROOT), str(TESTS_DIR)):
    if entry not in sys.path:
        sys.path.insert(0, entry)


def discover_modules() -> list[str]:
    """Return the sorted names of discoverable ``test_*.py`` modules."""
    return sorted(path.stem for path in TESTS_DIR.glob("test_*.py"))


def main(argv: list[str] | None = None) -> int:
    """Run the suites and return the process exit code."""
    parser = argparse.ArgumentParser(description="Run the Secure Vault unittest suites.")
    parser.add_argument("--only", default=None, help="only run suites/tests matching PATTERN")
    parser.add_argument("-q", "--quiet", action="store_true", help="less verbose output")
    args = parser.parse_args(argv)

    modules = discover_modules()
    if args.only:
        matched = [m for m in modules if args.only in m]
        if matched:
            modules = matched
    if not modules:
        print("no test modules found")
        return 1

    loader = unittest.TestLoader()
    verbosity = 1 if args.quiet else 2
    rows: list[tuple[str, int, int, int, float]] = []
    total_failures = 0
    total_errors = 0

    for module_name in modules:
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001 - report import failures as errors
            print(f"ERROR importing {module_name}: {exc!r}")
            rows.append((module_name, 0, 0, 1, 0.0))
            total_errors += 1
            continue
        if args.only and not any(module_name in m for m in (args.only,)):
            loader.testNamePatterns = [f"*{args.only}*"]
        else:
            loader.testNamePatterns = None
        suite = loader.loadTestsFromModule(module)
        count = suite.countTestCases()
        if count == 0:
            rows.append((module_name, 0, 0, 0, 0.0))
            continue
        print(f"\n=== {module_name} ===")
        runner = unittest.TextTestRunner(verbosity=verbosity, stream=sys.stdout)
        started = time.time()
        result = runner.run(suite)
        elapsed = time.time() - started
        failures = len(result.failures)
        errors = len(result.errors)
        total_failures += failures
        total_errors += errors
        rows.append((module_name, count, failures, errors, elapsed))

    print("\n" + "=" * 72)
    print(f"{'suite':<36}{'tests':>7}{'failures':>10}{'errors':>8}{'time':>10}")
    print("-" * 72)
    for name, count, failures, errors, elapsed in rows:
        print(f"{name:<36}{count:>7}{failures:>10}{errors:>8}{elapsed:>9.2f}s")
    print("-" * 72)
    total_tests = sum(row[1] for row in rows)
    total_time = sum(row[4] for row in rows)
    print(
        f"{'TOTAL':<36}{total_tests:>7}{total_failures:>10}{total_errors:>8}"
        f"{total_time:>9.2f}s"
    )
    return 1 if (total_failures or total_errors) else 0


if __name__ == "__main__":
    raise SystemExit(main())
