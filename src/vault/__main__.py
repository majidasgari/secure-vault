"""``python -m vault`` entry point (SPEC/03 §1)."""

from __future__ import annotations

from .gui import main

if __name__ == "__main__":
    raise SystemExit(main())
