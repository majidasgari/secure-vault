"""Secure Vault — a personal encrypted vault (notes + secrets) with agent-aware access.

The package is importable headless: the core layer has no Qt dependency. Later phases add
the service/socket layer, the MCP bridge, the Qt UI, importers and packaging.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
