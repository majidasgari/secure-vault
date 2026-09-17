"""Transport-independent interface layer for Secure Vault (SPEC/02).

Exposes the same command surface to the in-process UI, the local Unix-socket JSON-RPC
server and the MCP stdio bridge. Nothing in this package imports Qt.
"""

from __future__ import annotations

from .client import VaultClient
from .service import Service
from .socket_server import VaultSocketServer

__all__ = ["Service", "VaultClient", "VaultSocketServer"]
