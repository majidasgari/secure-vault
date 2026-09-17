"""Secure Vault Qt UI package (SPEC/03).

The UI is the privileged client: it calls :class:`vault.api.service.Service` in-process
with ``role="ui"`` and never goes through the local socket. Only this package (and
:mod:`vault.gui`) may import PySide6.
"""

from __future__ import annotations

__all__ = ["i18n"]
