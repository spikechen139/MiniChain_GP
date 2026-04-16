"""
Full-chain integrity verification and tampering detection (assignment Section 5.5).

This project milestone implements **Construction of Blockchain (5.3) only**.
Extended verification is intentionally not implemented here; this file is kept as a placeholder.
"""

from __future__ import annotations

from typing import Any


def is_chain_valid(*args: Any, **kwargs: Any) -> Any:
    raise NotImplementedError(
        "Full integrity verification (Section 5.5) is not part of the current submission scope "
        "(Construction of Blockchain / 5.3 only). "
        "Use minichain.blockchain.chain_links_valid() for genesis + link checks only."
    )
