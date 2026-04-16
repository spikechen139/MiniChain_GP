"""
Proof-of-Work mining (assignment Section 5.4).

This project milestone implements **Construction of Blockchain (5.3) only**.
PoW is intentionally not implemented here; this file is kept as a placeholder.
"""

from __future__ import annotations

DIFFICULTY = 4          # target hash starts with "0000"


def hash_meets_difficulty(block_hash: str, difficulty: int = DIFFICULTY) -> bool:
    """Return True if block_hash starts with required number of zeros."""
    return block_hash.startswith("0" * difficulty)


def mine_block(block, difficulty: int = DIFFICULTY) -> None:
    """
    Perform Proof-of-Work: find a nonce such that block's hash meets difficulty.
    Modifies block.header.nonce in place.

    Note: 'block' parameter is expected to be an instance of Block (from block.py).
    Import is delayed to avoid circular import.
    """

    target = "0" * difficulty
    while True:
        block_hash = block.compute_block_hash()
        if block_hash.startswith(target):
            break
        block.header.nonce += 1