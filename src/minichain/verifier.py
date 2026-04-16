"""
Full-chain integrity verification and tampering detection (assignment Section 5.5).

This project milestone implements **Construction of Blockchain (5.3) only**.
Extended verification is intentionally not implemented here; this file is kept as a placeholder.
"""

from __future__ import annotations

from src.minichain.blockchain import Blockchain
from src.minichain.miner import DIFFICULTY, hash_meets_difficulty


def is_chain_valid(
    chain: Blockchain,
    difficulty: int = DIFFICULTY,
    check_pow: bool = True,
) -> bool:
    """
    Verify entire blockchain:
      - Genesis block has correct previous_hash
      - Each block links to previous block's actual hash
      - (Optionally) each block's hash satisfies Proof-of-Work difficulty
    Returns True if all checks pass.
    """
    blocks = chain.blocks
    if not blocks:
        return False

    # Genesis check
    if blocks[0].header.previous_hash != "0" * 64:
        return False

    # Link and PoW checks
    for i, block in enumerate(blocks):
        if check_pow and not hash_meets_difficulty(block.compute_block_hash(), difficulty):
            return False

        if i > 0:
            prev_hash = blocks[i - 1].compute_block_hash()
            if block.header.previous_hash != prev_hash:
                return False

    return True