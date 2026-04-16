"""Blockchain: ordered blocks, genesis, append with link validation."""

from __future__ import annotations

from typing import List, Optional

from src.minichain.block import GENESIS_PREV_HASH, Block


class Blockchain:
    """Ordered list of blocks from genesis (index 0) to tip."""

    def __init__(self, genesis: Optional[Block] = None) -> None:
        self._blocks: List[Block] = []
        if genesis is not None:
            self._assert_valid_genesis(genesis)
            self._blocks.append(genesis)

    def _assert_valid_genesis(self, block: Block) -> None:
        if block.header.previous_hash != GENESIS_PREV_HASH:
            raise ValueError("Genesis block must use GENESIS_PREV_HASH as previous_hash.")

    @property
    def blocks(self) -> List[Block]:
        return self._blocks

    def __len__(self) -> int:
        return len(self._blocks)

    def __getitem__(self, index: int) -> Block:
        return self._blocks[index]

    def get_latest_block(self) -> Block:
        if not self._blocks:
            raise IndexError("Blockchain is empty.")
        return self._blocks[-1]

    def append_block(self, block: Block) -> None:
        if not self._blocks:
            raise ValueError("Cannot append: chain has no genesis block.")
        prev_hash = self._blocks[-1].compute_block_hash()
        if block.header.previous_hash != prev_hash:
            raise ValueError(
                "Invalid link: block.header.previous_hash does not match tip block hash."
            )
        self._blocks.append(block)


def chain_links_valid(chain: Blockchain) -> bool:
    """
    Return True if the chain has a valid genesis ``previous_hash`` and each block
    links to the previous block's ``compute_block_hash``.

    This covers **Section 5.3 (Construction of Blockchain)** only: it does **not**
    implement PoW checks (5.4) or full integrity / tamper detection (5.5).
    """
    blocks = chain.blocks
    if not blocks:
        return False
    if blocks[0].header.previous_hash != GENESIS_PREV_HASH:
        return False
    for i in range(1, len(blocks)):
        if blocks[i].header.previous_hash != blocks[i - 1].compute_block_hash():
            return False
    return True
