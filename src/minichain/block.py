"""Block header, block body, genesis / normal block factories, header hashing (SHA-256)."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import List, Optional

from src.minichain.merkle_tree import MerkleTree
from src.minichain.transaction import Transaction
from src.minichain.miner import DIFFICULTY, mine_block

GENESIS_PREV_HASH: str = "0" * 64


@dataclass
class BlockHeader:
    """Fields hashed for PoW / block_hash (order fixed — see ``compute_header_hash``)."""

    previous_hash: str
    timestamp: int
    nonce: int
    merkle_root: str


def compute_header_hash(header: BlockHeader) -> str:
    """
    SHA-256 hex of the canonical header string.

    Format: ``previous_hash|timestamp|nonce|merkle_root`` (UTF-8).
    Must stay in sync with ``Block.serialize_header_for_pow``.
    """
    s = (
        f"{header.previous_hash}|"
        f"{header.timestamp}|"
        f"{header.nonce}|"
        f"{header.merkle_root}"
    )
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class Block:
    """Header + confirmed transactions + Merkle tree; block hash = ``compute_header_hash(header)``."""

    def __init__(self, header: BlockHeader, transactions: List[Transaction]) -> None:
        self.header = header
        self.transactions = transactions
        self.merkle_tree = MerkleTree(transactions)
        if self.header.merkle_root != self.merkle_tree.root:
            raise ValueError("BlockHeader.merkle_root does not match MerkleTree.root for transactions.")

    def serialize_header_for_pow(self) -> bytes:
        s = (
            f"{self.header.previous_hash}|"
            f"{self.header.timestamp}|"
            f"{self.header.nonce}|"
            f"{self.header.merkle_root}"
        )
        return s.encode("utf-8")

    def compute_block_hash(self) -> str:
        return compute_header_hash(self.header)


def create_genesis_block(
    transactions: List[Transaction],
    timestamp: Optional[int] = None,
    do_mine: bool = True,
) -> Block:
    tree = MerkleTree(transactions)
    ts = int(time.time()) if timestamp is None else timestamp
    header = BlockHeader(
        previous_hash=GENESIS_PREV_HASH,
        timestamp=ts,
        nonce=0,
        merkle_root=tree.root,
    )
    block = Block(header, transactions)
    if do_mine:
        mine_block(block, DIFFICULTY)
    return block

def create_block(
    transactions: List[Transaction],
    previous_hash: str,
    nonce: int = 0,
    timestamp: Optional[int] = None,
    do_mine: bool = True,
) -> Block:
    tree = MerkleTree(transactions)
    ts = int(time.time()) if timestamp is None else timestamp
    header = BlockHeader(
        previous_hash=previous_hash,
        timestamp=ts,
        nonce=nonce,
        merkle_root=tree.root,
    )
    block = Block(header, transactions)
    if do_mine:
        mine_block(block, DIFFICULTY)
    return block
