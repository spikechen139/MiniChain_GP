"""Verifiable Merkle tree over transaction IDs (SHA-256)."""

from __future__ import annotations

import hashlib
from typing import List

from src.minichain.transaction import Transaction


class MerkleTree:
    """
    Binary Merkle tree from transactions (leaf = SHA-256(tx_id)).

    Transaction count must be a positive power of two.
    """

    def __init__(self, transactions: List[Transaction]) -> None:
        if not transactions:
            raise ValueError("Transaction list must not be empty.")
        if not self._is_power_of_two(len(transactions)):
            raise ValueError(
                f"Transaction count must be a power of two, got: {len(transactions)}"
            )

        self.transactions: List[Transaction] = transactions
        self.levels: List[List[str]] = []
        self.root: str = self._build_tree()

    def _build_tree(self) -> str:
        current_level = [
            self._sha256(tx.tx_id) for tx in self.transactions
        ]
        self.levels.append(current_level)

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1]
                parent_hash = self._sha256(left + right)
                next_level.append(parent_hash)
            current_level = next_level
            self.levels.append(current_level)

        return current_level[0]

    @staticmethod
    def _sha256(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @staticmethod
    def _is_power_of_two(n: int) -> bool:
        return n > 0 and (n & (n - 1)) == 0

    def print_tree(self) -> None:
        total_levels = len(self.levels)

        print()
        print("+" + "=" * 68 + "+")
        print("|" + "  Merkle Tree Visualization".center(68) + "|")
        print("+" + "=" * 68 + "+")

        for i, level in enumerate(reversed(self.levels)):
            depth = total_levels - 1 - i
            if depth == total_levels - 1:
                label = "[Root]"
            elif depth == 0:
                label = "[Leaves]"
            else:
                label = f"[Level {depth}]"

            indent = "    " * i
            print(f"\n  {label} (depth={depth}, nodes={len(level)})")
            print(f"  {'-' * 56}")
            for j, h in enumerate(level):
                connector = "|--" if j < len(level) - 1 else "`--"
                print(f"  {indent}{connector} [{j}] {h[:32]}...")

    def print_tree_classic(self) -> None:
        total_levels = len(self.levels)
        for i, level in enumerate(reversed(self.levels)):
            depth = total_levels - 1 - i
            if depth == total_levels - 1:
                label = "Root"
            elif depth == 0:
                label = "Leaves"
            else:
                label = f"Level {depth}"
            print(f"\n{'=' * 60}")
            print(f"  {label} (depth={depth}, nodes={len(level)})")
            print(f"{'=' * 60}")
            for j, h in enumerate(level):
                print(f"    [{j}] {h}")

    def __repr__(self) -> str:
        return (
            f"MerkleTree(\n"
            f"  transactions = {len(self.transactions)},\n"
            f"  levels       = {len(self.levels)},\n"
            f"  root         = {self.root}\n"
            f")"
        )
