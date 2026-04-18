"""Full-chain integrity verification and tampering detection."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec

from src.minichain.block import GENESIS_PREV_HASH, Block
from src.minichain.blockchain import Blockchain
from src.minichain.merkle_tree import MerkleTree
from src.minichain.miner import DIFFICULTY, hash_meets_difficulty
from src.minichain.transaction import Transaction


def _load_sender_public_key(tx: Transaction) -> ec.EllipticCurvePublicKey | None:
    """Reconstruct the sender public key from the stored address."""
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(),
            bytes.fromhex(tx.sender_address),
        )
    except ValueError:
        return None


def _is_transaction_valid(tx: Transaction) -> bool:
    """Return True if transaction contents, tx_id, and signatures are intact."""
    sender_public_key = _load_sender_public_key(tx)
    if sender_public_key is None:
        return False

    if tx.tx_id != tx._compute_tx_id():
        return False

    return tx.verify_transaction(sender_public_key)


def _is_block_data_valid(block: Block) -> bool:
    """Return True if all block transactions and the Merkle root are intact."""
    for tx in block.transactions:
        if not _is_transaction_valid(tx):
            return False

    try:
        current_root = MerkleTree(block.transactions).root
    except ValueError:
        return False

    if block.header.merkle_root != current_root:
        return False

    return True


def is_chain_valid(
    chain: Blockchain,
    difficulty: int = DIFFICULTY,
    check_pow: bool = True,
) -> bool:
    """
    Verify entire blockchain:
      - Genesis block has correct previous_hash
      - Every transaction in every block is still intact
      - Every block's Merkle root still matches its transactions
      - Each block links to previous block's actual hash
      - (Optionally) each block's hash satisfies Proof-of-Work difficulty
    Returns True if all checks pass.
    """
    blocks = chain.blocks
    if not blocks:
        return False

    # Genesis check
    if blocks[0].header.previous_hash != GENESIS_PREV_HASH:
        return False

    # Verify from the last block back to the genesis block.
    for i in range(len(blocks) - 1, -1, -1):
        block = blocks[i]

        if not _is_block_data_valid(block):
            return False

        if check_pow and not hash_meets_difficulty(block.compute_block_hash(), difficulty):
            return False

        if i > 0:
            prev_hash = blocks[i - 1].compute_block_hash()
            if block.header.previous_hash != prev_hash:
                return False

    return True