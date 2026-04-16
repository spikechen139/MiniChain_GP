"""Section 5.3: blockchain construction (genesis + links). — PoW / §5.5 not in scope."""

from minichain.account import Account
from minichain.block import create_block, create_genesis_block
from minichain.blockchain import Blockchain, chain_links_valid
from minichain.transaction import Transaction


def test_chain_links_and_genesis():
    a1, a2 = Account(), Account()
    tx1 = Transaction(a1, a2, 1.0)
    tx2 = Transaction(a2, a1, 0.5)
    genesis = create_genesis_block([tx1, tx2])
    chain = Blockchain(genesis)

    tx3 = Transaction(a1, a2, 2.0)
    tx4 = Transaction(a2, a1, 1.0)
    b2 = create_block([tx3, tx4], previous_hash=genesis.compute_block_hash())
    chain.append_block(b2)

    assert chain_links_valid(chain)
    assert b2.header.previous_hash == genesis.compute_block_hash()
