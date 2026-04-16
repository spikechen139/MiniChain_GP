

from src.minichain.account import Account
from src.minichain.block import create_block, create_genesis_block
from src.minichain.blockchain import Blockchain, chain_links_valid
from src.minichain.transaction import Transaction
from src.minichain.verifier import is_chain_valid


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

def test_chain_links_only():
    a1, a2 = Account(), Account()
    tx1 = Transaction(a1, a2, 1.0)
    tx2 = Transaction(a2, a1, 0.5)
    genesis = create_genesis_block([tx1, tx2], do_mine=False)   # 不挖矿
    chain = Blockchain(genesis)
    tx3 = Transaction(a1, a2, 2.0)
    tx4 = Transaction(a2, a1, 1.0)
    b2 = create_block([tx3, tx4], previous_hash=genesis.compute_block_hash(), do_mine=False)
    chain.append_block(b2)
    # 只检查链接，不检查 PoW
    from src.minichain.blockchain import chain_links_valid
    assert chain_links_valid(chain)
    assert b2.header.previous_hash == genesis.compute_block_hash()


def test_tampered_transaction_invalidates_chain():
    a1, a2 = Account(), Account()
    tx1 = Transaction(a1, a2, 1.0)
    tx2 = Transaction(a2, a1, 0.5)
    genesis = create_genesis_block([tx1, tx2], do_mine=True)
    chain = Blockchain(genesis)

    tx3 = Transaction(a1, a2, 2.0)
    tx4 = Transaction(a2, a1, 1.0)
    b2 = create_block([tx3, tx4], previous_hash=genesis.compute_block_hash(), do_mine=True)
    chain.append_block(b2)

    assert is_chain_valid(chain)

    chain.blocks[0].transactions[0].amount = 999.0
    assert not is_chain_valid(chain)
