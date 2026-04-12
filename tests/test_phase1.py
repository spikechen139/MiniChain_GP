"""Phase I: account, SISO transaction, Merkle tree."""

from minichain.account import Account
from minichain.merkle_tree import MerkleTree
from minichain.transaction import Transaction


def test_account_roundtrip():
    a = Account()
    b = Account.from_dict(a.to_dict())
    assert b.address == a.address


def test_transaction_sign_verify():
    alice, bob = Account(), Account()
    tx = Transaction(alice, bob, 42.0)
    assert tx.verify_transaction(alice.public_key)
    assert tx.tx_id == tx.tx_id


def test_merkle_root_power_of_two():
    a, b = Account(), Account()
    txs = [Transaction(a, b, 1.0), Transaction(b, a, 2.0)]
    tree = MerkleTree(txs)
    assert len(tree.root) == 64
