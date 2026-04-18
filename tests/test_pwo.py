import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.minichain.account import Account
from src.minichain.transaction import Transaction
from src.minichain.block import create_genesis_block, create_block
from src.minichain.blockchain import Blockchain
from src.minichain.verifier import is_chain_valid

a, b = Account(), Account()
genesis = create_genesis_block([Transaction(a, b, 100)], do_mine=True)
chain = Blockchain(genesis)
block1 = create_block([Transaction(b, a, 50)], previous_hash=genesis.compute_block_hash(), do_mine=True)
chain.append_block(block1)
print(is_chain_valid(chain))          # True
# 篡改
chain.blocks[0].transactions[0].amount = 999
print(is_chain_valid(chain))          # False