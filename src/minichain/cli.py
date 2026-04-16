"""Interactive CLI for MiniChain (Phase I + blockchain demo)."""

from __future__ import annotations

import os
from typing import Optional

from src.minichain.account import Account
from src.minichain.block import create_block, create_genesis_block
from src.minichain.blockchain import Blockchain, chain_links_valid
from src.minichain.merkle_tree import MerkleTree
from src.minichain.persistence import (
    ACCOUNTS_FILE,
    TRANSACTIONS_FILE,
    load_data,
    save_data,
)
from src.minichain.transaction import Transaction
from src.minichain.verifier import is_chain_valid
# ============================================================================
# Interactive CLI -- Helper Functions
# ============================================================================

def _print_banner() -> None:
    """Print the program startup banner."""
    print("\n" + "=" * 70)
    print("  MiniChain — Interactive CLI (Phase I + Phase II chain demo)")
    print("=" * 70)


def _print_menu() -> None:
    """Print the main menu."""
    print("\n+----------------------------------+")
    print("|          Menu                    |")
    print("+----------------------------------+")
    print("|  [1]  Create Account             |")
    print("|  [2]  List Accounts              |")
    print("|  [3]  New Transaction            |")
    print("|  [4]  View Merkle Tree           |")
    print("|  [5]  Simulate Tamper            |")
    print("|  [6]  Verify Integrity           |")
    print("|  [7]  Save Data                  |")
    print("|  [8]  Blockchain Demo (chain)     |")
    print("|  [0]  Exit                       |")
    print("+----------------------------------+")


def _select_account(accounts: dict, prompt: str) -> Optional[str]:
    """
    Display a numbered list of accounts and let the user select one.

    Args:
        accounts: A dict mapping account names to Account objects.
        prompt:   The prompt text to display above the list.

    Returns:
        The selected account name, or None if cancelled or invalid.
    """
    names = list(accounts.keys())
    if not names:
        print("  [WARNING] No accounts exist. Please create an account first.")
        return None

    print(f"\n  {prompt}:")
    for idx, name in enumerate(names, 1):
        print(f"    [{idx}] {name}  ({accounts[name].address[:24]}...)")
    print(f"    [0] Cancel")

    try:
        choice = int(input("  Enter selection: "))
    except ValueError:
        print("  [ERROR] Invalid input. A numeric value is required.")
        return None

    if choice == 0:
        return None
    if 1 <= choice <= len(names):
        return names[choice - 1]

    print("  [ERROR] Selection out of range.")
    return None


# ============================================================================
# CLI Command Implementations
# ============================================================================

def cmd_create_account(accounts: dict) -> None:
    """[1] Create a new ECC-based account."""
    print("\n" + "-" * 50)
    print("  Create Account")
    print("-" * 50)

    name = input("  Enter account name (e.g., Alice): ").strip()
    if not name:
        print("  [ERROR] Account name must not be empty.")
        return
    if name in accounts:
        print(f"  [ERROR] Name '{name}' already exists. Please choose another name.")
        return

    acc = Account()
    accounts[name] = acc
    print(f"  [OK] Account '{name}' created successfully.")
    print(f"       Address: {acc.address[:48]}...")


def cmd_list_accounts(accounts: dict) -> None:
    """[2] List all existing accounts."""
    print("\n" + "-" * 50)
    print("  Account List")
    print("-" * 50)

    if not accounts:
        print("  (empty) No accounts found. Please create one first.")
        return

    for i, (name, acc) in enumerate(accounts.items(), 1):
        print(f"  {i}. {name:<12}  Address: {acc.address[:40]}...")


def cmd_new_transaction(accounts: dict,
                        transactions: list,
                        merkle_info: dict) -> None:
    """
    [3] Create a new SISO transaction.

    After creation, if the current transaction pool size is a power of two,
    the Merkle Tree is automatically rebuilt and the new root is displayed.
    """
    print("\n" + "-" * 50)
    print("  New Transaction")
    print("-" * 50)

    if len(accounts) < 2:
        print("  [WARNING] At least 2 accounts are required. Please create accounts first.")
        return

    # Select sender
    sender_name = _select_account(accounts, "Select Sender")
    if sender_name is None:
        return

    # Select receiver
    receiver_name = _select_account(accounts, "Select Receiver")
    if receiver_name is None:
        return

    if sender_name == receiver_name:
        print("  [ERROR] Sender and receiver must be different accounts.")
        return

    # Enter amount
    try:
        amount = float(input("  Enter transfer amount: "))
        if amount <= 0:
            print("  [ERROR] Amount must be a positive number.")
            return
    except ValueError:
        print("  [ERROR] Invalid amount. Please enter a numeric value.")
        return

    # Create the transaction
    sender = accounts[sender_name]
    receiver = accounts[receiver_name]
    tx = Transaction(sender=sender, receiver=receiver, amount=amount)
    transactions.append(tx)

    # Store sender name for later verification
    tx._sender_name = sender_name  # type: ignore[attr-defined]

    print(f"\n  [OK] Transaction created successfully.")
    print(f"       TX ID    : {tx.tx_id[:32]}...")
    print(f"       Sender   : {sender_name} ({tx.sender_address[:24]}...)")
    print(f"       Receiver : {receiver_name} ({tx.receiver_address[:24]}...)")
    print(f"       Amount   : {tx.amount}")
    print(f"       Pool size: {len(transactions)}")

    # Automatically rebuild the Merkle Tree if pool size is a power of two
    _try_rebuild_merkle(transactions, merkle_info)


def _try_rebuild_merkle(transactions: list, merkle_info: dict) -> None:
    """Attempt to rebuild the Merkle Tree when the transaction count is a power of two."""
    n = len(transactions)
    if n > 0 and (n & (n - 1)) == 0:
        tree = MerkleTree(transactions)
        merkle_info["tree"] = tree
        merkle_info["root"] = tree.root
        print(f"\n  [OK] Merkle Tree rebuilt automatically. (transactions={n})")
        print(f"       Merkle Root: {tree.root}")
    else:
        print(f"\n  [INFO] Current transaction count ({n}) is not a power of two.")
        print(f"         The Merkle Tree will be built when the count reaches a power of two.")
        # Find the next power of two
        next_pow = 1
        while next_pow < n:
            next_pow <<= 1
        print(f"         Next buildable count: {next_pow}")


def cmd_view_merkle_tree(merkle_info: dict) -> None:
    """[4] Display the current Merkle Tree."""
    print("\n" + "-" * 50)
    print("  View Merkle Tree")
    print("-" * 50)

    tree = merkle_info.get("tree")
    if tree is None:
        print("  [WARNING] No Merkle Tree has been built yet.")
        print("            Create enough transactions (power of two: 2, 4, 8, ...).")
        return

    print(f"  Merkle Root  : {tree.root}")
    print(f"  Transactions : {len(tree.transactions)}")
    print(f"  Tree Levels  : {len(tree.levels)}")
    tree.print_tree()


def cmd_simulate_tamper(transactions: list, merkle_info: dict) -> None:
    """[5] Simulate a tampering attack by modifying transaction data (Task 5.5)."""
    print("\n" + "-" * 50)
    print("  Simulate Tamper")
    print("-" * 50)

    if not transactions:
        print("  [WARNING] Transaction pool is empty. Create transactions first.")
        return

    # List all transactions
    print("  Current transactions:")
    for idx, tx in enumerate(transactions, 1):
        sender_label = getattr(tx, '_sender_name', tx.sender_address[:16])
        print(f"    [{idx}] TX {tx.tx_id[:16]}...  "
              f"Sender={sender_label}  Amount={tx.amount}")
    print(f"    [0] Cancel")

    try:
        choice = int(input("  Select transaction to tamper with: "))
    except ValueError:
        print("  [ERROR] Invalid input.")
        return

    if choice == 0:
        return
    if choice < 1 or choice > len(transactions):
        print("  [ERROR] Selection out of range.")
        return

    tx = transactions[choice - 1]
    print(f"\n  Current transaction details:")
    print(f"    TX ID  : {tx.tx_id}")
    print(f"    Amount : {tx.amount}")
    print(f"    Data   : {tx.data}")

    try:
        new_amount = float(input("  Enter tampered amount: "))
    except ValueError:
        print("  [ERROR] Invalid amount.")
        return

    # Save original values for comparison
    old_amount = tx.amount
    old_tx_id = tx.tx_id
    old_root = merkle_info.get("root", None)

    # ---- Execute tamper ----
    tx.amount = new_amount
    tx.data["amount"] = new_amount
    # Note: The signature is NOT recomputed. This is intentional -- simulating an attack.
    # The tx_id is recomputed to reflect data changes, but the stale signature
    # will cause verification to fail.
    tx.tx_id = tx._compute_tx_id()

    print(f"\n  [WARNING] Tamper complete!")
    print(f"    Old amount : {old_amount}  ->  New amount : {new_amount}")
    print(f"    Old TX ID  : {old_tx_id[:32]}...")
    print(f"    New TX ID  : {tx.tx_id[:32]}...")

    # Rebuild Merkle Tree to show root change
    n = len(transactions)
    if n > 0 and (n & (n - 1)) == 0:
        new_tree = MerkleTree(transactions)
        new_root = new_tree.root
        print(f"\n  Merkle Root change:")
        print(f"    Before tamper : {old_root}")
        print(f"    After tamper  : {new_root}")
        if old_root and old_root != new_root:
            print(f"    [FAIL] Root has changed -- tamper is detectable!")
        else:
            print(f"    [OK] Root unchanged.")
        # Update stored state (tampered)
        merkle_info["tree"] = new_tree
        merkle_info["root"] = new_root
    else:
        print(f"\n  [INFO] Transaction count ({n}) is not a power of two. "
              f"Cannot rebuild Merkle Tree.")

    print("\n  Hint: Use [6] Verify Integrity to detect whether signatures are broken.")


def cmd_verify_integrity(accounts: dict,
                         transactions: list,
                         merkle_info: dict) -> None:
    """[6] Verify blockchain integrity (signatures + Merkle Root consistency)."""
    print("\n" + "-" * 50)
    print("  Verify Integrity")
    print("-" * 50)

    if not transactions:
        print("  [WARNING] Transaction pool is empty. Nothing to verify.")
        return

    all_valid = True

    # ---- Step 1: Verify each transaction's signature ----
    print("\n  [Step 1] Transaction Signature Verification:")
    for idx, tx in enumerate(transactions, 1):
        sender_name = getattr(tx, '_sender_name', None)
        if sender_name and sender_name in accounts:
            sender_pub = accounts[sender_name].public_key
            is_valid = tx.verify_transaction(sender_pub)
        else:
            # Sender name not found; try matching by address
            is_valid = False
            for name, acc in accounts.items():
                if acc.address == tx.sender_address:
                    is_valid = tx.verify_transaction(acc.public_key)
                    break

        if is_valid:
            print(f"    TX {idx}: [PASS] Signature valid.")
        else:
            print(f"    TX {idx}: [FAIL] Signature invalid -- possible tampering!")
            all_valid = False

    # ---- Step 2: Verify Merkle Root consistency ----
    print("\n  [Step 2] Merkle Root Consistency Check:")
    stored_root = merkle_info.get("root")
    tree = merkle_info.get("tree")

    if tree is None:
        n = len(transactions)
        if n > 0 and (n & (n - 1)) == 0:
            print("    Rebuilding Merkle Tree for comparison...")
            new_tree = MerkleTree(transactions)
            print(f"    Computed Root: {new_tree.root}")
            if stored_root:
                if new_tree.root == stored_root:
                    print(f"    [PASS] Merkle Root is consistent.")
                else:
                    print(f"    [FAIL] Merkle Root mismatch -- data may be tampered!")
                    print(f"           Stored Root   : {stored_root}")
                    print(f"           Computed Root : {new_tree.root}")
                    all_valid = False
            else:
                print(f"    [INFO] No stored root for comparison. Skipping.")
        else:
            print(f"    [INFO] Transaction count ({n}) is not a power of two. "
                  f"Skipping Merkle verification.")
    else:
        # Rebuild from current transactions and compare to stored root
        n = len(transactions)
        if n > 0 and (n & (n - 1)) == 0:
            fresh_tree = MerkleTree(transactions)
            if fresh_tree.root == stored_root:
                print(f"    [PASS] Merkle Root is consistent: {stored_root[:32]}...")
            else:
                print(f"    [FAIL] Merkle Root mismatch -- data may be tampered!")
                print(f"           Stored Root   : {stored_root}")
                print(f"           Computed Root : {fresh_tree.root}")
                all_valid = False
        else:
            print(f"    [INFO] Transaction count has changed ({n}). "
                  f"Cannot compare to original Merkle Root.")

    # ---- Summary ----
    print("\n  " + "=" * 46)
    if all_valid:
        print("  [PASS] Verification passed -- all data is intact.")
    else:
        print("  [FAIL] Verification failed -- tampering or anomaly detected!")
    print("  " + "=" * 46)


def cmd_save_data(accounts: dict, transactions: list) -> None:
    """[7] Save current data to local files."""
    print("\n" + "-" * 50)
    print("  Save Data")
    print("-" * 50)

    if not accounts and not transactions:
        print("  [WARNING] No data to save.")
        return

    save_data(accounts, transactions)


def cmd_blockchain_demo() -> None:
    """[8] Build a 2-block chain (genesis + one child) and print validation."""
    print("\n" + "-" * 50)
    print("  Blockchain demo (genesis + 1 block, 2 txs each)")
    print("-" * 50)

    a1, a2 = Account(), Account()
    tx1 = Transaction(sender=a1, receiver=a2, amount=10.0)
    tx2 = Transaction(sender=a2, receiver=a1, amount=3.0)

    print("  Mining genesis block...")
    genesis = create_genesis_block([tx1, tx2], do_mine=True)
    chain = Blockchain(genesis)

    tx3 = Transaction(sender=a1, receiver=a2, amount=1.0)
    tx4 = Transaction(sender=a2, receiver=a1, amount=0.5)
    tip_hash = genesis.compute_block_hash()
    print("  Mining block #2...")
    block2 = create_block([tx3, tx4], previous_hash=tip_hash, do_mine=True)
    chain.append_block(block2)


    print(f"  Chain valid (PoW + links): {is_chain_valid(chain)}")
    print(f"  Genesis previous_hash (constant): {genesis.header.previous_hash[:24]}...")
    print(f"  Genesis merkle_root:            {genesis.header.merkle_root[:32]}...")
    print(f"  Genesis nonce: {genesis.header.nonce}  hash: {genesis.compute_block_hash()}")
    print(f"  Genesis block_hash:             {genesis.compute_block_hash()[:32]}...")
    print(f"  Block2 previous_hash:           {block2.header.previous_hash[:32]}...")
    print(f"  Block2  nonce: {block2.header.nonce}  hash: {block2.compute_block_hash()}")
    print(f"  Block2 block_hash:              {block2.compute_block_hash()[:32]}...")
    print(f"  chain_links_valid (5.3 only):   {chain_links_valid(chain)}")

    print("\n  Simulating tamper: modify transaction amount in genesis block...")
    genesis.transactions[0].amount = 999.0  # 直接修改数据
    genesis.transactions[0].tx_id = genesis.transactions[0]._compute_tx_id()  # 更新tx_id（破坏签名）
    print(f"  After tamper, chain valid: {is_chain_valid(chain)}")

    bad_block = create_block([tx3, tx4], previous_hash="f" * 64)
    try:
        broken = Blockchain(genesis)
        broken.append_block(bad_block)
    except ValueError as e:
        print(f"\n  [INFO] Broken link rejected as expected: {e}")


# ============================================================================
# Main Program -- Interactive CLI
# ============================================================================

def main() -> None:
    """MiniChain interactive command-line interface."""

    _print_banner()

    # In-memory data stores
    accounts: dict = {}          # {name: Account}
    transactions: list = []      # [Transaction, ...]
    merkle_info: dict = {        # Latest Merkle Tree information
        "tree": None,
        "root": None,
    }

    # ---- Prompt to load existing data on startup ----
    has_files = os.path.exists(ACCOUNTS_FILE) or os.path.exists(TRANSACTIONS_FILE)
    if has_files:
        print("\n  Local data files detected.")
        load_choice = input("  Load existing data from files? (y/n): ").strip().lower()
        if load_choice == "y":
            loaded_accounts, loaded_transactions = load_data()
            accounts.update(loaded_accounts)
            transactions.extend(loaded_transactions)
            # Automatically build Merkle Tree if transaction count is a power of two
            n = len(transactions)
            if n > 0 and (n & (n - 1)) == 0:
                try:
                    tree = MerkleTree(transactions)
                    merkle_info["tree"] = tree
                    merkle_info["root"] = tree.root
                    print(f"  [OK] Merkle Tree rebuilt. Root: {tree.root[:32]}...")
                except ValueError:
                    pass
        else:
            print("  [INFO] Skipped data loading. Starting with a blank state.")

    while True:
        _print_menu()
        user_input = input("\n  Select an option [0-8]: ").strip()

        if user_input == "1":
            cmd_create_account(accounts)

        elif user_input == "2":
            cmd_list_accounts(accounts)

        elif user_input == "3":
            cmd_new_transaction(accounts, transactions, merkle_info)

        elif user_input == "4":
            cmd_view_merkle_tree(merkle_info)

        elif user_input == "5":
            cmd_simulate_tamper(transactions, merkle_info)

        elif user_input == "6":
            cmd_verify_integrity(accounts, transactions, merkle_info)

        elif user_input == "7":
            cmd_save_data(accounts, transactions)

        elif user_input == "8":
            cmd_blockchain_demo()

        elif user_input == "0":
            print("\n  Goodbye! MiniChain has exited.\n")
            break

        else:
            print("  [ERROR] Invalid option. Please enter a number between 0 and 8.")
