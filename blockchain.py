"""
MiniChain - Phase I: The Building Blocks
=========================================
This module implements Phase I of the MiniChain blockchain project, including:

1. ECC-based Account System (Account)
2. Single-Input Single-Output Transaction (SISO Transaction)
3. Verifiable Merkle Tree (MerkleTree)

Dependencies: cryptography, hashlib
"""

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature


# ============================================================================
# 1. Account -- ECC-based Account (Public/Private Key Pair)
# ============================================================================

class Account:
    """
    Blockchain account class using Elliptic Curve Cryptography (ECC).

    Generates a SECP256K1 key pair and derives a hex-encoded address
    from the uncompressed public key.

    Attributes:
        private_key: ECC private key object (SECP256K1 curve).
        public_key:  ECC public key object.
        address:     Account address (hex-encoded uncompressed public key).
    """

    def __init__(self) -> None:
        """Create a new account by generating an ECC key pair and deriving an address."""
        # Use the SECP256K1 curve (consistent with Bitcoin and Ethereum)
        self._private_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
            ec.SECP256K1()
        )
        self._public_key: ec.EllipticCurvePublicKey = self._private_key.public_key()

        # Serialize the public key in uncompressed X9.62 format as the account address
        self.address: str = self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        ).hex()

    # ---- Property Accessors ------------------------------------------------

    @property
    def private_key(self) -> ec.EllipticCurvePrivateKey:
        """Return the private key object (used only by the account holder)."""
        return self._private_key

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        """Return the public key object."""
        return self._public_key

    # ---- Signing and Verification ------------------------------------------

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message using the private key with ECDSA (SHA-256).

        Args:
            message: The raw bytes to be signed.

        Returns:
            The DER-encoded ECDSA signature bytes.
        """
        signature = self._private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature

    @staticmethod
    def verify(public_key: ec.EllipticCurvePublicKey,
               message: bytes,
               signature: bytes) -> bool:
        """
        Verify an ECDSA signature against a message using the given public key.

        Args:
            public_key: The signer's public key.
            message:    The original message bytes.
            signature:  The signature to verify.

        Returns:
            True if the signature is valid, False otherwise.
        """
        try:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    # ---- Serialization / Deserialization ------------------------------------

    def to_dict(self) -> dict:
        """
        Serialize the account to a dictionary with PEM-encoded keys.

        Returns:
            A dict containing 'address', 'private_key_pem', and 'public_key_pem'.
        """
        private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return {
            "address": self.address,
            "private_key_pem": private_pem,
            "public_key_pem": public_pem,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Account":
        """
        Reconstruct an Account object from a serialized dictionary.

        Args:
            data: A dict containing 'private_key_pem', 'public_key_pem', and 'address'.

        Returns:
            A reconstructed Account instance with the original key pair.
        """
        acc = object.__new__(cls)  # Skip __init__ to avoid regenerating keys

        # Restore key objects from PEM strings
        acc._private_key = serialization.load_pem_private_key(
            data["private_key_pem"].encode("utf-8"),
            password=None,
        )
        acc._public_key = acc._private_key.public_key()

        # Restore the address
        acc.address = data["address"]
        return acc

    def __repr__(self) -> str:
        return f"Account(address={self.address[:16]}...)"


# ============================================================================
# 2. Transaction -- Single-Input Single-Output (SISO) Transaction
# ============================================================================

class Transaction:
    """
    Single-Input Single-Output (SISO) transaction class.

    Each transaction contains:
        - tx_id:     Transaction ID (SHA-256 hash of transaction contents).
        - sender:    Sender address (Input).
        - receiver:  Receiver address (Output).
        - amount:    Virtual coin transfer amount.
        - signature: Digital signature of the transaction details by the sender.
        - data:      Dictionary containing the amount and its digital signature.
    """

    def __init__(self,
                 sender: Account,
                 receiver: Account,
                 amount: float) -> None:
        """
        Construct and sign a SISO transaction.

        Args:
            sender:   Sender account (private key required for signing).
            receiver: Receiver account.
            amount:   Transfer amount (virtual coins).
        """
        # ---- Core Fields ---------------------------------------------------
        self.sender_address: str = sender.address        # Input
        self.receiver_address: str = receiver.address     # Output
        self.amount: float = amount

        # ---- Data Field: amount + digitally signed amount ------------------
        amount_bytes = str(amount).encode("utf-8")
        self.amount_signature: bytes = sender.sign(amount_bytes)
        self.data: dict = {
            "amount": self.amount,
            "amount_signature": self.amount_signature.hex(),
        }

        # ---- Signature: sender signs the transaction details ---------------
        tx_details = self._get_tx_details()
        self.signature: bytes = sender.sign(tx_details)

        # ---- Transaction ID: SHA-256 hash of transaction contents ----------
        self.tx_id: str = self._compute_tx_id()

    # ---- Internal Methods --------------------------------------------------

    def _get_tx_details(self) -> bytes:
        """
        Concatenate the key transaction fields into a byte string for signing.

        Includes: sender_address + receiver_address + amount.

        Returns:
            UTF-8 encoded byte string of concatenated transaction details.
        """
        details = (
            f"{self.sender_address}"
            f"{self.receiver_address}"
            f"{self.amount}"
        )
        return details.encode("utf-8")

    def _compute_tx_id(self) -> str:
        """
        Compute the transaction ID by hashing the full transaction content with SHA-256.

        Returns:
            Hexadecimal string of the transaction hash.
        """
        tx_content = (
            f"{self.sender_address}"
            f"{self.receiver_address}"
            f"{self.amount}"
            f"{self.signature.hex()}"
        )
        return hashlib.sha256(tx_content.encode("utf-8")).hexdigest()

    # ---- Verification ------------------------------------------------------

    def verify_transaction(self, sender_public_key: ec.EllipticCurvePublicKey) -> bool:
        """
        Verify the legitimacy of the transaction signatures.

        Verification steps:
            1. Verify the transaction details signature (sender, receiver, amount).
            2. Verify the amount data signature.

        Args:
            sender_public_key: The sender's public key.

        Returns:
            True if all signatures are valid, False otherwise.
        """
        # Verify the transaction details signature
        tx_details = self._get_tx_details()
        if not Account.verify(sender_public_key, tx_details, self.signature):
            return False

        # Verify the amount signature
        amount_bytes = str(self.amount).encode("utf-8")
        amount_sig = bytes.fromhex(self.data["amount_signature"])
        if not Account.verify(sender_public_key, amount_bytes, amount_sig):
            return False

        return True

    # ---- Serialization / Deserialization -----------------------------------

    def to_dict(self) -> dict:
        """
        Serialize the transaction to a dictionary.

        Returns:
            A dict containing tx_id, sender_address, receiver_address, amount,
            signature (hex), amount_signature (hex), data, and _sender_name.
        """
        return {
            "tx_id": self.tx_id,
            "sender_address": self.sender_address,
            "receiver_address": self.receiver_address,
            "amount": self.amount,
            "signature": self.signature.hex(),
            "amount_signature": self.amount_signature.hex(),
            "data": self.data,
            "_sender_name": getattr(self, "_sender_name", None),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Transaction":
        """
        Reconstruct a Transaction object from a serialized dictionary.

        The object is created without re-signing, preserving the original
        signatures from the file.

        Args:
            data: A serialized transaction dictionary.

        Returns:
            A reconstructed Transaction instance.
        """
        tx = object.__new__(cls)  # Skip __init__ to avoid re-signing

        tx.sender_address = data["sender_address"]
        tx.receiver_address = data["receiver_address"]
        tx.amount = data["amount"]
        tx.signature = bytes.fromhex(data["signature"])
        tx.amount_signature = bytes.fromhex(data["amount_signature"])
        tx.data = data["data"]
        tx.tx_id = data["tx_id"]

        # Restore _sender_name if it exists
        sender_name = data.get("_sender_name")
        if sender_name:
            tx._sender_name = sender_name  # type: ignore[attr-defined]

        return tx

    def __repr__(self) -> str:
        return (
            f"Transaction(\n"
            f"  tx_id     = {self.tx_id[:16]}...,\n"
            f"  sender    = {self.sender_address[:16]}...,\n"
            f"  receiver  = {self.receiver_address[:16]}...,\n"
            f"  amount    = {self.amount},\n"
            f"  signature = {self.signature.hex()[:16]}...\n"
            f")"
        )


# ============================================================================
# 3. MerkleTree -- Verifiable Merkle Tree
# ============================================================================

class MerkleTree:
    """
    Verifiable Merkle Tree implementation.

    Constructs a binary hash tree bottom-up from a list of transactions using
    SHA-256, producing a single Merkle Root that uniquely represents the
    transaction set.

    Assumption: The number of transactions must be a power of two (2, 4, 8, ...).
    """

    def __init__(self, transactions: List[Transaction]) -> None:
        """
        Build a Merkle Tree from a list of transactions.

        Args:
            transactions: A list of Transaction objects. The count must be
                          a power of two.

        Raises:
            ValueError: If the transaction list is empty or its length is not
                        a power of two.
        """
        if not transactions:
            raise ValueError("Transaction list must not be empty.")
        if not self._is_power_of_two(len(transactions)):
            raise ValueError(
                f"Transaction count must be a power of two, got: {len(transactions)}"
            )

        self.transactions: List[Transaction] = transactions
        self.levels: List[List[str]] = []   # Stores hash values at each level
        self.root: str = self._build_tree()

    # ---- Tree Construction -------------------------------------------------

    def _build_tree(self) -> str:
        """
        Build the Merkle Tree bottom-up.

        Process:
            1. Leaf layer: compute SHA-256 of each transaction ID.
            2. Iteratively pair and hash nodes upward until a single root remains.

        Returns:
            The Merkle Root as a hexadecimal string.
        """
        # Level 0 (leaf nodes): SHA-256 hash of each transaction's tx_id
        current_level = [
            self._sha256(tx.tx_id) for tx in self.transactions
        ]
        self.levels.append(current_level)

        # Merge pairs upward until only one hash remains
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

    # ---- Helper Methods ----------------------------------------------------

    @staticmethod
    def _sha256(data: str) -> str:
        """
        Compute the SHA-256 hash of a string.

        Args:
            data: The input string.

        Returns:
            The hexadecimal-encoded hash digest.
        """
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @staticmethod
    def _is_power_of_two(n: int) -> bool:
        """Check whether a positive integer is a power of two."""
        return n > 0 and (n & (n - 1)) == 0

    def print_tree(self) -> None:
        """Print the Merkle Tree structure in a visual tree-style format."""
        total_levels = len(self.levels)

        # Header
        print()
        print("+" + "=" * 68 + "+")
        print("|" + "  Merkle Tree Visualization".center(68) + "|")
        print("+" + "=" * 68 + "+")

        # Print from root to leaves (top-down)
        for i, level in enumerate(reversed(self.levels)):
            depth = total_levels - 1 - i
            if depth == total_levels - 1:
                label = "[Root]"
            elif depth == 0:
                label = "[Leaves]"
            else:
                label = f"[Level {depth}]"

            indent = "    " * i  # Increase indentation with depth
            print(f"\n  {label} (depth={depth}, nodes={len(level)})")
            print(f"  {'-' * 56}")
            for j, h in enumerate(level):
                connector = "|--" if j < len(level) - 1 else "`--"
                print(f"  {indent}{connector} [{j}] {h[:32]}...")

    def print_tree_classic(self) -> None:
        """Print the Merkle Tree in a classic tabular format."""
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


# ============================================================================
# 4. Data Persistence -- Save and Load
# ============================================================================

# Data file paths (same directory as the script)
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ACCOUNTS_FILE = os.path.join(_SCRIPT_DIR, "accounts.txt")
TRANSACTIONS_FILE = os.path.join(_SCRIPT_DIR, "transactions.txt")


def save_data(accounts: dict, transactions: list) -> None:
    """
    Persist in-memory account and transaction data to local .txt files.

    Although the files use a .txt extension, the internal format is JSON
    for ease of parsing.

    Args:
        accounts:     A dict mapping account names to Account objects.
        transactions: A list of Transaction objects.
    """
    # ---- Save accounts ----
    accounts_data = {}
    for name, acc in accounts.items():
        accounts_data[name] = acc.to_dict()

    try:
        with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
            json.dump(accounts_data, f, indent=2, ensure_ascii=False)
        print(f"  [OK] Account data saved to: {ACCOUNTS_FILE}")
        print(f"       Total accounts: {len(accounts_data)}")
    except IOError as e:
        print(f"  [ERROR] Failed to save account data: {e}")

    # ---- Save transactions ----
    transactions_data = [tx.to_dict() for tx in transactions]

    try:
        with open(TRANSACTIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(transactions_data, f, indent=2, ensure_ascii=False)
        print(f"  [OK] Transaction data saved to: {TRANSACTIONS_FILE}")
        print(f"       Total transactions: {len(transactions_data)}")
    except IOError as e:
        print(f"  [ERROR] Failed to save transaction data: {e}")


def load_data() -> Tuple[dict, list]:
    """
    Load and reconstruct account and transaction objects from local .txt files.

    Returns:
        A tuple (accounts, transactions) where:
            accounts:     A dict mapping names to Account objects.
            transactions: A list of Transaction objects.
    """
    accounts: dict = {}
    transactions: list = []

    # ---- Load accounts ----
    if os.path.exists(ACCOUNTS_FILE):
        try:
            with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
                accounts_data = json.load(f)
            for name, acc_dict in accounts_data.items():
                accounts[name] = Account.from_dict(acc_dict)
            print(f"  [OK] Loaded {len(accounts)} account(s) from: {ACCOUNTS_FILE}")
        except (IOError, json.JSONDecodeError, KeyError, ValueError) as e:
            print(f"  [ERROR] Failed to load account data: {e}")
            accounts = {}
    else:
        print(f"  [INFO] Account file not found: {ACCOUNTS_FILE}")

    # ---- Load transactions ----
    if os.path.exists(TRANSACTIONS_FILE):
        try:
            with open(TRANSACTIONS_FILE, "r", encoding="utf-8") as f:
                transactions_data = json.load(f)
            for tx_dict in transactions_data:
                transactions.append(Transaction.from_dict(tx_dict))
            print(f"  [OK] Loaded {len(transactions)} transaction(s) from: {TRANSACTIONS_FILE}")
        except (IOError, json.JSONDecodeError, KeyError, ValueError) as e:
            print(f"  [ERROR] Failed to load transaction data: {e}")
            transactions = []
    else:
        print(f"  [INFO] Transaction file not found: {TRANSACTIONS_FILE}")

    return accounts, transactions


# ============================================================================
# Interactive CLI -- Helper Functions
# ============================================================================

def _print_banner() -> None:
    """Print the program startup banner."""
    print("\n" + "=" * 70)
    print("  MiniChain -- Phase I: Interactive CLI")
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


# ============================================================================
# Main Program -- Interactive CLI
# ============================================================================

def main() -> None:
    """MiniChain Phase I interactive command-line interface."""

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
        user_input = input("\n  Select an option [0-7]: ").strip()

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

        elif user_input == "0":
            print("\n  Goodbye! MiniChain has exited.\n")
            break

        else:
            print("  [ERROR] Invalid option. Please enter a number between 0 and 7.")


if __name__ == "__main__":
    main()
