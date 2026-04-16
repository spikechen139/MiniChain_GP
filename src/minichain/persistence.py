"""Persist accounts and transactions to JSON files in the project root."""

from __future__ import annotations

import json
import os
from typing import List, Tuple

from src.minichain.account import Account
from src.minichain.transaction import Transaction

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ACCOUNTS_FILE = os.path.join(_PROJECT_ROOT, "accounts.txt")
TRANSACTIONS_FILE = os.path.join(_PROJECT_ROOT, "transactions.txt")


def save_data(accounts: dict, transactions: List[Transaction]) -> None:
    """Save accounts and transactions to ``accounts.txt`` / ``transactions.txt`` (JSON)."""
    accounts_data = {name: acc.to_dict() for name, acc in accounts.items()}

    try:
        with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
            json.dump(accounts_data, f, indent=2, ensure_ascii=False)
        print(f"  [OK] Account data saved to: {ACCOUNTS_FILE}")
        print(f"       Total accounts: {len(accounts_data)}")
    except OSError as e:
        print(f"  [ERROR] Failed to save account data: {e}")

    transactions_data = [tx.to_dict() for tx in transactions]

    try:
        with open(TRANSACTIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(transactions_data, f, indent=2, ensure_ascii=False)
        print(f"  [OK] Transaction data saved to: {TRANSACTIONS_FILE}")
        print(f"       Total transactions: {len(transactions_data)}")
    except OSError as e:
        print(f"  [ERROR] Failed to save transaction data: {e}")


def load_data() -> Tuple[dict, list]:
    """Load accounts and transactions from disk; return ``({}, [])`` on failure."""
    accounts: dict = {}
    transactions: list = []

    if os.path.exists(ACCOUNTS_FILE):
        try:
            with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
                accounts_data = json.load(f)
            for name, acc_dict in accounts_data.items():
                accounts[name] = Account.from_dict(acc_dict)
            print(f"  [OK] Loaded {len(accounts)} account(s) from: {ACCOUNTS_FILE}")
        except (OSError, json.JSONDecodeError, KeyError, ValueError) as e:
            print(f"  [ERROR] Failed to load account data: {e}")
            accounts = {}
    else:
        print(f"  [INFO] Account file not found: {ACCOUNTS_FILE}")

    if os.path.exists(TRANSACTIONS_FILE):
        try:
            with open(TRANSACTIONS_FILE, "r", encoding="utf-8") as f:
                transactions_data = json.load(f)
            for tx_dict in transactions_data:
                transactions.append(Transaction.from_dict(tx_dict))
            print(f"  [OK] Loaded {len(transactions)} transaction(s) from: {TRANSACTIONS_FILE}")
        except (OSError, json.JSONDecodeError, KeyError, ValueError) as e:
            print(f"  [ERROR] Failed to load transaction data: {e}")
            transactions = []
    else:
        print(f"  [INFO] Transaction file not found: {TRANSACTIONS_FILE}")

    return accounts, transactions
