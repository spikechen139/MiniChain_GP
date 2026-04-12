# MiniChain_GP
<<<<<<< Blockchain_Constru

A simplified, functional blockchain system from the ground up (COMP4137/COMP7200).

**Current milestone:** assignment **Section 5.3 — Construction of Blockchain** (header + transactions + Merkle + SHA-256 + genesis).  
**Out of scope for this submission:** Section **5.4 PoW** and **5.5 full integrity verification** — `miner.py` and `verifier.py` are kept as placeholders only. Use `chain_links_valid()` in `blockchain.py` for genesis + per-block link checks (5.3).

## Layout

```
├── main.py                 # Entry: interactive CLI
├── requirements.txt
├── pyproject.toml
├── README.md
├── src/minichain/          # Core package
│   ├── __init__.py
│   ├── account.py          # ECC accounts, sign/verify, address
│   ├── transaction.py      # SISO transactions, tx_id
│   ├── merkle_tree.py      # Merkle tree (SHA-256)
│   ├── persistence.py      # Save/load accounts & txs (JSON)
│   ├── block.py            # Block header, block hash, genesis / block helpers
│   ├── blockchain.py       # Chain storage, append, link checks
│   ├── miner.py            # Placeholder (5.4 PoW — not implemented)
│   ├── verifier.py         # Placeholder (5.5 integrity — not implemented)
│   └── cli.py              # Interactive menu
└── tests/
    ├── test_phase1.py
    └── test_phase2.py
```

## Dependencies

- Python ≥ 3.10
- `cryptography` (see `pyproject.toml` / `requirements.txt`)

## Setup

```bash
pip install -e .
```

Optional (run tests):

```bash
pip install -e ".[dev]"
python -m pytest tests -q
```

## Run

From the project root:

```bash
python main.py
```

Data files `accounts.txt` and `transactions.txt` are written in the project root.

## Import

```python
from minichain import (
    Account, Transaction, MerkleTree,
    Blockchain, create_genesis_block, create_block, chain_links_valid,
)
```
