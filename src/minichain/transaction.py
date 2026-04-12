"""SISO transaction: structure, signatures, tx_id (SHA-256)."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric import ec

from minichain.account import Account


class Transaction:
    """Single-Input Single-Output (SISO) transaction."""

    def __init__(self, sender: Account, receiver: Account, amount: float) -> None:
        self.sender_address: str = sender.address
        self.receiver_address: str = receiver.address
        self.amount: float = amount

        amount_bytes = str(amount).encode("utf-8")
        self.amount_signature: bytes = sender.sign(amount_bytes)
        self.data: dict = {
            "amount": self.amount,
            "amount_signature": self.amount_signature.hex(),
        }

        tx_details = self._get_tx_details()
        self.signature: bytes = sender.sign(tx_details)

        self.tx_id: str = self._compute_tx_id()

    def _get_tx_details(self) -> bytes:
        details = (
            f"{self.sender_address}"
            f"{self.receiver_address}"
            f"{self.amount}"
        )
        return details.encode("utf-8")

    def _compute_tx_id(self) -> str:
        tx_content = (
            f"{self.sender_address}"
            f"{self.receiver_address}"
            f"{self.amount}"
            f"{self.signature.hex()}"
        )
        return hashlib.sha256(tx_content.encode("utf-8")).hexdigest()

    def verify_transaction(self, sender_public_key: ec.EllipticCurvePublicKey) -> bool:
        tx_details = self._get_tx_details()
        if not Account.verify(sender_public_key, tx_details, self.signature):
            return False

        amount_bytes = str(self.amount).encode("utf-8")
        amount_sig = bytes.fromhex(self.data["amount_signature"])
        if not Account.verify(sender_public_key, amount_bytes, amount_sig):
            return False

        return True

    def to_dict(self) -> dict:
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
        tx = object.__new__(cls)
        tx.sender_address = data["sender_address"]
        tx.receiver_address = data["receiver_address"]
        tx.amount = data["amount"]
        tx.signature = bytes.fromhex(data["signature"])
        tx.amount_signature = bytes.fromhex(data["amount_signature"])
        tx.data = data["data"]
        tx.tx_id = data["tx_id"]
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
