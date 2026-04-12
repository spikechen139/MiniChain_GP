"""ECC-based account: key pair, address, sign/verify."""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class Account:
    """
    Blockchain account class using Elliptic Curve Cryptography (ECC).

    Generates a SECP256K1 key pair and derives a hex-encoded address
    from the uncompressed public key.
    """

    def __init__(self) -> None:
        self._private_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
            ec.SECP256K1()
        )
        self._public_key: ec.EllipticCurvePublicKey = self._private_key.public_key()

        self.address: str = self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        ).hex()

    @property
    def private_key(self) -> ec.EllipticCurvePrivateKey:
        return self._private_key

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self._public_key

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    @staticmethod
    def verify(
        public_key: ec.EllipticCurvePublicKey,
        message: bytes,
        signature: bytes,
    ) -> bool:
        try:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    def to_dict(self) -> dict:
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
        acc = object.__new__(cls)
        acc._private_key = serialization.load_pem_private_key(
            data["private_key_pem"].encode("utf-8"),
            password=None,
        )
        acc._public_key = acc._private_key.public_key()
        acc.address = data["address"]
        return acc

    def __repr__(self) -> str:
        return f"Account(address={self.address[:16]}...)"
