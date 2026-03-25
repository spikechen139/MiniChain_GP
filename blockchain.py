"""
MiniChain - Phase I: The Building Blocks
=========================================
本模块实现了 MiniChain 区块链项目的第一阶段，包含：
1. 基于 ECC 的账户系统 (Account)
2. 单输入单输出交易 (SISO Transaction)
3. 可验证的 Merkle 树 (Verifiable Merkle Tree)

依赖库: cryptography, hashlib
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import List, Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature


# ============================================================================
# 1. Account — 基于 ECC 的账户（公私钥对）
# ============================================================================

class Account:
    """
    区块链账户类，使用椭圆曲线加密 (ECC) 生成公私钥对。

    Attributes:
        private_key: ECC 私钥对象（SECP256K1 曲线）
        public_key:  ECC 公钥对象
        address:     账户地址（公钥的十六进制编码）
    """

    def __init__(self) -> None:
        """创建新账户：自动生成 ECC 密钥对并派生地址。"""
        # 使用 SECP256K1 曲线（与比特币、以太坊一致）
        self._private_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
            ec.SECP256K1()
        )
        self._public_key: ec.EllipticCurvePublicKey = self._private_key.public_key()

        # 将公钥序列化为未压缩格式的十六进制字符串，作为账户地址
        self.address: str = self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        ).hex()

    # ---- 属性访问 --------------------------------------------------------

    @property
    def private_key(self) -> ec.EllipticCurvePrivateKey:
        """返回私钥对象（仅账户持有者使用）。"""
        return self._private_key

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        """返回公钥对象。"""
        return self._public_key

    # ---- 签名与验证 ------------------------------------------------------

    def sign(self, message: bytes) -> bytes:
        """
        使用私钥对消息进行 ECDSA 签名。

        Args:
            message: 待签名的字节数据

        Returns:
            签名的字节数据 (DER 编码)
        """
        signature = self._private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature

    @staticmethod
    def verify(public_key: ec.EllipticCurvePublicKey,
               message: bytes,
               signature: bytes) -> bool:
        """
        使用公钥验证消息的 ECDSA 签名。

        Args:
            public_key: 签名者的公钥
            message:    原始消息字节数据
            signature:  待验证的签名

        Returns:
            True 表示签名有效，False 表示无效
        """
        try:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    def __repr__(self) -> str:
        return f"Account(address={self.address[:16]}...)"


# ============================================================================
# 2. Transaction — 单输入单输出 (SISO) 交易
# ============================================================================

class Transaction:
    """
    单输入单输出 (SISO) 交易类。

    每笔交易包含：
        - tx_id:     交易 ID（交易内容的 SHA-256 哈希值）
        - sender:    发送者地址（Input）
        - receiver:  接收者地址（Output）
        - amount:    虚拟币转账金额
        - signature: 发送者对交易细节的数字签名
        - data:      包含金额与金额签名的数据字段
    """

    def __init__(self,
                 sender: Account,
                 receiver: Account,
                 amount: float) -> None:
        """
        构造并签名一笔 SISO 交易。

        Args:
            sender:   发送者账户（需要私钥来签名）
            receiver: 接收者账户
            amount:   转账金额（虚拟币）
        """
        # ---- 基本字段 ----------------------------------------------------
        self.sender_address: str = sender.address        # Input
        self.receiver_address: str = receiver.address     # Output
        self.amount: float = amount

        # ---- Data 字段：金额 + 金额的数字签名 ----------------------------
        amount_bytes = str(amount).encode("utf-8")
        self.amount_signature: bytes = sender.sign(amount_bytes)
        self.data: dict = {
            "amount": self.amount,
            "amount_signature": self.amount_signature.hex(),
        }

        # ---- Signature：发送者对交易细节的签名 ----------------------------
        tx_details = self._get_tx_details()
        self.signature: bytes = sender.sign(tx_details)

        # ---- Transaction ID：交易内容的 SHA-256 哈希 ----------------------
        self.tx_id: str = self._compute_tx_id()

    # ---- 内部方法 --------------------------------------------------------

    def _get_tx_details(self) -> bytes:
        """
        将交易关键字段拼接为字节串，用于签名和哈希。

        包含：sender_address + receiver_address + amount
        """
        details = (
            f"{self.sender_address}"
            f"{self.receiver_address}"
            f"{self.amount}"
        )
        return details.encode("utf-8")

    def _compute_tx_id(self) -> str:
        """
        计算交易 ID —— 对交易完整内容进行 SHA-256 哈希。

        Returns:
            十六进制字符串形式的交易哈希
        """
        tx_content = (
            f"{self.sender_address}"
            f"{self.receiver_address}"
            f"{self.amount}"
            f"{self.signature.hex()}"
        )
        return hashlib.sha256(tx_content.encode("utf-8")).hexdigest()

    # ---- 验证方法 --------------------------------------------------------

    def verify_transaction(self, sender_public_key: ec.EllipticCurvePublicKey) -> bool:
        """
        验证交易签名的合法性。

        步骤：
            1. 验证交易细节签名（sender, receiver, amount）
            2. 验证金额数据签名

        Args:
            sender_public_key: 发送者的公钥

        Returns:
            True 表示交易合法，False 表示签名无效
        """
        # 验证交易签名
        tx_details = self._get_tx_details()
        if not Account.verify(sender_public_key, tx_details, self.signature):
            return False

        # 验证金额签名
        amount_bytes = str(self.amount).encode("utf-8")
        amount_sig = bytes.fromhex(self.data["amount_signature"])
        if not Account.verify(sender_public_key, amount_bytes, amount_sig):
            return False

        return True

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
# 3. MerkleTree — 可验证 Merkle 树
# ============================================================================

class MerkleTree:
    """
    可验证的 Merkle 树实现。

    使用 SHA-256 哈希函数，从交易列表自底向上构建 Merkle 树，
    最终生成唯一的 Merkle Root。

    假设：交易数量为 2 的幂次方（2, 4, 8, …）
    """

    def __init__(self, transactions: List[Transaction]) -> None:
        """
        从交易列表构建 Merkle 树。

        Args:
            transactions: 交易对象列表（数量必须为 2 的幂次方）

        Raises:
            ValueError: 交易列表为空或数量不是 2 的幂次方
        """
        if not transactions:
            raise ValueError("交易列表不能为空。")
        if not self._is_power_of_two(len(transactions)):
            raise ValueError(
                f"交易数量必须为 2 的幂次方，当前数量: {len(transactions)}"
            )

        self.transactions: List[Transaction] = transactions
        self.levels: List[List[str]] = []   # 存储每一层的哈希值
        self.root: str = self._build_tree()

    # ---- 构建逻辑 --------------------------------------------------------

    def _build_tree(self) -> str:
        """
        自底向上构建 Merkle 树。

        1. 叶子层：计算每笔交易 ID 的 SHA-256 哈希值
        2. 逐层两两配对哈希，直到只剩一个根节点

        Returns:
            Merkle Root（十六进制字符串）
        """
        # 第 0 层（叶子节点）：对每笔交易的 tx_id 计算 SHA-256
        current_level = [
            self._sha256(tx.tx_id) for tx in self.transactions
        ]
        self.levels.append(current_level)

        # 逐层向上合并，直到只剩一个哈希值
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

    # ---- 辅助方法 --------------------------------------------------------

    @staticmethod
    def _sha256(data: str) -> str:
        """
        对字符串数据计算 SHA-256 哈希。

        Args:
            data: 输入字符串

        Returns:
            十六进制编码的哈希值
        """
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @staticmethod
    def _is_power_of_two(n: int) -> bool:
        """判断一个正整数是否为 2 的幂次方。"""
        return n > 0 and (n & (n - 1)) == 0

    def print_tree(self) -> None:
        """可视化打印 Merkle 树的各层结构。"""
        total_levels = len(self.levels)
        for i, level in enumerate(reversed(self.levels)):
            depth = total_levels - 1 - i
            if depth == total_levels - 1:
                label = "Root"
            elif depth == 0:
                label = "Leaves"
            else:
                label = f"Level {depth}"
            print(f"\n{'='*60}")
            print(f"  {label} (depth={depth}, nodes={len(level)})")
            print(f"{'='*60}")
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
# 主演示程序
# ============================================================================

def main() -> None:
    """演示 MiniChain Phase I 的完整流程。"""

    print("=" * 70)
    print("  MiniChain — Phase I: The Building Blocks")
    print("=" * 70)

    # ------------------------------------------------------------------
    # Step 1: 创建账户
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  Step 1: 创建账户 (Account Creation)")
    print("=" * 70)

    alice = Account()
    bob = Account()
    charlie = Account()
    diana = Account()

    accounts = {"Alice": alice, "Bob": bob, "Charlie": charlie, "Diana": diana}
    for name, acc in accounts.items():
        print(f"  {name:>8} -> address: {acc.address[:32]}...")

    # ------------------------------------------------------------------
    # Step 2: 生成 SISO 交易
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  Step 2: 生成 SISO 交易 (Transaction Generation)")
    print("=" * 70)

    # 创建 4 笔交易（2 的幂次方，满足 Merkle 树要求）
    tx1 = Transaction(sender=alice,   receiver=bob,     amount=10.0)
    tx2 = Transaction(sender=bob,     receiver=charlie, amount=5.0)
    tx3 = Transaction(sender=charlie, receiver=diana,   amount=3.0)
    tx4 = Transaction(sender=diana,   receiver=alice,   amount=7.5)

    transactions = [tx1, tx2, tx3, tx4]

    for i, tx in enumerate(transactions, 1):
        print(f"\n  --- Transaction {i} ---")
        print(f"  TX ID     : {tx.tx_id}")
        print(f"  Sender    : {tx.sender_address[:32]}...")
        print(f"  Receiver  : {tx.receiver_address[:32]}...")
        print(f"  Amount    : {tx.amount}")
        print(f"  Signature : {tx.signature.hex()[:32]}...")

    # ------------------------------------------------------------------
    # Step 3: 验证交易签名
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  Step 3: 验证交易签名 (Transaction Verification)")
    print("=" * 70)

    senders = [alice, bob, charlie, diana]
    for i, (tx, sender) in enumerate(zip(transactions, senders), 1):
        is_valid = tx.verify_transaction(sender.public_key)
        status = "✓ VALID" if is_valid else "✗ INVALID"
        print(f"  Transaction {i}: {status}")

    # 演示使用错误公钥验证 — 应返回 False
    print("\n  [篡改测试] 使用 Bob 的公钥验证 Alice 发起的 TX1:")
    is_valid = tx1.verify_transaction(bob.public_key)
    status = "✓ VALID" if is_valid else "✗ INVALID (预期结果)"
    print(f"  Transaction 1: {status}")

    # ------------------------------------------------------------------
    # Step 4: 构建 Merkle 树
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  Step 4: 构建 Merkle 树 (Merkle Tree Construction)")
    print("=" * 70)

    merkle_tree = MerkleTree(transactions)
    print(f"\n  Merkle Root: {merkle_tree.root}")
    print(f"  树层数:       {len(merkle_tree.levels)}")

    # 可视化打印 Merkle 树
    merkle_tree.print_tree()

    # ------------------------------------------------------------------
    # Step 5: Merkle Root 一致性验证
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  Step 5: Merkle Root 一致性验证")
    print("=" * 70)

    # 用相同交易重新构建，Root 应一致
    merkle_tree_2 = MerkleTree(transactions)
    match = merkle_tree.root == merkle_tree_2.root
    print(f"  同交易重建 Merkle Root 一致: {'✓ YES' if match else '✗ NO'}")

    # 修改交易顺序，Root 应不同
    merkle_tree_3 = MerkleTree([tx4, tx3, tx2, tx1])
    mismatch = merkle_tree.root != merkle_tree_3.root
    print(f"  交易顺序改变后 Root 不同:    {'✓ YES' if mismatch else '✗ NO'}")

    print("\n" + "=" * 70)
    print("  Phase I 演示完成！")
    print("=" * 70)


if __name__ == "__main__":
    main()
