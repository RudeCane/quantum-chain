"""
Quantum-Resistant Blockchain in Python
=======================================
- Block hashing      : SHA-256 (Proof-of-Work)
- Quantum signatures : CRYSTALS-Dilithium2 (pip install dilithium-py)
                       Fallback: Lamport OTS (pure Python, hash-based, QR)
- Supply model       : UNLIMITED total supply
                       Hard cap of 20,000,000 coins per 365-day epoch
                       Unused allowance does NOT roll over to next epoch
                       Coinbase reward auto-scales to never exceed the cap

Install optional (for real Dilithium):
    pip install dilithium-py
"""

import hashlib
import json
import time
import os
from typing import List, Optional, Tuple, Dict, Any

# ─────────────────────────────────────────────────────────────
# SUPPLY CONSTANTS
# ─────────────────────────────────────────────────────────────

ANNUAL_CAP     = 20_000_000.0       # max coins mineable per epoch
EPOCH_SECONDS  = 365 * 24 * 3600   # one epoch = 365 days (wall-clock)

# ─────────────────────────────────────────────────────────────
# 1. QUANTUM-RESISTANT SIGNATURE SCHEME
# ─────────────────────────────────────────────────────────────

try:
    from dilithium_py.dilithium import Dilithium2  # pip install dilithium-py

    SCHEME = "Dilithium2 (CRYSTALS / NIST PQC)"

    def generate_keypair() -> Tuple[bytes, bytes]:
        pk, sk = Dilithium2.keygen()
        return pk, sk

    def sign_message(sk: bytes, message: bytes) -> bytes:
        return Dilithium2.sign(sk, message)

    def verify_signature(pk: bytes, message: bytes, signature: bytes) -> bool:
        try:
            return Dilithium2.verify(pk, message, signature)
        except Exception:
            return False

except ImportError:
    SCHEME = "Lamport-OTS (SHA-256, hash-based QR)"

    def _sha256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def generate_keypair() -> Tuple[bytes, bytes]:
        sk_values = [os.urandom(32) for _ in range(512)]
        pk_values = [_sha256(s) for s in sk_values]
        return b"".join(pk_values), b"".join(sk_values)

    def sign_message(sk: bytes, message: bytes) -> bytes:
        sk_values = [sk[i * 32:(i + 1) * 32] for i in range(512)]
        msg_hash  = _sha256(message)
        sig_parts = []
        for byte_idx in range(32):
            byte = msg_hash[byte_idx]
            for bit_idx in range(8):
                bit      = (byte >> (7 - bit_idx)) & 1
                position = byte_idx * 8 + bit_idx
                sig_parts.append(sk_values[position * 2 + bit])
        return b"".join(sig_parts)

    def verify_signature(pk: bytes, message: bytes, signature: bytes) -> bool:
        try:
            pk_values = [pk[i * 32:(i + 1) * 32] for i in range(512)]
            msg_hash  = _sha256(message)
            sig_parts = [signature[i * 32:(i + 1) * 32] for i in range(256)]
            for byte_idx in range(32):
                byte = msg_hash[byte_idx]
                for bit_idx in range(8):
                    bit      = (byte >> (7 - bit_idx)) & 1
                    position = byte_idx * 8 + bit_idx
                    if _sha256(sig_parts[position]) != pk_values[position * 2 + bit]:
                        return False
            return True
        except Exception:
            return False


# ─────────────────────────────────────────────────────────────
# 2. EMISSION LEDGER
# ─────────────────────────────────────────────────────────────

class EmissionLedger:
    """
    Tracks coins minted per 365-day epoch.

    Epoch numbering (0-indexed, unlimited):
        epoch 0  →  [genesis,          genesis + 365d)
        epoch 1  →  [genesis + 365d,   genesis + 730d)
        epoch N  →  [genesis + N*365d, genesis + (N+1)*365d)

    Rules:
        * At most ANNUAL_CAP coins may be minted in any single epoch.
        * Unused allowance is forfeited each epoch (no rollover).
        * Total supply is unbounded across all epochs combined.
    """

    def __init__(self, genesis_timestamp: float):
        self.genesis: float = genesis_timestamp
        self._minted: Dict[int, float] = {}   # epoch_number → coins minted

    # ── epoch helpers ──────────────────────────────────────────

    def epoch_of(self, timestamp: float) -> int:
        elapsed = max(0.0, timestamp - self.genesis)
        return int(elapsed // EPOCH_SECONDS)

    def epoch_bounds(self, epoch: int) -> Tuple[float, float]:
        start = self.genesis + epoch * EPOCH_SECONDS
        return start, start + EPOCH_SECONDS

    def current_epoch(self) -> int:
        return self.epoch_of(time.time())

    # ── supply queries ─────────────────────────────────────────

    def minted_in_epoch(self, epoch: int) -> float:
        return self._minted.get(epoch, 0.0)

    def remaining_in_epoch(self, epoch: int) -> float:
        return max(0.0, ANNUAL_CAP - self.minted_in_epoch(epoch))

    def total_supply(self) -> float:
        return sum(self._minted.values())

    # ── reward calculation ─────────────────────────────────────

    def calc_reward(self, timestamp: float, requested: float) -> float:
        """Clip requested reward to whatever remains in this epoch."""
        return min(requested, self.remaining_in_epoch(self.epoch_of(timestamp)))

    def record_mint(self, timestamp: float, amount: float) -> None:
        if amount <= 0:
            return
        epoch = self.epoch_of(timestamp)
        self._minted[epoch] = self.minted_in_epoch(epoch) + amount

    # ── reporting ─────────────────────────────────────────────

    def summary(self) -> str:
        lines = [
            "━" * 55,
            "  Emission Ledger",
            f"  Genesis    : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.genesis))}",
            f"  Annual cap : {ANNUAL_CAP:>10,.1f} coins per 365-day epoch",
            f"  Total minted: {self.total_supply():>10,.4f} coins (supply is unlimited)",
            "  Per-epoch breakdown:",
        ]
        if not self._minted:
            lines.append("    (no coins minted yet)")
        for epoch in sorted(self._minted):
            start, end = self.epoch_bounds(epoch)
            minted = self._minted[epoch]
            pct    = minted / ANNUAL_CAP * 100
            lines.append(
                f"    Epoch {epoch:>3}  "
                f"{time.strftime('%Y-%m-%d', time.localtime(start))} – "
                f"{time.strftime('%Y-%m-%d', time.localtime(end))}  "
                f"minted={minted:>10,.4f}  ({pct:6.2f}% of cap)"
            )
        lines.append("━" * 55)
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# 3. TRANSACTION
# ─────────────────────────────────────────────────────────────

class Transaction:
    def __init__(self, sender_pk: bytes, recipient_pk: bytes,
                 amount: float, timestamp: Optional[float] = None):
        self.sender_pk    = sender_pk
        self.recipient_pk = recipient_pk
        self.amount       = amount
        self.timestamp    = timestamp or time.time()
        self.signature: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sender_pk":    self.sender_pk.hex(),
            "recipient_pk": self.recipient_pk.hex(),
            "amount":       self.amount,
            "timestamp":    self.timestamp,
        }

    def serialize(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True).encode()

    def sign(self, sk: bytes) -> None:
        self.signature = sign_message(sk, self.serialize())

    def is_valid(self) -> bool:
        if self.sender_pk == b"COINBASE":
            return True
        if not self.signature:
            return False
        return verify_signature(self.sender_pk, self.serialize(), self.signature)

    def __repr__(self) -> str:
        src = "COINBASE" if self.sender_pk == b"COINBASE" else self.sender_pk.hex()[:12] + "..."
        return f"Transaction(amount={self.amount:.4f}, from={src})"


# ─────────────────────────────────────────────────────────────
# 4. BLOCK
# ─────────────────────────────────────────────────────────────

class Block:
    def __init__(self, index: int, transactions: List[Transaction],
                 previous_hash: str, difficulty: int = 4,
                 timestamp: Optional[float] = None):
        self.index         = index
        self.transactions  = transactions
        self.previous_hash = previous_hash
        self.timestamp     = timestamp or time.time()
        self.difficulty    = difficulty
        self.nonce         = 0
        self.hash          = self.compute_hash()

    def compute_hash(self) -> str:
        data = {
            "index":         self.index,
            "previous_hash": self.previous_hash,
            "timestamp":     self.timestamp,
            "nonce":         self.nonce,
            "transactions":  [tx.to_dict() for tx in self.transactions],
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def mine(self) -> None:
        target = "0" * self.difficulty
        print(f"  Mining block {self.index} (difficulty={self.difficulty})...", end=" ", flush=True)
        t0 = time.time()
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash   = self.compute_hash()
        print(f"Found!  nonce={self.nonce}  hash={self.hash[:20]}...  ({time.time()-t0:.2f}s)")

    def is_valid_pow(self) -> bool:
        return self.hash == self.compute_hash() and self.hash.startswith("0" * self.difficulty)

    def transactions_valid(self) -> bool:
        return all(tx.is_valid() for tx in self.transactions)

    def coinbase_amount(self) -> float:
        return sum(tx.amount for tx in self.transactions if tx.sender_pk == b"COINBASE")

    def __repr__(self) -> str:
        return (f"Block(index={self.index}, hash={self.hash[:16]}..., "
                f"txs={len(self.transactions)}, nonce={self.nonce})")


# ─────────────────────────────────────────────────────────────
# 5. BLOCKCHAIN
# ─────────────────────────────────────────────────────────────

class Blockchain:
    """
    Unlimited-supply, quantum-resistant blockchain.

    Emission model:
      - Each 365-day epoch: miners may collectively produce at most
        ANNUAL_CAP (20,000,000) new coins.
      - Coinbase rewards are automatically reduced when the cap is near.
      - Epochs are infinite — the chain continues forever.
      - Unused coins within an epoch are simply not minted (no rollover).
      - Chain validation replays the emission ledger and rejects any block
        that would push a single epoch over the cap.
    """

    BASE_REWARD = 50.0  # target reward per block; clipped to epoch remaining

    def __init__(self, difficulty: int = 4,
                 genesis_timestamp: Optional[float] = None):
        self.difficulty            = difficulty
        self.chain: List[Block]    = []
        self.pending_transactions: List[Transaction] = []
        ts             = genesis_timestamp or time.time()
        self.emission  = EmissionLedger(genesis_timestamp=ts)
        self._create_genesis_block()

    # ── genesis ───────────────────────────────────────────────

    def _create_genesis_block(self) -> None:
        genesis = Block(
            index=0,
            transactions=[],
            previous_hash="0" * 64,
            difficulty=self.difficulty,
            timestamp=self.emission.genesis,
        )
        genesis.nonce = 0
        genesis.hash  = genesis.compute_hash()
        self.chain.append(genesis)
        print(f"Genesis block  hash={genesis.hash[:20]}...")
        print(f"  Epoch 0 start: "
              f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.emission.genesis))}")

    # ── properties ────────────────────────────────────────────

    @property
    def latest_block(self) -> Block:
        return self.chain[-1]

    def current_epoch(self) -> int:
        return self.emission.current_epoch()

    def epoch_remaining(self, epoch: Optional[int] = None) -> float:
        e = self.current_epoch() if epoch is None else epoch
        return self.emission.remaining_in_epoch(e)

    def total_supply(self) -> float:
        return self.emission.total_supply()

    # ── transactions ──────────────────────────────────────────

    def add_transaction(self, tx: Transaction) -> bool:
        if not tx.is_valid():
            print(f"  ✗ Rejected invalid tx: {tx}")
            return False
        self.pending_transactions.append(tx)
        print(f"  ✓ Queued: {tx}")
        return True

    # ── mining ────────────────────────────────────────────────

    def mine_pending_transactions(self, miner_pk: bytes) -> Block:
        """
        Mine all pending transactions.
        Coinbase reward = min(BASE_REWARD, coins_remaining_this_epoch).
        If the epoch cap is fully exhausted, the block still mines but
        the miner earns 0 from coinbase (transaction fees would apply in
        a full implementation).
        """
        ts     = time.time()
        epoch  = self.emission.epoch_of(ts)
        reward = self.emission.calc_reward(ts, self.BASE_REWARD)

        remaining = self.emission.remaining_in_epoch(epoch)
        print(f"\n  Epoch {epoch} | cap remaining: {remaining:,.4f} | "
              f"coinbase reward: {reward:.4f}")

        transactions: List[Transaction] = []
        if reward > 0:
            transactions.append(Transaction(
                sender_pk    = b"COINBASE",
                recipient_pk = miner_pk,
                amount       = reward,
                timestamp    = ts,
            ))
        else:
            print(f"  ⚠ Epoch {epoch} cap exhausted — block mined with no coinbase reward.")

        transactions.extend(self.pending_transactions)

        block = Block(
            index         = len(self.chain),
            transactions  = transactions,
            previous_hash = self.latest_block.hash,
            difficulty    = self.difficulty,
            timestamp     = ts,
        )
        block.mine()

        self.emission.record_mint(ts, reward)
        self.chain.append(block)
        self.pending_transactions = []
        return block

    # ── validation ────────────────────────────────────────────

    def is_chain_valid(self) -> bool:
        """
        Full chain validation including replay of annual emission cap.
        """
        print("\nValidating chain...")
        replay: Dict[int, float] = {}  # epoch → cumulative minted

        for i in range(1, len(self.chain)):
            cur  = self.chain[i]
            prev = self.chain[i - 1]

            # 1. Hash integrity
            if cur.hash != cur.compute_hash():
                print(f"  ✗ Block {i}: hash mismatch"); return False

            # 2. Chain linkage
            if cur.previous_hash != prev.hash:
                print(f"  ✗ Block {i}: broken chain link"); return False

            # 3. Proof-of-Work
            if not cur.is_valid_pow():
                print(f"  ✗ Block {i}: invalid PoW"); return False

            # 4. Transaction signatures
            if not cur.transactions_valid():
                print(f"  ✗ Block {i}: bad transaction signature"); return False

            # 5. Annual emission cap
            epoch        = self.emission.epoch_of(cur.timestamp)
            cb           = cur.coinbase_amount()
            epoch_total  = replay.get(epoch, 0.0) + cb
            if epoch_total > ANNUAL_CAP + 1e-9:
                print(f"  ✗ Block {i}: epoch {epoch} emission exceeds cap "
                      f"({epoch_total:.4f} > {ANNUAL_CAP:.1f})")
                return False
            replay[epoch] = epoch_total

            print(f"  ✓ Block {i}  epoch={epoch}  "
                  f"cb={cb:.4f}  epoch_total={epoch_total:.4f}")

        print("Chain is VALID ✓")
        return True

    # ── balance ───────────────────────────────────────────────

    def get_balance(self, pk: bytes) -> float:
        bal = 0.0
        for block in self.chain:
            for tx in block.transactions:
                if tx.recipient_pk == pk: bal += tx.amount
                if tx.sender_pk    == pk: bal -= tx.amount
        return bal

    def __repr__(self) -> str:
        return (f"Blockchain(blocks={len(self.chain)}, "
                f"difficulty={self.difficulty}, "
                f"supply={self.total_supply():,.4f})")


# ─────────────────────────────────────────────────────────────
# 6. WALLET
# ─────────────────────────────────────────────────────────────

class Wallet:
    def __init__(self):
        print(f"Generating {SCHEME} keypair...")
        self.pk, self.sk = generate_keypair()
        print(f"  Public key: {self.pk.hex()[:32]}...")

    def create_transaction(self, recipient_pk: bytes, amount: float) -> Transaction:
        tx = Transaction(self.pk, recipient_pk, amount)
        tx.sign(self.sk)
        return tx

    def address(self) -> str:
        return hashlib.sha256(self.pk).hexdigest()[:40]


# ─────────────────────────────────────────────────────────────
# 7. DEMO
# ─────────────────────────────────────────────────────────────

def demo():
    SEP = "=" * 65

    print(SEP)
    print("  Quantum-Resistant Blockchain")
    print(f"  Signature : {SCHEME}")
    print(f"  Hashing   : SHA-256 (Proof-of-Work)")
    print(f"  Supply    : UNLIMITED — hard cap {ANNUAL_CAP:,.0f} coins / 365 days")
    print(SEP)

    # ── Blockchain + wallets ──────────────────────────────────
    bc    = Blockchain(difficulty=3)
    alice = Wallet()
    bob   = Wallet()
    miner = Wallet()
    print(f"\n  Alice : {alice.address()}")
    print(f"  Bob   : {bob.address()}")
    print(f"  Miner : {miner.address()}")

    # ── Mine a couple of normal blocks ────────────────────────
    print(f"\n── Block 1: coinbase to miner ──")
    bc.mine_pending_transactions(miner_pk=miner.pk)

    print(f"\n── Miner sends 20 to Alice, Alice sends 10 to Bob ──")
    bc.add_transaction(miner.create_transaction(alice.pk, 20.0))
    bc.add_transaction(alice.create_transaction(bob.pk,   10.0))
    print(f"\n── Block 2: mine with 2 pending transactions ──")
    bc.mine_pending_transactions(miner_pk=miner.pk)

    # ── Demonstrate cap exhaustion ────────────────────────────
    print(f"\n── Simulating epoch cap exhaustion ──")
    epoch0    = bc.emission.epoch_of(time.time())
    remaining = bc.emission.remaining_in_epoch(epoch0)
    print(f"  Epoch {epoch0} remaining: {remaining:.4f}  — burning it artificially...")
    bc.emission.record_mint(time.time(), remaining)
    print(f"  Epoch {epoch0} remaining after burn: {bc.emission.remaining_in_epoch(epoch0):.4f}")

    print(f"\n── Block 3: cap exhausted (expect 0 coinbase) ──")
    bc.mine_pending_transactions(miner_pk=miner.pk)

    # ── Show next epoch would reset ───────────────────────────
    future_ts   = bc.emission.genesis + (epoch0 + 1) * EPOCH_SECONDS + 60
    epoch_next  = bc.emission.epoch_of(future_ts)
    print(f"\n── Next epoch ({epoch_next}) allowance: "
          f"{bc.emission.remaining_in_epoch(epoch_next):,.1f} coins ──")
    print("  (Full 20,000,000-coin cap resets for each new 365-day epoch)")

    # ── Chain validation ──────────────────────────────────────
    bc.is_chain_valid()

    # ── Balances ──────────────────────────────────────────────
    print(f"\n── Balances ──")
    print(f"  Alice : {bc.get_balance(alice.pk):>12.4f}")
    print(f"  Bob   : {bc.get_balance(bob.pk):>12.4f}")
    print(f"  Miner : {bc.get_balance(miner.pk):>12.4f}")

    # ── Emission summary ──────────────────────────────────────
    print(f"\n{bc.emission.summary()}")

    # ── Tamper test: inflate a coinbase past the cap ──────────
    print("── Tamper Test: set coinbase to 2x annual cap ──")
    bc.chain[1].transactions[0].amount = ANNUAL_CAP * 2
    bc.chain[1].hash = bc.chain[1].compute_hash()
    result = bc.is_chain_valid()
    print(f"  Chain valid after tampering: {result}")

    print(f"\n{SEP}\nDone.\n{SEP}")


if __name__ == "__main__":
    demo()
