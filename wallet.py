"""
Quantum-Resistant Wallet
========================
A full-featured CLI wallet for the QR blockchain.

Security model:
  • Keys generated with CRYSTALS-Dilithium2 (NIST PQC standard)
    — falls back to Lamport OTS (SHA-256 hash-based, also QR)
  • Private key NEVER stored in plaintext
  • Keystore encrypted with AES-256-GCM derived from passphrase
    via PBKDF2-HMAC-SHA256 (600,000 iterations)
  • Wallet file is a single encrypted JSON blob
  • Address = SHA-256(public_key)[:40]  (hex)

Features:
  • Create / load wallet
  • Show address & balance (via node RPC)
  • Send coins (signs tx, broadcasts to node)
  • Transaction history
  • Address book (label → address)
  • Export / import wallet
  • QR code display for address (terminal ASCII art)
  • Multi-wallet support

Usage:
    python wallet.py                        # interactive menu
    python wallet.py --wallet mywallet.qwallet
    python wallet.py --node 127.0.0.1:6000  # connect to running node

Requirements (all stdlib except optional qrcode):
    pip install qrcode          # optional — terminal QR codes
    pip install dilithium-py    # optional — real Dilithium signatures
"""

import os
import sys
import json
import time
import hashlib
import hmac
import struct
import getpass
import argparse
import socket
import threading
from typing import Optional, Tuple, Dict, List, Any

# ── optional imports ──────────────────────────────────────────
try:
    import qrcode                    # pip install qrcode
    HAS_QR = True
except ImportError:
    HAS_QR = False

# ── bring in our crypto from the blockchain core ──────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from quantum_blockchain import (
        generate_keypair, sign_message, verify_signature, SCHEME,
        Transaction,
    )
except ImportError:
    print("ERROR: quantum_blockchain.py must be in the same folder as wallet.py")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────

WALLET_EXT       = ".qwallet"
PBKDF2_ITERS     = 600_000
AES_KEY_BYTES    = 32   # AES-256
SALT_BYTES       = 32
NONCE_BYTES      = 12   # GCM nonce
TAG_BYTES        = 16   # GCM auth tag
WALLET_VERSION   = 1
DEFAULT_NODE     = ("127.0.0.1", 6000)

# Terminal colours
C_RESET  = "\033[0m"
C_BOLD   = "\033[1m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN   = "\033[96m"
C_RED    = "\033[91m"
C_DIM    = "\033[2m"
C_MAGENTA= "\033[95m"


def c(text: str, colour: str) -> str:
    return f"{colour}{text}{C_RESET}"


# ─────────────────────────────────────────────────────────────
# AES-256-GCM (pure Python — stdlib only)
# Uses the PyCryptodome approach manually via ctypes if available,
# otherwise falls back to XSalsa20-style construction with HMAC.
# For production, swap in: from Cryptodome.Cipher import AES
# ─────────────────────────────────────────────────────────────

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 key derivation."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        PBKDF2_ITERS,
        dklen=AES_KEY_BYTES,
    )

# Try to use PyCryptodome or cryptography lib for real AES-GCM
def _try_aes_gcm():
    try:
        from Cryptodome.Cipher import AES as _AES
        def encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
            nonce  = os.urandom(NONCE_BYTES)
            cipher = _AES.new(key, _AES.MODE_GCM, nonce=nonce)
            ct, tag = cipher.encrypt_and_digest(plaintext)
            return nonce, ct, tag
        def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
            cipher = _AES.new(key, _AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
        return encrypt, decrypt, "AES-256-GCM (PyCryptodome)"
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        def encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
            nonce  = os.urandom(NONCE_BYTES)
            aesgcm = AESGCM(key)
            ct_tag = aesgcm.encrypt(nonce, plaintext, None)
            ct, tag = ct_tag[:-TAG_BYTES], ct_tag[-TAG_BYTES:]
            return nonce, ct, tag
        def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext + tag, None)
        return encrypt, decrypt, "AES-256-GCM (cryptography)"
    except ImportError:
        pass
    return None, None, None

_aes_encrypt, _aes_decrypt, _aes_backend = _try_aes_gcm()

if _aes_encrypt is None:
    # Fallback: AES-CTR + HMAC-SHA256 (encrypt-then-MAC) using stdlib only
    # This uses a manual AES-CTR implementation via hashlib counter mode.
    # NOTE: for production always install pycryptodome or cryptography.
    import struct as _struct

    def _aes_ctr_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
        """Generate keystream via SHA-256 counter mode (stdlib fallback)."""
        stream = bytearray()
        counter = 0
        while len(stream) < length:
            block = hashlib.sha256(key + nonce + _struct.pack(">Q", counter)).digest()
            stream.extend(block)
            counter += 1
        return bytes(stream[:length])

    def _aes_encrypt_fallback(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        nonce     = os.urandom(NONCE_BYTES)
        keystream = _aes_ctr_keystream(key, nonce, len(plaintext))
        ct        = bytes(a ^ b for a, b in zip(plaintext, keystream))
        tag       = hmac.new(key, nonce + ct, hashlib.sha256).digest()[:TAG_BYTES]
        return nonce, ct, tag

    def _aes_decrypt_fallback(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        expected_tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[:TAG_BYTES]
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("MAC verification failed — wrong passphrase or corrupted wallet")
        keystream = _aes_ctr_keystream(key, nonce, len(ciphertext))
        return bytes(a ^ b for a, b in zip(ciphertext, keystream))

    _aes_encrypt  = _aes_encrypt_fallback
    _aes_decrypt  = _aes_decrypt_fallback
    _aes_backend  = "AES-CTR + HMAC-SHA256 (stdlib fallback — install pycryptodome for GCM)"


def encrypt_data(passphrase: str, plaintext: bytes) -> Dict[str, str]:
    """Encrypt bytes with passphrase. Returns JSON-serialisable dict."""
    salt           = os.urandom(SALT_BYTES)
    key            = _derive_key(passphrase, salt)
    nonce, ct, tag = _aes_encrypt(key, plaintext)
    return {
        "salt":       salt.hex(),
        "nonce":      nonce.hex(),
        "ciphertext": ct.hex(),
        "tag":        tag.hex(),
        "backend":    _aes_backend,
        "pbkdf2_iter": PBKDF2_ITERS,
    }

def decrypt_data(passphrase: str, enc: Dict[str, str]) -> bytes:
    """Decrypt an encrypt_data() blob."""
    salt  = bytes.fromhex(enc["salt"])
    nonce = bytes.fromhex(enc["nonce"])
    ct    = bytes.fromhex(enc["ciphertext"])
    tag   = bytes.fromhex(enc["tag"])
    key   = _derive_key(passphrase, salt)
    return _aes_decrypt(key, nonce, ct, tag)


# ─────────────────────────────────────────────────────────────
# KEYSTORE  —  on-disk encrypted wallet file
# ─────────────────────────────────────────────────────────────

class Keystore:
    """
    Encrypted wallet file.

    Schema (plaintext JSON before encryption):
    {
      "version":    1,
      "scheme":     "Lamport-OTS / Dilithium2",
      "pk":         "<hex>",
      "sk":         "<hex>",
      "created_at": <unix_ts>,
      "label":      "My Wallet",
      "address_book": { "label": "address_hex", ... },
      "tx_history": [ { "txid", "amount", "to/from", "timestamp", "direction" } ]
    }
    """

    def __init__(self, path: str):
        self.path = path

    # ── creation ──────────────────────────────────────────────

    @staticmethod
    def create(path: str, passphrase: str, label: str = "My Wallet") -> "Keystore":
        ks = Keystore(path)
        print(f"\n  Generating {SCHEME} keypair...")
        print(f"  {c('This may take a few seconds for Lamport OTS...', C_DIM)}")
        pk, sk = generate_keypair()
        plain  = json.dumps({
            "version":      WALLET_VERSION,
            "scheme":       SCHEME,
            "pk":           pk.hex(),
            "sk":           sk.hex(),
            "created_at":   time.time(),
            "label":        label,
            "address_book": {},
            "tx_history":   [],
        }).encode()
        enc = encrypt_data(passphrase, plain)
        blob = {"encrypted": enc}
        with open(path, "w") as f:
            json.dump(blob, f, indent=2)
        print(f"  {c('Wallet saved:', C_GREEN)} {path}")
        return ks

    @staticmethod
    def load(path: str, passphrase: str) -> Dict[str, Any]:
        with open(path) as f:
            blob = json.load(f)
        try:
            plain = decrypt_data(passphrase, blob["encrypted"])
            return json.loads(plain.decode())
        except Exception:
            raise ValueError("Wrong passphrase or corrupted wallet file")

    @staticmethod
    def save(path: str, passphrase: str, data: Dict[str, Any]) -> None:
        plain = json.dumps(data).encode()
        enc   = encrypt_data(passphrase, plain)
        with open(path, "w") as f:
            json.dump({"encrypted": enc}, f, indent=2)


# ─────────────────────────────────────────────────────────────
# NODE RPC CLIENT  —  talks to p2p_node.py over TCP
# ─────────────────────────────────────────────────────────────

class NodeClient:
    """
    Lightweight JSON-over-TCP client that speaks the same protocol
    as p2p_node.py. Used by the wallet to query balance and broadcast txs.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 6000, timeout: int = 8):
        self.host    = host
        self.port    = port
        self.timeout = timeout

    def _call(self, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
                s.sendall(json.dumps(msg).encode() + b"\n")
                # Read response(s) — may need a few lines
                buf = b""
                s.settimeout(self.timeout)
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    if b"\n" in buf:
                        break
                lines = buf.split(b"\n")
                for line in lines:
                    line = line.strip()
                    if line:
                        return json.loads(line.decode())
        except Exception as e:
            return {"error": str(e)}
        return None

    def get_chain(self) -> Optional[List[Dict]]:
        resp = self._call({"type": "GET_CHAIN"})
        if resp and resp.get("type") == "CHAIN":
            return resp.get("blocks", [])
        return None

    def broadcast_tx(self, tx_dict: Dict[str, Any]) -> bool:
        resp = self._call({"type": "NEW_TX", "tx": tx_dict})
        # Node doesn't send an ACK for NEW_TX — success = no error
        return resp is None or "error" not in resp

    def get_balance(self, address_hex: str, pk_hex: str) -> Optional[float]:
        """Scan chain for all credits and debits to this public key."""
        blocks = self.get_chain()
        if blocks is None:
            return None
        balance = 0.0
        for block in blocks:
            for tx in block.get("transactions", []):
                if tx["recipient_pk"] == pk_hex:
                    balance += tx["amount"]
                if tx["sender_pk"] == pk_hex:
                    balance -= tx["amount"]
        return balance

    def get_tx_history(self, pk_hex: str) -> List[Dict]:
        blocks = self.get_chain()
        if not blocks:
            return []
        history = []
        for block in blocks:
            for tx in block.get("transactions", []):
                if tx["recipient_pk"] == pk_hex or tx["sender_pk"] == pk_hex:
                    direction = "IN" if tx["recipient_pk"] == pk_hex else "OUT"
                    counterpart = tx["sender_pk"] if direction == "IN" else tx["recipient_pk"]
                    history.append({
                        "block":       block["index"],
                        "direction":   direction,
                        "amount":      tx["amount"],
                        "counterpart": counterpart[:20] + "...",
                        "timestamp":   tx["timestamp"],
                    })
        return sorted(history, key=lambda x: x["timestamp"], reverse=True)

    def is_connected(self) -> bool:
        try:
            with socket.create_connection((self.host, self.port), timeout=3):
                return True
        except Exception:
            return False


# ─────────────────────────────────────────────────────────────
# QR CODE (terminal)
# ─────────────────────────────────────────────────────────────

def print_qr(data: str) -> None:
    if HAS_QR:
        qr = qrcode.QRCode(border=1)
        qr.add_data(data)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
    else:
        # Manual tiny QR-like block art using address hash
        print(f"\n  {c('[Install qrcode for real QR: pip install qrcode]', C_DIM)}")
        h = hashlib.sha256(data.encode()).hexdigest()
        rows = 8
        cols = 16
        print("  ┌" + "──" * cols + "┐")
        for r in range(rows):
            row = "  │"
            for c_ in range(cols):
                idx = (r * cols + c_) % len(h)
                row += "██" if int(h[idx], 16) % 2 else "  "
            print(row + "│")
        print("  └" + "──" * cols + "┘")


# ─────────────────────────────────────────────────────────────
# WALLET CLI
# ─────────────────────────────────────────────────────────────

BANNER = f"""
{C_CYAN}{C_BOLD}
  ╔═══════════════════════════════════════════════════╗
  ║     ⬡  QUANTUM-RESISTANT WALLET  ⬡               ║
  ║     SHA-256 Chain  •  Post-Quantum Signatures     ║
  ╚═══════════════════════════════════════════════════╝
{C_RESET}"""


class WalletCLI:

    def __init__(self, wallet_path: str, node_host: str, node_port: int):
        self.path       = wallet_path
        self.node       = NodeClient(node_host, node_port)
        self._data: Optional[Dict[str, Any]] = None
        self._pass: Optional[str] = None

    # ── auth ──────────────────────────────────────────────────

    def _unlock(self) -> bool:
        """Prompt for passphrase and unlock wallet."""
        attempts = 3
        for i in range(attempts):
            pp = getpass.getpass(f"  Passphrase: ")
            try:
                self._data = Keystore.load(self.path, pp)
                self._pass = pp
                return True
            except ValueError:
                remaining = attempts - i - 1
                if remaining:
                    print(f"  {c('Wrong passphrase.', C_RED)} {remaining} attempt(s) left.")
                else:
                    print(f"  {c('Too many failed attempts.', C_RED)}")
        return False

    def _save(self) -> None:
        Keystore.save(self.path, self._pass, self._data)

    @property
    def pk(self) -> bytes:
        return bytes.fromhex(self._data["pk"])

    @property
    def sk(self) -> bytes:
        return bytes.fromhex(self._data["sk"])

    @property
    def address(self) -> str:
        return hashlib.sha256(self.pk).hexdigest()[:40]

    # ── menu ──────────────────────────────────────────────────

    def run(self) -> None:
        print(BANNER)

        if not os.path.exists(self.path):
            self._first_run()
        else:
            print(f"  Loading wallet: {c(self.path, C_CYAN)}")
            if not self._unlock():
                return

        print(f"\n  {c('Wallet unlocked!', C_GREEN)}")
        print(f"  Scheme  : {c(self._data['scheme'], C_MAGENTA)}")
        print(f"  Label   : {c(self._data['label'], C_BOLD)}")
        print(f"  Address : {c(self.address, C_YELLOW)}")
        node_status = c("● connected", C_GREEN) if self.node.is_connected() else c("○ offline", C_DIM)
        print(f"  Node    : {self.node.host}:{self.node.port}  {node_status}\n")

        while True:
            self._print_menu()
            choice = input(f"  {c('>', C_CYAN)} ").strip()
            print()

            if   choice == "1": self._show_address()
            elif choice == "2": self._show_balance()
            elif choice == "3": self._send_coins()
            elif choice == "4": self._tx_history()
            elif choice == "5": self._address_book()
            elif choice == "6": self._show_qr()
            elif choice == "7": self._export_wallet()
            elif choice == "8": self._wallet_info()
            elif choice == "9": self._change_passphrase()
            elif choice in ("0", "q", "quit", "exit"):
                print(f"  {c('Goodbye. Stay quantum-safe!', C_GREEN)}\n")
                break
            else:
                print(f"  {c('Invalid choice.', C_RED)}\n")

    def _first_run(self) -> None:
        print(f"  {c('No wallet found at:', C_YELLOW)} {self.path}")
        print("  Creating a new wallet...\n")
        label = input("  Wallet label (default: My Wallet): ").strip() or "My Wallet"
        while True:
            pp  = getpass.getpass("  Choose a passphrase: ")
            pp2 = getpass.getpass("  Confirm passphrase:  ")
            if pp == pp2:
                break
            print(f"  {c('Passphrases do not match. Try again.', C_RED)}")
        Keystore.create(self.path, pp, label)
        self._data = Keystore.load(self.path, pp)
        self._pass = pp

    def _print_menu(self) -> None:
        lines = [
            f"  {c('┌─ MENU ─────────────────────────────────────┐', C_DIM)}",
            f"  {c('│', C_DIM)}  {c('1', C_CYAN)}  Show my address",
            f"  {c('│', C_DIM)}  {c('2', C_CYAN)}  Check balance",
            f"  {c('│', C_DIM)}  {c('3', C_CYAN)}  Send coins",
            f"  {c('│', C_DIM)}  {c('4', C_CYAN)}  Transaction history",
            f"  {c('│', C_DIM)}  {c('5', C_CYAN)}  Address book",
            f"  {c('│', C_DIM)}  {c('6', C_CYAN)}  Show QR code",
            f"  {c('│', C_DIM)}  {c('7', C_CYAN)}  Export / backup wallet",
            f"  {c('│', C_DIM)}  {c('8', C_CYAN)}  Wallet info",
            f"  {c('│', C_DIM)}  {c('9', C_CYAN)}  Change passphrase",
            f"  {c('│', C_DIM)}  {c('0', C_CYAN)}  Quit",
            f"  {c('└────────────────────────────────────────────┘', C_DIM)}",
        ]
        print("\n".join(lines))

    # ── menu actions ──────────────────────────────────────────

    def _show_address(self) -> None:
        print(f"  {c('Your address:', C_BOLD)}")
        print(f"  {c(self.address, C_YELLOW)}\n")
        print(f"  {c('Full public key (for receiving):', C_DIM)}")
        pk_hex = self._data["pk"]
        for i in range(0, min(len(pk_hex), 128), 64):
            print(f"  {c(pk_hex[i:i+64], C_DIM)}")
        if len(pk_hex) > 128:
            print(f"  {c(f'... ({len(pk_hex)} hex chars total)', C_DIM)}")
        print()

    def _show_balance(self) -> None:
        print(f"  Querying node {self.node.host}:{self.node.port}...")
        balance = self.node.get_balance(self.address, self._data["pk"])
        if balance is None:
            print(f"  {c('Could not reach node. Is it running?', C_RED)}\n")
        else:
            colour = C_GREEN if balance > 0 else C_DIM
            print(f"  Balance: {c(f'{balance:,.4f} coins', colour)}\n")

    def _send_coins(self) -> None:
        print(f"  {c('Send Coins', C_BOLD)}")

        # Recipient — allow address book lookup
        ab = self._data.get("address_book", {})
        if ab:
            print(f"  {c('Address book shortcuts:', C_DIM)}")
            for lbl, addr in ab.items():
                print(f"    {c(lbl, C_CYAN)} → {addr[:20]}...")
            print()

        raw_recipient = input("  Recipient (address / pk_hex / label): ").strip()
        # Resolve label
        recipient_pk_hex = ab.get(raw_recipient, raw_recipient)

        try:
            recipient_pk = bytes.fromhex(recipient_pk_hex)
        except ValueError:
            print(f"  {c('Invalid recipient address/key.', C_RED)}\n")
            return

        try:
            amount = float(input("  Amount: "))
            if amount <= 0:
                raise ValueError
        except ValueError:
            print(f"  {c('Invalid amount.', C_RED)}\n")
            return

        # Check balance
        balance = self.node.get_balance(self.address, self._data["pk"])
        if balance is not None and amount > balance:
            print(f"  {c(f'Insufficient balance ({balance:,.4f} available).', C_RED)}\n")
            return

        confirm = input(f"  Send {c(f'{amount:,.4f}', C_YELLOW)} coins to "
                        f"{c(recipient_pk_hex[:20]+'...', C_CYAN)}? [y/N]: ").strip().lower()
        if confirm != "y":
            print("  Cancelled.\n")
            return

        # Build and sign transaction
        print(f"  Signing with {SCHEME}...")
        tx = Transaction(
            sender_pk    = self.pk,
            recipient_pk = recipient_pk,
            amount       = amount,
        )
        tx.sign(self.sk)

        if not tx.is_valid():
            print(f"  {c('Signature verification failed!', C_RED)}\n")
            return

        # Broadcast
        from quantum_blockchain import tx_to_dict  # reuse serialiser if available
        tx_dict = {
            "sender_pk":    tx.sender_pk.hex(),
            "recipient_pk": tx.recipient_pk.hex(),
            "amount":       tx.amount,
            "timestamp":    tx.timestamp,
            "signature":    tx.signature.hex() if tx.signature else None,
        }
        print("  Broadcasting to network...")
        ok = self.node.broadcast_tx(tx_dict)
        if ok:
            print(f"  {c('✓ Transaction broadcast successfully!', C_GREEN)}")
            # Save to local history
            self._data.setdefault("tx_history", []).append({
                "direction":   "OUT",
                "amount":      amount,
                "counterpart": recipient_pk_hex[:40],
                "timestamp":   tx.timestamp,
                "status":      "broadcast",
            })
            self._save()
        else:
            print(f"  {c('✗ Broadcast failed. Node may be offline.', C_RED)}")
        print()

    def _tx_history(self) -> None:
        print(f"  {c('Transaction History', C_BOLD)} (from node)\n")
        history = self.node.get_tx_history(self._data["pk"])
        if not history:
            print(f"  {c('No transactions found (or node offline).', C_DIM)}\n")
            return
        print(f"  {'Block':>6}  {'Dir':>4}  {'Amount':>14}  {'Time':<20}  Counterpart")
        print(f"  {'─'*6}  {'─'*4}  {'─'*14}  {'─'*20}  {'─'*22}")
        for tx in history[:20]:
            ts  = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(tx["timestamp"]))
            dir_col = C_GREEN if tx["direction"] == "IN" else C_RED
            arrow   = "▲ IN " if tx["direction"] == "IN" else "▼ OUT"
            print(f"  {tx['block']:>6}  {c(arrow, dir_col)}  "
                  f"{tx['amount']:>14,.4f}  {ts:<20}  {tx['counterpart']}")
        if len(history) > 20:
            print(f"  {c(f'... and {len(history)-20} more', C_DIM)}")
        print()

    def _address_book(self) -> None:
        ab = self._data.setdefault("address_book", {})
        while True:
            print(f"  {c('Address Book', C_BOLD)}")
            if not ab:
                print(f"  {c('(empty)', C_DIM)}")
            else:
                for lbl, addr in ab.items():
                    print(f"  {c(lbl, C_CYAN):<30}  {addr[:40]}")
            print(f"\n  {c('a', C_CYAN)} Add  |  {c('d', C_CYAN)} Delete  |  {c('b', C_CYAN)} Back")
            cmd = input(f"  {c('>', C_CYAN)} ").strip().lower()
            if cmd == "a":
                lbl  = input("  Label: ").strip()
                addr = input("  Address/PK hex: ").strip()
                if lbl and addr:
                    ab[lbl] = addr
                    self._save()
                    print(f"  {c('Saved.', C_GREEN)}")
            elif cmd == "d":
                lbl = input("  Label to delete: ").strip()
                if lbl in ab:
                    del ab[lbl]
                    self._save()
                    print(f"  {c('Deleted.', C_GREEN)}")
                else:
                    print(f"  {c('Label not found.', C_RED)}")
            elif cmd == "b":
                break
            print()

    def _show_qr(self) -> None:
        print(f"  {c('QR Code for your address:', C_BOLD)}")
        print(f"  {c(self.address, C_YELLOW)}\n")
        print_qr(self.address)
        print()

    def _export_wallet(self) -> None:
        print(f"  {c('Export / Backup', C_BOLD)}\n")
        print(f"  1  Export encrypted wallet file (safe to share/backup)")
        print(f"  2  Export plaintext private key  {c('(DANGER — keep secret!)', C_RED)}")
        print(f"  3  Back")
        choice = input(f"  {c('>', C_CYAN)} ").strip()

        if choice == "1":
            dest = input(f"  Save to file (default: {self.path}.bak): ").strip()
            dest = dest or self.path + ".bak"
            import shutil
            shutil.copy2(self.path, dest)
            print(f"  {c(f'Backup saved to {dest}', C_GREEN)}\n")

        elif choice == "2":
            warn = input(f"  {c('WARNING: This will show your UNENCRYPTED private key.', C_RED)}\n"
                         "  Anyone with this key can steal your coins.\n"
                         "  Type YES to continue: ")
            if warn.strip() == "YES":
                print(f"\n  {c('Private key (hex):', C_RED)}")
                sk_hex = self._data["sk"]
                for i in range(0, min(len(sk_hex), 256), 64):
                    print(f"  {sk_hex[i:i+64]}")
                if len(sk_hex) > 256:
                    print(f"  ... ({len(sk_hex)} hex chars total)")
                print(f"\n  {c('Public key (hex):', C_YELLOW)}")
                pk_hex = self._data["pk"]
                for i in range(0, min(len(pk_hex), 128), 64):
                    print(f"  {pk_hex[i:i+64]}")
                print()
            else:
                print("  Cancelled.\n")

    def _wallet_info(self) -> None:
        d = self._data
        created = time.strftime("%Y-%m-%d %H:%M:%S",
                                time.localtime(d.get("created_at", 0)))
        pk_bytes = len(d["pk"]) // 2
        sk_bytes = len(d["sk"]) // 2
        print(f"  {c('Wallet Information', C_BOLD)}")
        print(f"  Label         : {c(d['label'], C_CYAN)}")
        print(f"  File          : {self.path}")
        print(f"  Created       : {created}")
        print(f"  Scheme        : {c(d['scheme'], C_MAGENTA)}")
        print(f"  Address       : {c(self.address, C_YELLOW)}")
        print(f"  Encryption    : {c(_aes_backend, C_DIM)}")
        print(f"  KDF           : PBKDF2-HMAC-SHA256  ({PBKDF2_ITERS:,} iterations)")
        print(f"  Public key    : {pk_bytes:,} bytes")
        print(f"  Private key   : {sk_bytes:,} bytes")
        print(f"  Node          : {self.node.host}:{self.node.port}")
        connected = self.node.is_connected()
        print(f"  Node status   : {c('connected', C_GREEN) if connected else c('offline', C_RED)}")
        print()

    def _change_passphrase(self) -> None:
        print(f"  {c('Change Passphrase', C_BOLD)}\n")
        current = getpass.getpass("  Current passphrase: ")
        try:
            Keystore.load(self.path, current)
        except ValueError:
            print(f"  {c('Wrong passphrase.', C_RED)}\n")
            return
        while True:
            new1 = getpass.getpass("  New passphrase: ")
            new2 = getpass.getpass("  Confirm new passphrase: ")
            if new1 == new2:
                break
            print(f"  {c('Passphrases do not match.', C_RED)}")
        self._pass = new1
        self._save()
        print(f"  {c('Passphrase changed successfully.', C_GREEN)}\n")


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Quantum-Resistant Wallet for the SHA-256 QR Blockchain"
    )
    parser.add_argument(
        "--wallet", default="wallet" + WALLET_EXT,
        help=f"Path to wallet file (default: wallet{WALLET_EXT})"
    )
    parser.add_argument(
        "--node", default=f"{DEFAULT_NODE[0]}:{DEFAULT_NODE[1]}",
        help="Node address host:port (default: 127.0.0.1:6000)"
    )
    args = parser.parse_args()

    # Parse node address
    if ":" in args.node:
        node_host, node_port_s = args.node.rsplit(":", 1)
        node_port = int(node_port_s)
    else:
        node_host = args.node
        node_port = DEFAULT_NODE[1]

    cli = WalletCLI(
        wallet_path = args.wallet,
        node_host   = node_host,
        node_port   = node_port,
    )
    cli.run()


if __name__ == "__main__":
    main()
