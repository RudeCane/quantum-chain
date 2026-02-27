# ⛓️ Quantum Chain

> A quantum-resistant, proof-of-work blockchain with post-quantum cryptographic signatures and a capped annual emission model.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Crypto](https://img.shields.io/badge/Signatures-Dilithium2%20%7C%20Lamport--OTS-purple)
![PoW](https://img.shields.io/badge/Consensus-SHA--256%20PoW-orange)

---

## 🔐 Why Quantum-Resistant?

Classical blockchains (Bitcoin, Ethereum) rely on ECDSA signatures, which are vulnerable to Shor's algorithm running on a sufficiently powerful quantum computer. Quantum Chain replaces ECDSA with:

- **CRYSTALS-Dilithium2** — NIST FIPS 204 lattice-based signature scheme (recommended)
- **Lamport One-Time Signatures** — Hash-based fallback requiring no external dependencies

SHA-256 proof-of-work remains quantum-safe; Grover's algorithm only halves its effective security, which is mitigated by difficulty adjustment.

---

## ✨ Features

| Feature | Details |
|---|---|
| **Consensus** | SHA-256 Proof of Work |
| **Signatures** | CRYSTALS-Dilithium2 (NIST PQC) or Lamport-OTS |
| **Supply** | Unlimited total, **20M coin annual cap** |
| **Mining Reward** | 50 coins base, auto-scales near annual cap |
| **Wallet Encryption** | AES-256-GCM with PBKDF2 (600,000 iterations) |
| **Networking** | TCP peer-to-peer gossip protocol |
| **Chain Sync** | Longest-chain rule with 5-step validation |

---

## 📁 Project Structure

```
quantum-chain/
├── quantum_blockchain.py   # Core: blocks, transactions, EmissionLedger
├── p2p_node.py             # P2P networking, gossip protocol, mining CLI
└── wallet.py               # AES-256-GCM encrypted keystore + CLI
```

---

## 🚀 Quick Start

### Prerequisites

```bash
pip install pycryptodome          # AES wallet encryption
pip install dilithium-py          # Dilithium2 signatures (recommended)
pip install qrcode                # Optional: QR code display
```

Python 3.9+ required. Dilithium2 is optional — the node falls back to Lamport-OTS automatically.

### Run a Node

```bash
# Start a node on default port 5000
python p2p_node.py

# Start on a custom port with known peers
python p2p_node.py --port 5001 --peers localhost:5000

# Start with custom mining difficulty
python p2p_node.py --port 5002 --difficulty 4
```

### Node CLI Commands

Once running, type commands in the interactive prompt:

| Command | Description |
|---|---|
| `mine` | Mine a new block and collect the reward |
| `balance <address>` | Check the balance of any address |
| `chain` | Print the full blockchain |
| `peers` | List connected peers |
| `help` | Show all commands |

### Run the Wallet

```bash
python wallet.py
```

On first run, you'll be prompted to create a passphrase-protected keystore. The wallet auto-connects to a local node on port 5000.

### Spin Up a Local Test Network

```bash
# Terminal 1 — Seed node
python p2p_node.py --port 5000

# Terminal 2 — Second node
python p2p_node.py --port 5001 --peers localhost:5000

# Terminal 3 — Start mining on node 2
# (connect with wallet.py or use the interactive CLI)
```

---

## 📦 Architecture

### Block Structure

```
Block
├── index          — Block height
├── timestamp      — Unix epoch
├── transactions[] — List of signed transactions
├── previous_hash  — SHA-256 of prior block
├── nonce          — PoW solution
└── hash           — SHA-256(index + timestamp + txs + prev_hash + nonce)
```

### Transaction Lifecycle

```
Create TX → Sign (Dilithium2/Lamport) → Broadcast to peers
         → Enter mempool → Mined into block → Confirmed
```

### Emission Model

- Each **epoch** is 365 days (wall-clock based)
- At most **20,000,000 coins** can be minted per epoch
- Unused allowance does **not** roll over to the next epoch
- The `EmissionLedger` enforces this at the consensus layer — nodes reject blocks that violate the cap

---

## 🔒 Security Model

| Threat | Mitigation |
|---|---|
| Quantum key forgery | Dilithium2 / Lamport-OTS replace ECDSA |
| 51% attack | SHA-256 PoW; Grover's only halves security |
| Wallet theft | AES-256-GCM + PBKDF2 (600k iterations) |
| Eclipse attack | Multi-peer gossip with up to 50 connections |
| Replay attack | Transaction includes recipient + timestamp |
| Key reuse (Lamport) | OTS design enforced at wallet layer |

---

## 📖 Documentation

Full documentation is available in the [`/docs`](./docs) folder (GitBook format):

- [Getting Started](./docs/getting-started/overview.md)
- [Architecture](./docs/architecture/how-it-works.md)
- [Security Model](./docs/security/threat-model.md)
- [Tokenomics](./docs/tokenomics/supply-model.md)
- [Mining Guide](./docs/mining/overview.md)
- [Wallet Guide](./docs/wallet/overview.md)
- [Network Protocol](./docs/network/protocol.md)
- [API Reference](./docs/api/node-rpc.md)

---

## ⚠️ Disclaimer

This is an **experimental research project** demonstrating post-quantum cryptographic techniques in a blockchain context. It is not audited and should not be used to store real value.

---

## 📄 License

MIT License — see [LICENSE](./LICENSE) for details.
