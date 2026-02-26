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
