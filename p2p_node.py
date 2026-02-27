"""
P2P Networking Layer — Quantum-Resistant Blockchain
====================================================
Each node:
  • Listens for inbound TCP connections from peers
  • Connects outbound to known peers
  • Gossips new blocks and transactions to all connected peers
  • Syncs the chain from the longest-chain peer on startup
  • Auto-reconnects to lost peers

Message protocol (newline-delimited JSON over TCP):
  { "type": "HELLO",       "version": 1, "height": N }
  { "type": "GET_PEERS"  }
  { "type": "PEERS",       "peers": [["host", port], ...] }
  { "type": "GET_CHAIN"  }
  { "type": "CHAIN",       "blocks": [...] }
  { "type": "GET_BLOCK",   "index": N }
  { "type": "BLOCK",       "block": {...} }
  { "type": "NEW_BLOCK",   "block": {...} }
  { "type": "NEW_TX",      "tx": {...} }
  { "type": "PING" }
  { "type": "PONG" }

Usage (run each in a separate terminal):

    # Bootstrap / seed node (port 6000)
    python p2p_node.py --port 6000

    # Second node — connects to seed
    python p2p_node.py --port 6001 --peers 127.0.0.1:6000

    # Third node
    python p2p_node.py --port 6002 --peers 127.0.0.1:6000

    # Mine a block on node 6001 (interactive prompt)
    > mine

    # Send a tx from node 6001
    > tx <recipient_address> <amount>

    # Show chain
    > chain

    # Show peers
    > peers

Requirements:
    pip install aiohttp   (optional — only needed for HTTP API)
    The blockchain itself only needs the standard library + quantum_blockchain.py
"""

import asyncio
import json
import logging
import argparse
import time
import sys
import os
import hashlib
from typing import Dict, List, Optional, Set, Tuple, Any

# ── import our blockchain core ────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from quantum_blockchain import (
    Blockchain, Block, Transaction, Wallet,
    ANNUAL_CAP, EPOCH_SECONDS, SCHEME,
    sign_message, verify_signature, generate_keypair,
)

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────

PROTOCOL_VERSION  = 1
MAX_PEERS         = 50
PING_INTERVAL     = 30        # seconds between keepalive pings
RECONNECT_DELAY   = 15        # seconds before retrying a lost peer
SYNC_TIMEOUT      = 60        # seconds to wait for chain sync response
MAX_MESSAGE_BYTES = 64 * 1024 * 1024  # 64 MB max message size

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("p2p")


# ─────────────────────────────────────────────────────────────
# SERIALISATION HELPERS
# ─────────────────────────────────────────────────────────────

def block_to_dict(block: Block) -> Dict[str, Any]:
    return {
        "index":         block.index,
        "previous_hash": block.previous_hash,
        "timestamp":     block.timestamp,
        "difficulty":    block.difficulty,
        "nonce":         block.nonce,
        "hash":          block.hash,
        "transactions":  [tx_to_dict(tx) for tx in block.transactions],
    }

def tx_to_dict(tx: Transaction) -> Dict[str, Any]:
    return {
        "sender_pk":    tx.sender_pk.hex(),
        "recipient_pk": tx.recipient_pk.hex(),
        "amount":       tx.amount,
        "timestamp":    tx.timestamp,
        "signature":    tx.signature.hex() if tx.signature else None,
    }

def dict_to_tx(d: Dict[str, Any]) -> Transaction:
    tx = Transaction(
        sender_pk    = bytes.fromhex(d["sender_pk"]),
        recipient_pk = bytes.fromhex(d["recipient_pk"]),
        amount       = d["amount"],
        timestamp    = d["timestamp"],
    )
    if d.get("signature"):
        tx.signature = bytes.fromhex(d["signature"])
    return tx

def dict_to_block(d: Dict[str, Any], difficulty: int) -> Block:
    txs   = [dict_to_tx(t) for t in d["transactions"]]
    block = Block(
        index         = d["index"],
        transactions  = txs,
        previous_hash = d["previous_hash"],
        difficulty    = d.get("difficulty", difficulty),
        timestamp     = d["timestamp"],
    )
    block.nonce = d["nonce"]
    block.hash  = d["hash"]
    return block


# ─────────────────────────────────────────────────────────────
# PEER CONNECTION
# ─────────────────────────────────────────────────────────────

class PeerConnection:
    """Wraps a single asyncio TCP connection to one peer."""

    def __init__(self, host: str, port: int,
                 reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter,
                 node: "P2PNode"):
        self.host   = host
        self.port   = port
        self.reader = reader
        self.writer = writer
        self.node   = node
        self.addr   = f"{host}:{port}"
        self.alive  = True
        self._send_lock = asyncio.Lock()
        self.log    = logging.getLogger(f"peer[{self.addr}]")

    async def send(self, msg: Dict[str, Any]) -> bool:
        """Send a JSON message terminated by newline."""
        if not self.alive:
            return False
        try:
            async with self._send_lock:
                data = json.dumps(msg).encode() + b"\n"
                self.writer.write(data)
                await self.writer.drain()
            return True
        except Exception as e:
            self.log.warning(f"Send failed: {e}")
            await self.disconnect()
            return False

    async def recv(self) -> Optional[Dict[str, Any]]:
        """Read one newline-terminated JSON message."""
        try:
            line = await asyncio.wait_for(
                self.reader.readline(), timeout=PING_INTERVAL * 2
            )
            if not line:
                return None
            if len(line) > MAX_MESSAGE_BYTES:
                self.log.warning("Oversized message — dropping")
                return None
            return json.loads(line.decode().strip())
        except asyncio.TimeoutError:
            return {"type": "TIMEOUT"}
        except Exception as e:
            self.log.warning(f"Recv error: {e}")
            return None

    async def disconnect(self) -> None:
        if not self.alive:
            return
        self.alive = False
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass
        self.log.info("Disconnected")
        self.node.remove_peer(self)

    async def run(self) -> None:
        """Main read loop for this peer."""
        self.log.info("Connected")
        # Send HELLO
        await self.send({
            "type":    "HELLO",
            "version": PROTOCOL_VERSION,
            "height":  len(self.node.blockchain.chain) - 1,
            "port":    self.node.port,
        })
        # Ask for peer list
        await self.send({"type": "GET_PEERS"})

        while self.alive:
            msg = await self.recv()
            if msg is None:
                break
            await self.node.handle_message(msg, self)

        await self.disconnect()


# ─────────────────────────────────────────────────────────────
# P2P NODE
# ─────────────────────────────────────────────────────────────

class P2PNode:
    """
    Full P2P node.

    Responsibilities:
      - Accept inbound connections
      - Maintain outbound connections to known peers
      - Gossip new blocks and transactions
      - Sync chain from longest peer on startup / fork detection
      - Serve an interactive CLI prompt
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 6000,
                 seed_peers: Optional[List[Tuple[str, int]]] = None,
                 difficulty: int = 3):
        self.host        = host
        self.port        = port
        self.difficulty  = difficulty
        self.blockchain  = Blockchain(difficulty=difficulty)
        self.wallet      = Wallet()
        self.peers: Dict[str, PeerConnection] = {}   # addr → PeerConnection
        self.known_peers: Set[Tuple[str, str]] = set()  # (host, port) known
        self._seed_peers = seed_peers or []
        self._seen_hashes: Set[str] = set()   # dedup gossip
        self._mining    = False
        self.log        = logging.getLogger(f"node:{port}")

        self.log.info(f"Wallet address : {self.wallet.address()}")
        self.log.info(f"Signature scheme: {SCHEME}")

    # ── peer management ───────────────────────────────────────

    def remove_peer(self, peer: PeerConnection) -> None:
        self.peers.pop(peer.addr, None)
        self.log.info(f"Peer removed: {peer.addr}  (connected={len(self.peers)})")

    def peer_count(self) -> int:
        return len(self.peers)

    # ── message handling ──────────────────────────────────────

    async def handle_message(self, msg: Dict[str, Any], peer: PeerConnection) -> None:
        mtype = msg.get("type")

        if mtype == "HELLO":
            their_height = msg.get("height", 0)
            our_height   = len(self.blockchain.chain) - 1
            self.log.info(f"HELLO from {peer.addr}  their_height={their_height}  ours={our_height}")
            if their_height > our_height:
                self.log.info(f"Peer {peer.addr} is ahead — requesting full chain")
                await peer.send({"type": "GET_CHAIN"})
            # Register their listening port
            their_port = msg.get("port")
            if their_port and peer.host:
                self.known_peers.add((peer.host, str(their_port)))

        elif mtype == "GET_PEERS":
            peer_list = [[h, int(p)] for h, p in self.known_peers
                         if f"{h}:{p}" != peer.addr][:MAX_PEERS]
            await peer.send({"type": "PEERS", "peers": peer_list})

        elif mtype == "PEERS":
            for entry in msg.get("peers", []):
                h, p = str(entry[0]), int(entry[1])
                addr = f"{h}:{p}"
                if addr not in self.peers and (h, str(p)) not in self.known_peers:
                    self.known_peers.add((h, str(p)))
                    asyncio.create_task(self._connect_to_peer(h, p))

        elif mtype == "GET_CHAIN":
            chain_data = [block_to_dict(b) for b in self.blockchain.chain]
            await peer.send({"type": "CHAIN", "blocks": chain_data})

        elif mtype == "CHAIN":
            await self._handle_chain(msg.get("blocks", []), peer)

        elif mtype == "GET_BLOCK":
            idx = msg.get("index")
            if idx is not None and 0 <= idx < len(self.blockchain.chain):
                await peer.send({
                    "type":  "BLOCK",
                    "block": block_to_dict(self.blockchain.chain[idx])
                })

        elif mtype in ("BLOCK", "NEW_BLOCK"):
            raw = msg.get("block")
            if raw:
                await self._handle_new_block(raw, peer)

        elif mtype == "NEW_TX":
            raw = msg.get("tx")
            if raw:
                await self._handle_new_tx(raw, peer)

        elif mtype == "PING":
            await peer.send({"type": "PONG"})

        elif mtype in ("PONG", "TIMEOUT"):
            pass  # keepalive handled

        else:
            self.log.debug(f"Unknown message type '{mtype}' from {peer.addr}")

    # ── chain sync ────────────────────────────────────────────

    async def _handle_chain(self, blocks_raw: List[Dict], peer: PeerConnection) -> None:
        if not blocks_raw:
            return
        if len(blocks_raw) <= len(self.blockchain.chain):
            self.log.info(f"Peer {peer.addr} chain not longer than ours — ignoring")
            return

        self.log.info(f"Syncing chain from {peer.addr}  ({len(blocks_raw)} blocks)")
        # Rebuild a candidate blockchain
        candidate = Blockchain(
            difficulty        = self.difficulty,
            genesis_timestamp = self.blockchain.emission.genesis,
        )
        # Replace genesis
        genesis_raw = blocks_raw[0]
        candidate.chain[0].timestamp = genesis_raw["timestamp"]
        candidate.chain[0].hash      = genesis_raw["hash"]

        valid = True
        for raw in blocks_raw[1:]:
            block = dict_to_block(raw, self.difficulty)
            # Validate PoW
            if not block.is_valid_pow():
                self.log.warning(f"Bad PoW in synced block {block.index} from {peer.addr}")
                valid = False
                break
            # Validate transactions
            if not block.transactions_valid():
                self.log.warning(f"Bad tx sig in synced block {block.index}")
                valid = False
                break
            candidate.chain.append(block)
            # Update emission ledger
            reward = block.coinbase_amount()
            candidate.emission.record_mint(block.timestamp, reward)

        if valid and candidate.is_chain_valid():
            self.blockchain = candidate
            self.log.info(f"Chain replaced  height={len(self.blockchain.chain)-1}  "
                          f"supply={self.blockchain.total_supply():,.2f}")
        else:
            self.log.warning(f"Synced chain from {peer.addr} failed validation — rejected")

    async def _handle_new_block(self, raw: Dict, peer: PeerConnection) -> None:
        block_hash = raw.get("hash", "")
        if block_hash in self._seen_hashes:
            return
        self._seen_hashes.add(block_hash)

        block = dict_to_block(raw, self.difficulty)
        our_height = len(self.blockchain.chain) - 1

        if block.index <= our_height:
            return  # already have it or stale fork

        if block.index == our_height + 1:
            # Expected next block — validate and append
            if block.previous_hash != self.blockchain.latest_block.hash:
                self.log.warning(f"Block {block.index} from {peer.addr}: bad prev_hash — requesting full chain")
                await peer.send({"type": "GET_CHAIN"})
                return
            if not block.is_valid_pow():
                self.log.warning(f"Block {block.index} from {peer.addr}: invalid PoW")
                return
            if not block.transactions_valid():
                self.log.warning(f"Block {block.index} from {peer.addr}: invalid tx sig")
                return
            # Emission cap check
            epoch  = self.blockchain.emission.epoch_of(block.timestamp)
            cb     = block.coinbase_amount()
            remain = self.blockchain.emission.remaining_in_epoch(epoch)
            if cb > remain + 1e-9:
                self.log.warning(f"Block {block.index}: coinbase {cb} exceeds epoch cap {remain}")
                return

            self.blockchain.chain.append(block)
            self.blockchain.emission.record_mint(block.timestamp, cb)
            self.log.info(f"✓ New block {block.index}  hash={block.hash[:16]}...  "
                          f"coinbase={cb:.4f}  from={peer.addr}")
            # Relay to other peers
            await self.broadcast({"type": "NEW_BLOCK", "block": raw}, exclude=peer)
        else:
            # We're behind by more than 1 — full sync
            self.log.info(f"Block {block.index} is ahead of us by >1 — requesting full chain")
            await peer.send({"type": "GET_CHAIN"})

    async def _handle_new_tx(self, raw: Dict, peer: PeerConnection) -> None:
        tx_id = hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()
        if tx_id in self._seen_hashes:
            return
        self._seen_hashes.add(tx_id)

        tx = dict_to_tx(raw)
        if self.blockchain.add_transaction(tx):
            await self.broadcast({"type": "NEW_TX", "tx": raw}, exclude=peer)

    # ── broadcasting ──────────────────────────────────────────

    async def broadcast(self, msg: Dict[str, Any],
                        exclude: Optional[PeerConnection] = None) -> None:
        tasks = [
            p.send(msg) for p in list(self.peers.values())
            if p is not exclude and p.alive
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # ── connection management ─────────────────────────────────

    async def _handle_inbound(self, reader: asyncio.StreamReader,
                               writer: asyncio.StreamWriter) -> None:
        addr_info = writer.get_extra_info("peername")
        host      = addr_info[0] if addr_info else "unknown"
        port      = addr_info[1] if addr_info else 0
        addr      = f"{host}:{port}"

        if len(self.peers) >= MAX_PEERS:
            writer.close()
            return

        peer = PeerConnection(host, port, reader, writer, self)
        self.peers[addr] = peer
        self.known_peers.add((host, str(port)))
        self.log.info(f"Inbound connection from {addr}  (total={len(self.peers)})")
        await peer.run()

    async def _connect_to_peer(self, host: str, port: int) -> None:
        addr = f"{host}:{port}"
        if addr in self.peers:
            return
        if f"{self.host}:{self.port}" == addr or f"127.0.0.1:{self.port}" == addr:
            return  # don't connect to self

        while True:
            try:
                self.log.info(f"Connecting to {addr}...")
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=10
                )
                peer = PeerConnection(host, port, reader, writer, self)
                self.peers[addr] = peer
                self.known_peers.add((host, str(port)))
                self.log.info(f"Connected to {addr}  (total={len(self.peers)})")
                await peer.run()
            except asyncio.TimeoutError:
                self.log.warning(f"Timeout connecting to {addr}")
            except ConnectionRefusedError:
                self.log.warning(f"Connection refused: {addr}")
            except Exception as e:
                self.log.warning(f"Error connecting to {addr}: {e}")

            self.log.info(f"Reconnecting to {addr} in {RECONNECT_DELAY}s...")
            await asyncio.sleep(RECONNECT_DELAY)

    # ── keepalive ─────────────────────────────────────────────

    async def _ping_loop(self) -> None:
        while True:
            await asyncio.sleep(PING_INTERVAL)
            await self.broadcast({"type": "PING"})

    # ── mining ────────────────────────────────────────────────

    async def mine_one_block(self) -> Optional[Block]:
        """Mine a single block and broadcast it."""
        if self._mining:
            self.log.warning("Already mining")
            return None
        self._mining = True
        try:
            self.log.info("Starting mining...")
            loop  = asyncio.get_event_loop()
            block = await loop.run_in_executor(
                None,
                lambda: self._mine_sync()
            )
            if block:
                self.log.info(f"⛏ Block mined! index={block.index}  hash={block.hash[:20]}...")
                raw = block_to_dict(block)
                await self.broadcast({"type": "NEW_BLOCK", "block": raw})
            return block
        finally:
            self._mining = False

    def _mine_sync(self) -> Optional[Block]:
        """Blocking mine call (runs in thread executor)."""
        return self.blockchain.mine_pending_transactions(miner_pk=self.wallet.pk)

    # ── interactive CLI ───────────────────────────────────────

    async def _cli_loop(self) -> None:
        print(f"\n{'─'*55}")
        print(f"  Node running on port {self.port}")
        print(f"  Wallet: {self.wallet.address()}")
        print(f"  Commands: mine | tx <addr> <amount> | chain | peers | balance | supply | help | quit")
        print(f"{'─'*55}\n")

        loop = asyncio.get_event_loop()
        while True:
            try:
                raw = await loop.run_in_executor(None, lambda: input(f"[{self.port}]> ").strip())
            except (EOFError, KeyboardInterrupt):
                break

            parts = raw.split()
            if not parts:
                continue
            cmd = parts[0].lower()

            if cmd == "mine":
                asyncio.create_task(self.mine_one_block())

            elif cmd == "tx":
                if len(parts) < 3:
                    print("Usage: tx <recipient_address_hex> <amount>")
                    continue
                try:
                    recipient_pk = bytes.fromhex(parts[1])
                    amount       = float(parts[2])
                    tx           = self.wallet.create_transaction(recipient_pk, amount)
                    if self.blockchain.add_transaction(tx):
                        raw_tx = tx_to_dict(tx)
                        await self.broadcast({"type": "NEW_TX", "tx": raw_tx})
                        print(f"  ✓ Transaction broadcast: {amount} coins")
                    else:
                        print("  ✗ Transaction rejected (check signature/balance)")
                except Exception as e:
                    print(f"  Error: {e}")

            elif cmd == "chain":
                print(f"\n  Chain height : {len(self.blockchain.chain)-1}")
                print(f"  Total supply : {self.blockchain.total_supply():,.4f}")
                for b in self.blockchain.chain[-5:]:
                    print(f"    Block {b.index:>5}  hash={b.hash[:20]}...  "
                          f"txs={len(b.transactions)}  coinbase={b.coinbase_amount():.4f}")
                print()

            elif cmd == "peers":
                print(f"\n  Connected peers ({len(self.peers)}):")
                for addr, p in self.peers.items():
                    print(f"    {addr}  alive={p.alive}")
                print(f"  Known peers   ({len(self.known_peers)}):")
                for h, p in self.known_peers:
                    print(f"    {h}:{p}")
                print()

            elif cmd == "balance":
                bal = self.blockchain.get_balance(self.wallet.pk)
                print(f"\n  Balance: {bal:,.4f} coins  (address={self.wallet.address()})\n")

            elif cmd == "supply":
                print(f"\n{self.blockchain.emission.summary()}\n")

            elif cmd == "help":
                print("""
  mine              — mine the next block (rewards go to your wallet)
  tx <pk_hex> <amt> — broadcast a signed transaction
  chain             — show last 5 blocks
  peers             — show connected & known peers
  balance           — show your wallet balance
  supply            — show emission ledger summary
  quit              — shut down node
""")
            elif cmd in ("quit", "exit", "q"):
                print("Shutting down...")
                sys.exit(0)
            else:
                print(f"  Unknown command '{cmd}' — type 'help'")

    # ── main entry point ──────────────────────────────────────

    async def start(self) -> None:
        # Start TCP server
        server = await asyncio.start_server(
            self._handle_inbound, self.host, self.port
        )
        self.log.info(f"Listening on {self.host}:{self.port}")

        # Connect to seed peers
        for host, port in self._seed_peers:
            self.known_peers.add((host, str(port)))
            asyncio.create_task(self._connect_to_peer(host, port))

        # Start background tasks
        asyncio.create_task(self._ping_loop())

        async with server:
            await asyncio.gather(
                server.serve_forever(),
                self._cli_loop(),
            )


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────

def parse_peers(peer_str: str) -> List[Tuple[str, int]]:
    result = []
    for p in peer_str.split(","):
        p = p.strip()
        if not p:
            continue
        if ":" in p:
            host, port = p.rsplit(":", 1)
            result.append((host.strip(), int(port.strip())))
        else:
            result.append(("127.0.0.1", int(p)))
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Quantum-Resistant Blockchain P2P Node"
    )
    parser.add_argument("--host",       default="0.0.0.0",  help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port",       default=6000, type=int, help="Listen port (default: 6000)")
    parser.add_argument("--peers",      default="",   help="Comma-separated seed peers, e.g. 127.0.0.1:6000,127.0.0.1:6001")
    parser.add_argument("--difficulty", default=3,    type=int, help="PoW difficulty (default: 3)")
    args = parser.parse_args()

    seed_peers = parse_peers(args.peers) if args.peers else []

    node = P2PNode(
        host       = args.host,
        port       = args.port,
        seed_peers = seed_peers,
        difficulty = args.difficulty,
    )

    try:
        asyncio.run(node.start())
    except KeyboardInterrupt:
        print("\nNode stopped.")


if __name__ == "__main__":
    main()
