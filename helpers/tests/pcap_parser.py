"""
BitTorrent PWP Piece Extractor — Scapy Version
===============================================
Replaces all manual Ethernet/IP/TCP parsing with Scapy layer access.
The TCP reassembler and BitTorrent PWP parser remain the same.

Install:
    pip install scapy

Usage:
    # From a PCAP file
    python3 bt_scapy_extractor.py capture.pcap

    # Live capture (requires root)
    sudo python3 bt_scapy_extractor.py --live --iface eth0

    # Live with BPF filter
    sudo python3 bt_scapy_extractor.py --live --iface eth0 --filter "tcp port 6881"
"""

import struct
import hashlib
import argparse
import threading
from queue import Queue, Empty
from collections import defaultdict

# Scapy imports — replaces all manual parse_ethernet / parse_ip / parse_tcp
from scapy.all import (
    rdpcap,          # read PCAP file -> list of packets
    sniff,           # live capture
    IP,              # IPv4 layer
    TCP,             # TCP layer
    Raw,             # raw payload layer
)


# ─────────────────────────────────────────────────────────────────────────────
# TCP Stream Reassembler  (unchanged from stdlib version)
# ─────────────────────────────────────────────────────────────────────────────

class TCPStream:
    """
    Reassembles a unidirectional TCP stream using sequence numbers.
    Buffers out-of-order segments and emits contiguous bytes.
    """
    def __init__(self):
        self.segments = {}    # seq_number -> bytes
        self.next_seq = None  # next expected sequence number
        self.buffer   = b""   # contiguous reassembled data

    def add(self, seq, data):
        if not data:
            return
        if self.next_seq is None:
            self.next_seq = seq
        self.segments[seq] = data
        # flush contiguous segments into buffer
        while self.next_seq in self.segments:
            chunk = self.segments.pop(self.next_seq)
            self.buffer += chunk
            self.next_seq += len(chunk)

    def peek(self, n):
        return self.buffer[:n] if len(self.buffer) >= n else None

    def read(self, n):
        if len(self.buffer) < n:
            return None
        data, self.buffer = self.buffer[:n], self.buffer[n:]
        return data

    def available(self):
        return len(self.buffer)


# ─────────────────────────────────────────────────────────────────────────────
# BitTorrent PWP Parser  (unchanged from stdlib version)
# ─────────────────────────────────────────────────────────────────────────────

BT_HANDSHAKE  = b"\x13BitTorrent protocol"
HANDSHAKE_LEN = 68   # 1 + 19 + 8 + 20 + 20

MSG_NAMES = {
    0: "CHOKE", 1: "UNCHOKE", 2: "INTERESTED", 3: "NOT_INTERESTED",
    4: "HAVE",  5: "BITFIELD", 6: "REQUEST",   7: "PIECE",
    8: "CANCEL", 9: "PORT",
}

class BTFlowParser:
    """
    Parses BitTorrent PWP messages from a reassembled TCP stream.
    Call .feed(seq, data) for every TCP segment belonging to this flow.
    """
    def __init__(self, flow_id):
        self.flow_id        = flow_id   # (src_ip, src_port, dst_ip, dst_port)
        self.stream         = TCPStream()
        self.handshake_done = False
        self.info_hash      = None
        self.peer_id        = None
        self.messages       = []
        self.piece_blocks   = defaultdict(dict)  # idx -> {begin: data}

    # ── public interface ─────────────────────────────────────────────────────

    def feed(self, seq, data):
        """Feed a TCP segment into this flow's stream."""
        self.stream.add(seq, data)
        self._parse()

    def reassemble_pieces(self):
        """
        Attempt to reassemble complete pieces from buffered blocks.
        A piece is complete if blocks are contiguous starting from offset 0.
        Returns {piece_index: bytes}
        """
        result = {}
        for idx, blocks in self.piece_blocks.items():
            begins = sorted(blocks)
            if begins[0] != 0:
                continue           # missing piece start
            data, expected = b"", 0
            ok = True
            for b in begins:
                if b != expected:
                    ok = False
                    break
                data    += blocks[b]
                expected = b + len(blocks[b])
            if ok:
                result[idx] = data
        return result

    # ── internal parsing ─────────────────────────────────────────────────────

    def _parse(self):
        if not self.handshake_done:
            self._try_handshake()
        while self.handshake_done:
            if not self._try_message():
                break

    def _try_handshake(self):
        if self.stream.available() < HANDSHAKE_LEN:
            return
        prefix = self.stream.peek(len(BT_HANDSHAKE))
        if prefix != BT_HANDSHAKE:
            return
        raw = self.stream.read(HANDSHAKE_LEN)
        self.info_hash      = raw[28:48].hex()
        self.peer_id        = raw[48:68]
        self.handshake_done = True
        src_ip, src_port, dst_ip, dst_port = self.flow_id
        print(f"\n[HANDSHAKE] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        print(f"  info_hash : {self.info_hash}")
        print(f"  peer_id   : {self.peer_id!r}")

    def _try_message(self):
        """
        PWP framing: [4-byte big-endian length][1-byte msg_id][payload]
        length=0 is a keepalive (no msg_id follows).
        Returns True if a message was consumed, False if more data needed.
        """
        if self.stream.available() < 4:
            return False

        raw_len  = self.stream.peek(4)
        msg_len  = struct.unpack("!I", raw_len)[0]

        if msg_len == 0:                          # keepalive
            self.stream.read(4)
            self.messages.append({"type": "KEEPALIVE"})
            return True

        if msg_len > 2 * 1024 * 1024:            # sanity guard
            return False

        if self.stream.available() < 4 + msg_len:
            return False                          # wait for more data

        self.stream.read(4)                       # consume length prefix
        msg_data = self.stream.read(msg_len)
        msg_id   = msg_data[0]
        payload  = msg_data[1:]

        msg = {
            "type":   MSG_NAMES.get(msg_id, f"UNKNOWN({msg_id})"),
            "msg_id": msg_id,
            "length": msg_len,
        }

        if msg_id == 4 and len(payload) >= 4:    # HAVE
            msg["piece_index"] = struct.unpack("!I", payload[:4])[0]

        elif msg_id == 5:                        # BITFIELD
            msg["pieces_have"] = sum(bin(b).count("1") for b in payload)

        elif msg_id == 6 and len(payload) >= 12: # REQUEST
            msg["piece_index"], msg["begin"], msg["block_length"] = \
                struct.unpack("!III", payload[:12])

        elif msg_id == 7 and len(payload) >= 8:  # PIECE  ← what we want
            idx   = struct.unpack("!I", payload[0:4])[0]
            begin = struct.unpack("!I", payload[4:8])[0]
            data  = payload[8:]
            msg.update({"piece_index": idx, "begin": begin,
                        "block_length": len(data),
                        "block_sha1": hashlib.sha1(data).hexdigest()})
            self.piece_blocks[idx][begin] = data  # buffer for reassembly

        elif msg_id == 8 and len(payload) >= 12: # CANCEL
            msg["piece_index"], msg["begin"], msg["block_length"] = \
                struct.unpack("!III", payload[:12])

        self.messages.append(msg)
        return True


# ─────────────────────────────────────────────────────────────────────────────
# ★  Scapy packet handler  ★
#    This replaces ALL of: parse_pcap / parse_ethernet / parse_ip / parse_tcp
# ─────────────────────────────────────────────────────────────────────────────

# Global flow table — shared between PCAP and live modes
flows: dict[tuple, BTFlowParser] = {}


def handle_packet(pkt):
    """
    Called once per packet by Scapy (both rdpcap iteration and sniff callback).

    Scapy gives us pre-parsed layers — no manual struct unpacking needed.
    We just check which layers are present and read their fields directly.
    """

    # ── 1. Filter: only IPv4 TCP packets with a payload ───────────────────
    #
    #   Previously:  parse_ethernet() -> check ethertype
    #                parse_ip()       -> check version, protocol
    #                parse_tcp()      -> check data offset
    #
    #   With Scapy:  just check layer presence
    #
    if not (IP in pkt and TCP in pkt):
        return

    # ── 2. Extract fields — Scapy parses headers automatically ───────────
    #
    #   Previously:  struct.unpack("!HH", payload[0:4])  for ports
    #                struct.unpack("!I",  payload[4:8])  for seq
    #                payload[data_offset:]               for TCP payload
    #
    #   With Scapy:  attribute access on the layer object
    #
    src_ip   = pkt[IP].src        # e.g. "192.168.1.5"
    dst_ip   = pkt[IP].dst        # e.g. "82.163.151.223"
    src_port = pkt[TCP].sport     # int
    dst_port = pkt[TCP].dport     # int
    seq      = pkt[TCP].seq       # 32-bit sequence number

    # ── 3. Get TCP payload ────────────────────────────────────────────────
    #
    #   Scapy represents the TCP payload as a Raw layer (or nothing).
    #   bytes() on a layer gives its raw bytes including all sub-layers.
    #
    if not pkt[TCP].payload:
        return                    # no application data, skip (ACKs etc.)

    payload = bytes(pkt[TCP].payload)

    # ── 4. Route into per-flow BT parser ─────────────────────────────────
    #
    #   Flow key is the 4-tuple identifying one direction of a TCP connection.
    #   Each direction is tracked separately (same as before).
    #
    flow_id = (src_ip, src_port, dst_ip, dst_port)

    if flow_id not in flows:
        flows[flow_id] = BTFlowParser(flow_id)

    flows[flow_id].feed(seq, payload)


# ─────────────────────────────────────────────────────────────────────────────
# PCAP file mode
# ─────────────────────────────────────────────────────────────────────────────

def process_pcap(path):
    """
    Read all packets from a PCAP file and process them.

    rdpcap() returns a PacketList — we iterate and call handle_packet()
    for each one, exactly like the sniff() callback does for live capture.
    This means the same handle_packet() function works for both modes.
    """
    print(f"[*] Reading {path} ...")
    packets = rdpcap(path)               # Scapy parses every packet upfront
    print(f"[*] {len(packets)} packets loaded")

    for pkt in packets:
        handle_packet(pkt)               # same handler as live mode


# ─────────────────────────────────────────────────────────────────────────────
# Live capture mode
# ─────────────────────────────────────────────────────────────────────────────

def process_live(iface, bpf_filter, timeout=None):
    """
    Capture packets live off a network interface.

    Key differences vs PCAP mode:
      - Packets arrive one at a time asynchronously
      - We use a Queue to decouple capture (fast) from parsing (slower)
      - sniff() blocks until timeout or KeyboardInterrupt
      - Flows may start mid-session (handshake already happened = missed)
    """
    packet_queue = Queue(maxsize=50_000)

    def _enqueue(pkt):
        """Fast callback — just enqueue, never block the capture thread."""
        try:
            packet_queue.put_nowait(pkt)
        except Exception:
            pass   # drop if queue full rather than stalling capture

    def _capture_thread():
        print(f"[*] Capturing on {iface}  filter='{bpf_filter}'  (Ctrl+C to stop)")
        sniff(
            iface=iface,
            filter=bpf_filter,
            prn=_enqueue,          # callback per packet
            store=False,           # don't accumulate in memory
            timeout=timeout,
        )
        packet_queue.put(None)     # sentinel: capture finished

    def _processing_thread():
        while True:
            try:
                pkt = packet_queue.get(timeout=1)
                if pkt is None:    # sentinel
                    break
                handle_packet(pkt)
            except Empty:
                continue
            except KeyboardInterrupt:
                break

    t_cap  = threading.Thread(target=_capture_thread,  daemon=True)
    t_proc = threading.Thread(target=_processing_thread)
    t_cap.start()
    t_proc.start()
    t_proc.join()


# ─────────────────────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────────────────────

def print_report():
    bt_flows = {fid: fp for fid, fp in flows.items() if fp.handshake_done}

    print(f"\n{'='*65}")
    print(f"SUMMARY")
    print(f"{'='*65}")
    print(f"Total TCP flows : {len(flows)}")
    print(f"BT flows found  : {len(bt_flows)}")

    if not bt_flows:
        print("\n[!] No BT handshakes detected.")
        print("    Possible causes: encrypted traffic (MSE/PE), mid-session capture.")
        return

    all_piece_msgs = []

    for flow_id, parser in bt_flows.items():
        src_ip, src_port, dst_ip, dst_port = flow_id
        piece_msgs   = [m for m in parser.messages if m.get("msg_id") == 7]
        request_msgs = [m for m in parser.messages if m.get("msg_id") == 6]
        have_msgs    = [m for m in parser.messages if m.get("msg_id") == 4]
        bf_msgs      = [m for m in parser.messages if m.get("msg_id") == 5]

        print(f"\n{'─'*65}")
        print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        print(f"  info_hash : {parser.info_hash}")
        print(f"  peer_id   : {parser.peer_id!r}")
        print(f"  BITFIELD  : {len(bf_msgs)}"
              + (f"  ({bf_msgs[0]['pieces_have']} pieces at connect)" if bf_msgs else ""))
        print(f"  HAVE      : {len(have_msgs)}")
        print(f"  REQUEST   : {len(request_msgs)}")
        print(f"  PIECE     : {len(piece_msgs)}")

        if not piece_msgs:
            continue

        indices      = sorted(set(m["piece_index"] for m in piece_msgs))
        total_bytes  = sum(m["block_length"] for m in piece_msgs)
        print(f"\n  Piece indices : {indices}")
        print(f"  Total data    : {total_bytes:,} bytes ({total_bytes/1024:.1f} KB)")

        print(f"\n  {'Piece':>6}  {'Blocks':>6}  {'Bytes':>10}  Begins")
        print(f"  {'─'*6}  {'─'*6}  {'─'*10}  {'─'*30}")
        for idx in indices:
            blks   = [m for m in piece_msgs if m["piece_index"] == idx]
            begins = sorted(m["begin"] for m in blks)
            nbytes = sum(m["block_length"] for m in blks)
            print(f"  {idx:>6}  {len(blks):>6}  {nbytes:>10,}  {begins[:6]}"
                  f"{'...' if len(begins) > 6 else ''}")

        reassembled = parser.reassemble_pieces()
        if reassembled:
            print(f"\n  Reassembled pieces:")
            for idx, data in reassembled.items():
                sha1 = hashlib.sha1(data).hexdigest()
                print(f"    Piece {idx:>5}: {len(data):>8,} bytes | SHA1: {sha1}")
        else:
            print(f"\n  [!] No fully reassembled pieces (partial capture)")

        all_piece_msgs.extend(piece_msgs)

    print(f"\n{'='*65}")
    print(f"Total PIECE messages: {len(all_piece_msgs)}")
    print(f"{'='*65}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="BitTorrent PWP extractor using Scapy"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("pcap", nargs="?",         help="Path to .pcap file")
    group.add_argument("--live", action="store_true", help="Live capture mode")

    parser.add_argument("--iface",  default="eth0",  help="Interface for live capture")
    parser.add_argument("--filter", default="tcp",   help="BPF filter for live capture")
    parser.add_argument("--timeout", type=int,       help="Live capture timeout (seconds)")
    args = parser.parse_args()

    if args.live:
        process_live(args.iface, args.filter, args.timeout)
    else:
        process_pcap(args.pcap)

    print_report()