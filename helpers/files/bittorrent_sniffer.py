#!/usr/bin/env python3
"""
BitTorrent Traffic Analyzer using Scapy
Detects and analyzes DHT, Peer Wire Protocol, and Tracker traffic
"""

from scapy.all import *
import binascii
import struct
import json
from datetime import datetime
from collections import defaultdict


class BitTorrentSniffer:
    def __init__(self):
        self.stats = defaultdict(int)
        self.infohashes = set()
        self.peers = set()
        self.nodes = set()

    def parse_bencode_simple(self, data):
        """Simple bencode parser for basic DHT messages"""
        try:
            # Just extract basic info without full parsing
            result = {}
            if b'1:q' in data:
                # Extract query type
                if b'4:ping' in data:
                    result['query'] = 'ping'
                elif b'9:find_node' in data:
                    result['query'] = 'find_node'
                elif b'9:get_peers' in data:
                    result['query'] = 'get_peers'
                elif b'13:announce_peer' in data:
                    result['query'] = 'announce_peer'

            if b'1:y1:r' in data:
                result['type'] = 'response'
            elif b'1:y1:q' in data:
                result['type'] = 'query'
            elif b'1:y1:e' in data:
                result['type'] = 'error'

            return result
        except:
            return {}

    def analyze_dht_packet(self, packet):
        """Analyze DHT (Distributed Hash Table) traffic"""
        try:
            payload = bytes(packet[UDP].payload)

            # DHT messages are bencoded dictionaries
            if not payload or payload[0] != ord(b'd'):
                return

            src = f"{packet[IP].src}:{packet[UDP].sport}"
            dst = f"{packet[IP].dst}:{packet[UDP].dport}"

            # Parse basic structure
            parsed = self.parse_bencode_simple(payload)

            if parsed:
                msg_type = parsed.get('type', 'unknown')
                query = parsed.get('query', '')

                print(f"\n{'=' * 70}")
                print(f"[DHT {msg_type.upper()}] {datetime.now().strftime('%H:%M:%S.%f')[:-3]}")
                print(f"  Source: {src}")
                print(f"  Destination: {dst}")

                if query:
                    print(f"  Query: {query}")
                    self.stats[f'dht_{query}'] += 1

                # Try to extract node ID
                if b'2:id20:' in payload:
                    idx = payload.find(b'2:id20:')
                    if idx != -1 and len(payload) >= idx + 27:
                        node_id = payload[idx + 7:idx + 27]
                        node_id_hex = binascii.hexlify(node_id).decode()
                        print(f"  Node ID: {node_id_hex}")
                        self.nodes.add(node_id_hex)

                # Try to extract info_hash for get_peers/announce_peer
                if b'9:info_hash20:' in payload:
                    idx = payload.find(b'9:info_hash20:')
                    if idx != -1 and len(payload) >= idx + 34:
                        info_hash = payload[idx + 14:idx + 34]
                        info_hash_hex = binascii.hexlify(info_hash).decode()
                        print(f"  InfoHash: {info_hash_hex}")
                        self.infohashes.add(info_hash_hex)

                # Show raw payload preview
                print(f"  Payload preview: {payload[:100]}")

                self.stats['dht_total'] += 1

        except Exception as e:
            # Silently skip parsing errors
            pass

    def analyze_pwp_packet(self, packet):
        """Analyze Peer Wire Protocol traffic"""
        try:
            if not packet.haslayer(Raw):
                return

            payload = bytes(packet[Raw].load)

            if len(payload) == 0:
                return

            src = f"{packet[IP].src}:{packet[TCP].sport}"
            dst = f"{packet[IP].dst}:{packet[TCP].dport}"

            # Check for BitTorrent handshake
            if len(payload) >= 68 and payload[0] == 19 and payload[1:20] == b"BitTorrent protocol":
                info_hash = binascii.hexlify(payload[28:48]).decode()
                peer_id = payload[48:68]

                print(f"\n{'=' * 70}")
                print(f"[HANDSHAKE] {datetime.now().strftime('%H:%M:%S.%f')[:-3]}")
                print(f"  Source: {src}")
                print(f"  Destination: {dst}")
                print(f"  InfoHash: {info_hash}")
                print(f"  Peer ID: {binascii.hexlify(peer_id).decode()}")

                # Check for extension support
                reserved = payload[20:28]
                if reserved[5] & 0x10:
                    print(f"  Extensions: Supported (DHT, Extension Protocol, etc.)")

                self.infohashes.add(info_hash)
                self.peers.add(f"{packet[IP].src}:{packet[TCP].sport}")
                self.stats['handshakes'] += 1

            # Check for PWP messages (after handshake)
            elif len(payload) >= 5:
                try:
                    msg_length = struct.unpack(">I", payload[:4])[0]

                    if msg_length > 0 and msg_length < 100000 and len(payload) >= 5:
                        msg_id = payload[4]

                        msg_types = {
                            0: "choke",
                            1: "unchoke",
                            2: "interested",
                            3: "not_interested",
                            4: "have",
                            5: "bitfield",
                            6: "request",
                            7: "piece",
                            8: "cancel",
                            9: "port",
                            20: "extended"
                        }

                        if msg_id in msg_types:
                            msg_name = msg_types[msg_id]

                            print(f"\n{'=' * 70}")
                            print(f"[PWP-{msg_name.upper()}] {datetime.now().strftime('%H:%M:%S.%f')[:-3]}")
                            print(f"  Source: {src}")
                            print(f"  Destination: {dst}")
                            print(f"  Message Length: {msg_length} bytes")

                            # Additional info for specific message types
                            if msg_id == 4 and len(payload) >= 9:  # have
                                piece_index = struct.unpack(">I", payload[5:9])[0]
                                print(f"  Piece Index: {piece_index}")

                            elif msg_id == 6 and len(payload) >= 17:  # request
                                index = struct.unpack(">I", payload[5:9])[0]
                                begin = struct.unpack(">I", payload[9:13])[0]
                                length = struct.unpack(">I", payload[13:17])[0]
                                print(f"  Piece: {index}, Offset: {begin}, Length: {length}")

                            elif msg_id == 7 and len(payload) >= 13:  # piece
                                index = struct.unpack(">I", payload[5:9])[0]
                                begin = struct.unpack(">I", payload[9:13])[0]
                                block_size = len(payload) - 13
                                print(f"  Piece: {index}, Offset: {begin}, Block Size: {block_size}")

                            elif msg_id == 20:  # extended
                                if len(payload) >= 6:
                                    ext_msg_id = payload[5]
                                    print(f"  Extended Message ID: {ext_msg_id}")
                                    if ext_msg_id == 0:
                                        print(f"  Type: Extension Handshake")
                                    elif ext_msg_id == 1:
                                        print(f"  Type: Metadata Request/Data")

                            self.stats[f'pwp_{msg_name}'] += 1
                            self.stats['pwp_total'] += 1

                except struct.error:
                    pass

        except Exception as e:
            pass

    def analyze_tracker_packet(self, packet):
        """Analyze HTTP/UDP tracker traffic"""
        try:
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)

                # HTTP tracker detection
                if b'GET /announce' in payload or b'GET /scrape' in payload:
                    src = f"{packet[IP].src}:{packet[TCP].sport}"
                    dst = f"{packet[IP].dst}:{packet[TCP].dport}"

                    print(f"\n{'=' * 70}")
                    print(f"[HTTP TRACKER] {datetime.now().strftime('%H:%M:%S.%f')[:-3]}")
                    print(f"  Source: {src}")
                    print(f"  Destination: {dst}")

                    # Extract info_hash from URL
                    if b'info_hash=' in payload:
                        try:
                            start = payload.find(b'info_hash=') + 10
                            # URL encoded info_hash is 60 chars (20 bytes * 3 for %XX)
                            info_hash_encoded = payload[start:start + 60]
                            print(f"  Request: {payload[:200].decode('utf-8', errors='ignore')}")
                        except:
                            pass

                    self.stats['tracker_http'] += 1

                # Check for UDP tracker protocol
                elif packet.haslayer(UDP) and len(payload) >= 16:
                    # UDP tracker connect request has specific format
                    if len(payload) == 16:
                        try:
                            protocol_id = struct.unpack(">Q", payload[:8])[0]
                            if protocol_id == 0x41727101980:  # Magic constant
                                action = struct.unpack(">I", payload[8:12])[0]

                                actions = {0: "connect", 1: "announce", 2: "scrape", 3: "error"}
                                if action in actions:
                                    print(f"\n{'=' * 70}")
                                    print(f"[UDP TRACKER] {datetime.now().strftime('%H:%M:%S.%f')[:-3]}")
                                    print(f"  Action: {actions[action]}")
                                    self.stats['tracker_udp'] += 1
                        except:
                            pass

        except Exception as e:
            pass

    def analyze_packet(self, packet):
        """Main packet analysis dispatcher"""
        try:
            # Check for DHT traffic (UDP)
            if packet.haslayer(UDP):
                sport = packet[UDP].sport
                dport = packet[UDP].dport

                # DHT commonly uses ports 6881-6889, but can be any port
                # Check if it's bencoded data (starts with 'd')
                if packet.haslayer(Raw):
                    payload = bytes(packet[UDP].payload)
                    if payload and payload[0] == ord(b'd'):
                        self.analyze_dht_packet(packet)
                        return

                # Also check tracker UDP
                self.analyze_tracker_packet(packet)

            # Check for Peer Wire Protocol (TCP)
            if packet.haslayer(TCP):
                self.analyze_pwp_packet(packet)
                self.analyze_tracker_packet(packet)

        except Exception as e:
            # Silently continue on errors
            pass

    def print_statistics(self):
        """Print collected statistics"""
        print(f"\n\n{'=' * 70}")
        print("STATISTICS SUMMARY")
        print(f"{'=' * 70}")
        print(f"Total DHT packets: {self.stats['dht_total']}")
        print(f"  - Ping: {self.stats['dht_ping']}")
        print(f"  - Find Node: {self.stats['dht_find_node']}")
        print(f"  - Get Peers: {self.stats['dht_get_peers']}")
        print(f"  - Announce Peer: {self.stats['dht_announce_peer']}")
        print(f"\nTotal PWP packets: {self.stats['pwp_total']}")
        print(f"  - Handshakes: {self.stats['handshakes']}")
        print(f"  - Interested: {self.stats['pwp_interested']}")
        print(f"  - Piece: {self.stats['pwp_piece']}")
        print(f"  - Request: {self.stats['pwp_request']}")
        print(f"\nTracker requests:")
        print(f"  - HTTP: {self.stats['tracker_http']}")
        print(f"  - UDP: {self.stats['tracker_udp']}")
        print(f"\nUnique InfoHashes discovered: {len(self.infohashes)}")
        print(f"Unique Peers discovered: {len(self.peers)}")
        print(f"Unique DHT Nodes discovered: {len(self.nodes)}")

        if self.infohashes:
            print(f"\nInfoHashes:")
            for ih in list(self.infohashes)[:10]:
                print(f"  {ih}")
            if len(self.infohashes) > 10:
                print(f"  ... and {len(self.infohashes) - 10} more")


def main():
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║           BitTorrent Traffic Analyzer using Scapy                 ║
║                                                                   ║
║  Captures and analyzes:                                          ║
║    • DHT (Distributed Hash Table) traffic                        ║
║    • Peer Wire Protocol (PWP) messages                           ║
║    • HTTP/UDP Tracker communication                              ║
╚═══════════════════════════════════════════════════════════════════╝
""")

    sniffer = BitTorrentSniffer()

    # BPF filter for BitTorrent traffic
    # Common ports: 6881-6889, but traffic can be on any port
    # We'll capture UDP (for DHT) and TCP (for PWP and HTTP trackers)
    bpf_filter = "udp or tcp"

    print("Starting packet capture...")
    print("Filter: Analyzing all UDP and TCP traffic for BitTorrent signatures")
    print("Press Ctrl+C to stop and show statistics\n")

    try:
        sniff(
            filter=bpf_filter,
            prn=sniffer.analyze_packet,
            store=0
        )
    except KeyboardInterrupt:
        print("\n\nStopping capture...")
        sniffer.print_statistics()


if __name__ == "__main__":
    # Check if running as root
    # import os
    #
    # if os.geteuid() != 0:
    #     print("Warning: This script requires root privileges to capture packets.")
    #     print("Please run with: sudo python3 bittorrent_sniffer.py")
    #     exit(1)

    main()
