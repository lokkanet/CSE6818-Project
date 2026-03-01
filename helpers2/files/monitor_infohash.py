#!/usr/bin/env python3
"""
Monitor Specific InfoHash
Track all traffic related to a specific torrent infohash
"""

from scapy.all import *
import binascii
from datetime import datetime


class InfoHashMonitor:
    def __init__(self, target_infohash):
        self.target_infohash = target_infohash.lower()
        self.peers_found = set()
        self.dht_nodes = set()
        self.handshakes = []
        self.stats = {
            'dht_queries': 0,
            'handshakes': 0,
            'piece_transfers': 0,
            'requests': 0
        }

    def check_packet(self, packet):
        """Check if packet contains our target infohash"""

        # Check DHT traffic
        if packet.haslayer(UDP):
            try:
                payload = bytes(packet[UDP].payload)

                if b'9:info_hash20:' in payload:
                    idx = payload.find(b'9:info_hash20:')
                    if idx != -1 and len(payload) >= idx + 34:
                        info_hash = binascii.hexlify(payload[idx + 14:idx + 34]).decode()

                        if info_hash.lower() == self.target_infohash:
                            self.found_in_dht(packet, info_hash)
            except:
                pass

        # Check PWP handshakes
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            try:
                payload = bytes(packet[Raw].load)

                if len(payload) >= 68 and payload[0] == 19 and payload[1:20] == b"BitTorrent protocol":
                    info_hash = binascii.hexlify(payload[28:48]).decode()

                    if info_hash.lower() == self.target_infohash:
                        self.found_in_handshake(packet, info_hash)

                # Check for piece transfers
                elif len(payload) >= 5:
                    msg_length = struct.unpack(">I", payload[:4])[0]
                    if 0 < msg_length < 100000 and len(payload) >= 5:
                        msg_id = payload[4]

                        # Message ID 7 = piece
                        if msg_id == 7:
                            self.stats['piece_transfers'] += 1

                        # Message ID 6 = request
                        elif msg_id == 6:
                            self.stats['requests'] += 1

            except:
                pass

    def found_in_dht(self, packet, info_hash):
        """Handle DHT packet containing our infohash"""
        src = f"{packet[IP].src}:{packet[UDP].sport}"
        dst = f"{packet[IP].dst}:{packet[UDP].dport}"

        self.stats['dht_queries'] += 1

        print(f"\n{'=' * 70}")
        print(f"[DHT] Found target infohash! {datetime.now().strftime('%H:%M:%S')}")
        print(f"  InfoHash: {info_hash}")
        print(f"  From: {src}")
        print(f"  To: {dst}")

        # Try to determine query type
        payload = bytes(packet[UDP].payload)
        if b'1:q9:get_peers' in payload:
            print(f"  Query Type: get_peers")
        elif b'1:q13:announce_peer' in payload:
            print(f"  Query Type: announce_peer")
            self.peers_found.add(src)

        self.dht_nodes.add(src)
        self.dht_nodes.add(dst)

    def found_in_handshake(self, packet, info_hash):
        """Handle handshake containing our infohash"""
        src = f"{packet[IP].src}:{packet[TCP].sport}"
        dst = f"{packet[IP].dst}:{packet[TCP].dport}"

        payload = bytes(packet[Raw].load)
        peer_id = binascii.hexlify(payload[48:68]).decode()

        self.stats['handshakes'] += 1
        self.handshakes.append({
            'time': datetime.now(),
            'src': src,
            'dst': dst,
            'peer_id': peer_id
        })

        print(f"\n{'=' * 70}")
        print(f"[HANDSHAKE] Peer connecting for target torrent!")
        print(f"  InfoHash: {info_hash}")
        print(f"  From: {src}")
        print(f"  To: {dst}")
        print(f"  Peer ID: {peer_id}")

        self.peers_found.add(src)
        self.peers_found.add(dst)

    def print_stats(self):
        """Print statistics"""
        print(f"\n\n{'=' * 70}")
        print(f"MONITORING SUMMARY FOR: {self.target_infohash}")
        print(f"{'=' * 70}")
        print(f"DHT Queries: {self.stats['dht_queries']}")
        print(f"Handshakes: {self.stats['handshakes']}")
        print(f"Piece Requests: {self.stats['requests']}")
        print(f"Piece Transfers: {self.stats['piece_transfers']}")
        print(f"\nUnique Peers Found: {len(self.peers_found)}")
        print(f"Unique DHT Nodes: {len(self.dht_nodes)}")

        if self.peers_found:
            print(f"\nPeers discovered:")
            for peer in sorted(self.peers_found)[:20]:
                print(f"  {peer}")
            if len(self.peers_found) > 20:
                print(f"  ... and {len(self.peers_found) - 20} more")

        if self.handshakes:
            print(f"\nRecent handshakes:")
            for hs in self.handshakes[-10:]:
                print(f"  {hs['time'].strftime('%H:%M:%S')} - {hs['src']} -> {hs['dst']}")


def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: sudo python3 monitor_infohash.py <infohash>")
        print("\nExample:")
        print("  sudo python3 monitor_infohash.py cb91abca6f8d6b34ff8d69540c7dc195e4fb3233")
        sys.exit(1)

    target_infohash = sys.argv[1].strip()

    # Validate infohash
    if len(target_infohash) != 40:
        print(f"Error: Invalid infohash length ({len(target_infohash)}). Should be 40 hex characters.")
        sys.exit(1)

    try:
        int(target_infohash, 16)
    except ValueError:
        print("Error: InfoHash must be hexadecimal")
        sys.exit(1)

    print(f"""
╔═══════════════════════════════════════════════════════════════════╗
║              InfoHash Monitor - Scapy Edition                     ║
╚═══════════════════════════════════════════════════════════════════╝

Monitoring for InfoHash: {target_infohash}

This will capture all BitTorrent traffic and filter for your specific torrent.
Press Ctrl+C to stop and show statistics.

""")

    monitor = InfoHashMonitor(target_infohash)

    try:
        sniff(
            filter="udp or tcp",
            prn=monitor.check_packet,
            store=0
        )
    except KeyboardInterrupt:
        print("\n\nStopping monitor...")
        monitor.print_stats()


if __name__ == "__main__":
    import os

    if os.geteuid() != 0:
        print("Error: This script requires root privileges.")
        print("Please run with: sudo python3 monitor_infohash.py <infohash>")
        exit(1)

    main()
