#!/usr/bin/env python3
"""
Complete BitTorrent Traffic Analyzer - DHT, Trackers, and PEX
Catches all three peer discovery mechanisms
"""

from scapy.all import *
import binascii
import struct
from datetime import datetime
from collections import defaultdict


class CompleteBitTorrentAnalyzer:
    def __init__(self):
        self.stats = defaultdict(int)
        self.infohashes = set()
        self.peers = defaultdict(set)

    def analyze_packet(self, packet):
        """Main packet analysis dispatcher"""
        try:
            # Check for DHT (UDP)
            if packet.haslayer(UDP):
                self.analyze_dht(packet)
                self.analyze_tracker_udp(packet)

            # Check for Trackers and PEX (TCP)
            if packet.haslayer(TCP):
                self.analyze_tracker_http(packet)
                self.analyze_pex(packet)

        except Exception as e:
            pass

    def analyze_dht(self, packet):
        """Analyze DHT (Distributed Hash Table) traffic"""
        try:
            payload = bytes(packet[UDP].payload)

            # DHT messages are bencoded and start with 'd'
            # checks if its a dht msg
            if not payload or payload[0] != ord(b'd'):
                return

            src = f"{packet[IP].src}:{packet[UDP].sport}"
            dst = f"{packet[IP].dst}:{packet[UDP].dport}"

            dt = datetime.fromtimestamp(packet.time)
            time_str = dt.strftime('%H:%M:%S.%f')[:-3]

            print(f"\n{'=' * 70}")
            print(f"[DHT] {time_str}")
            print(f"  Source: {src}")
            print(f"  Destination: {dst}")

            # Determine message type
            if b'1:q4:ping' in payload:
                print(f"  Type: Ping Query")
                self.stats['dht_ping'] += 1
            elif b'1:q9:find_node' in payload:
                print(f"  Type: Find Node Query")
                self.stats['dht_find_node'] += 1
            elif b'1:q9:get_peers' in payload:
                print(f"  Type: Get Peers Query")
                self.stats['dht_get_peers'] += 1
            elif b'1:q13:announce_peer' in payload:
                print(f"  Type: Announce Peer Query")
                self.stats['dht_announce_peer'] += 1
            elif b'1:y1:r' in payload:
                print(f"  Type: Response")
                self.stats['dht_response'] += 1

            # Extract info_hash if present
            if b'9:info_hash20:' in payload:
                idx = payload.find(b'9:info_hash20:')
                if idx != -1 and len(payload) >= idx + 34:
                    info_hash = binascii.hexlify(payload[idx + 14:idx + 34]).decode()
                    print(f"  InfoHash: {info_hash}")
                    self.infohashes.add(info_hash)

            self.stats['dht_total'] += 1

        except Exception as e:
            pass

    def analyze_tracker_udp(self, packet):
        """Analyze UDP Tracker Protocol (BEP 15)"""
        try:
            payload = bytes(packet[UDP].payload)

            if len(payload) < 16:
                return

            # UDP tracker uses specific magic constant
            # Connect request: protocol_id = 0x41727101980
            if len(payload) == 16:
                try:
                    protocol_id = struct.unpack(">Q", payload[0:8])[0]

                    # Magic constant for UDP tracker
                    if protocol_id == 0x41727101980:
                        action = struct.unpack(">I", payload[8:12])[0]
                        transaction_id = struct.unpack(">I", payload[12:16])[0]

                        src = f"{packet[IP].src}:{packet[UDP].sport}"
                        dst = f"{packet[IP].dst}:{packet[UDP].dport}"

                        dt = datetime.fromtimestamp(packet.time)
                        time_str = dt.strftime('%H:%M:%S.%f')[:-3]

                        action_types = {0: "connect", 1: "announce", 2: "scrape", 3: "error"}
                        action_name = action_types.get(action, f"unknown ({action})")

                        print(f"\n{'=' * 70}")
                        print(f"[UDP TRACKER] {time_str}")
                        print(f"  Source: {src}")
                        print(f"  Destination: {dst}")
                        print(f"  Action: {action_name}")
                        print(f"  Transaction ID: {transaction_id}")

                        self.stats[f'tracker_udp_{action_name}'] += 1
                        self.stats['tracker_udp_total'] += 1

                except struct.error:
                    pass

            # Announce request (longer message)
            elif len(payload) >= 98:
                try:
                    # Try to parse as announce
                    protocol_id = struct.unpack(">Q", payload[0:8])[0]

                    if protocol_id == 0x41727101980:
                        action = struct.unpack(">I", payload[8:12])[0]

                        if action == 1:  # Announce
                            info_hash = binascii.hexlify(payload[16:36]).decode()

                            src = f"{packet[IP].src}:{packet[UDP].sport}"
                            dst = f"{packet[IP].dst}:{packet[UDP].dport}"

                            dt = datetime.fromtimestamp(packet.time)
                            time_str = dt.strftime('%H:%M:%S.%f')[:-3]

                            print(f"\n{'=' * 70}")
                            print(f"[UDP TRACKER ANNOUNCE] {time_str}")
                            print(f"  Source: {src}")
                            print(f"  Destination: {dst}")
                            print(f"  InfoHash: {info_hash}")

                            self.infohashes.add(info_hash)
                            self.stats['tracker_udp_announce'] += 1

                except struct.error:
                    pass

        except Exception as e:
            pass

    def analyze_tracker_http(self, packet):
        """Analyze HTTP Tracker requests"""
        try:
            if not packet.haslayer(Raw):
                return

            payload = bytes(packet[Raw].load)

            # Check for HTTP tracker requests
            if b'GET /announce' in payload or b'GET /scrape' in payload:
                src = f"{packet[IP].src}:{packet[TCP].sport}"
                dst = f"{packet[IP].dst}:{packet[TCP].dport}"

                dt = datetime.fromtimestamp(packet.time)
                time_str = dt.strftime('%H:%M:%S.%f')[:-3]

                print(f"\n{'=' * 70}")
                print(f"[HTTP TRACKER] {time_str}")
                print(f"  Source: {src}")
                print(f"  Destination: {dst}")

                # Determine type
                if b'GET /announce' in payload:
                    print(f"  Type: Announce")
                    self.stats['tracker_http_announce'] += 1
                elif b'GET /scrape' in payload:
                    print(f"  Type: Scrape")
                    self.stats['tracker_http_scrape'] += 1

                # Try to extract info_hash from URL
                if b'info_hash=' in payload:
                    try:
                        # Find info_hash in the request
                        idx = payload.find(b'info_hash=')
                        # URL-encoded infohash is typically 60 chars (20 bytes * 3 for %XX)
                        # This is simplified - real parsing would decode URL encoding
                        print(f"  Contains info_hash parameter")
                    except:
                        pass

                # Extract tracker URL/host
                if b'Host: ' in payload:
                    host_start = payload.find(b'Host: ') + 6
                    host_end = payload.find(b'\r\n', host_start)
                    if host_end != -1:
                        host = payload[host_start:host_end].decode('utf-8', errors='ignore')
                        print(f"  Tracker: {host}")

                self.stats['tracker_http_total'] += 1

        except Exception as e:
            pass

    def analyze_pex(self, packet):
        """Analyze PEX (Peer Exchange) - Extended Protocol"""
        try:
            if not packet.haslayer(Raw):
                return

            payload = bytes(packet[Raw].load)

            if len(payload) < 5:
                return

            # Check for extended protocol messages
            # Message format: <length><message_id><extended_message_id><payload>
            try:
                msg_length = struct.unpack(">I", payload[0:4])[0]

                if msg_length > 0 and msg_length < 100000 and len(payload) >= 5:
                    msg_id = payload[4]

                    # Message ID 20 = Extended protocol
                    if msg_id == 20 and len(payload) >= 6:
                        ext_msg_id = payload[5]

                        src = f"{packet[IP].src}:{packet[TCP].sport}"
                        dst = f"{packet[IP].dst}:{packet[TCP].dport}"

                        dt = datetime.fromtimestamp(packet.time)
                        time_str = dt.strftime('%H:%M:%S.%f')[:-3]

                        # Extended message ID 0 = Handshake
                        # Extended message ID 1 = ut_pex (Peer Exchange)
                        # Extended message ID 2 = ut_metadata

                        if ext_msg_id == 0:
                            print(f"\n{'=' * 70}")
                            print(f"[EXTENDED HANDSHAKE] {time_str}")
                            print(f"  Source: {src}")
                            print(f"  Destination: {dst}")
                            print(f"  Type: Extension Protocol Handshake")

                            # Try to parse the bencoded dictionary
                            ext_payload = payload[6:]
                            if ext_payload and ext_payload[0] == ord(b'd'):
                                # Check for ut_pex support
                                if b'ut_pex' in ext_payload:
                                    print(f"  Supports: PEX (Peer Exchange)")
                                if b'ut_metadata' in ext_payload:
                                    print(f"  Supports: Metadata Exchange")

                            self.stats['extended_handshake'] += 1

                        elif ext_msg_id == 1:
                            print(f"\n{'=' * 70}")
                            print(f"[PEX - PEER EXCHANGE] {time_str}")
                            print(f"  Source: {src}")
                            print(f"  Destination: {dst}")
                            print(f"  Type: ut_pex (Peer Exchange)")

                            # PEX payload is bencoded
                            ext_payload = payload[6:]

                            # Try to count peers
                            # PEX sends peer lists in 'added' and 'added.f' fields
                            if b'5:added' in ext_payload:
                                # Find the peer list
                                # Format: 5:added<length>:<compact_peer_list>
                                # Each peer is 6 bytes (4 bytes IP + 2 bytes port)
                                try:
                                    added_idx = ext_payload.find(b'5:added')
                                    # This is simplified - proper bencode parsing needed
                                    print(f"  Peers being exchanged: (peer list present)")
                                except:
                                    pass

                            self.stats['pex_message'] += 1
                            self.stats['pex_total'] += 1

                        elif ext_msg_id == 2:
                            print(f"\n{'=' * 70}")
                            print(f"[METADATA EXCHANGE] {time_str}")
                            print(f"  Source: {src}")
                            print(f"  Destination: {dst}")
                            print(f"  Type: ut_metadata (Metadata Exchange)")

                            self.stats['metadata_exchange'] += 1

            except struct.error:
                pass

        except Exception as e:
            pass

    def print_statistics(self):
        """Print collected statistics"""
        print(f"\n\n{'=' * 70}")
        print("COMPLETE BITTORRENT TRAFFIC ANALYSIS")
        print(f"{'=' * 70}")

        # DHT Statistics
        print(f"\n1. DHT (Distributed Hash Table)")
        print(f"   {'-' * 66}")
        print(f"   Total DHT packets: {self.stats['dht_total']}")
        print(f"     - Ping: {self.stats['dht_ping']}")
        print(f"     - Find Node: {self.stats['dht_find_node']}")
        print(f"     - Get Peers: {self.stats['dht_get_peers']}")
        print(f"     - Announce Peer: {self.stats['dht_announce_peer']}")
        print(f"     - Responses: {self.stats['dht_response']}")

        # HTTP Tracker Statistics
        print(f"\n2. HTTP Trackers (Centralized)")
        print(f"   {'-' * 66}")
        print(f"   Total HTTP tracker requests: {self.stats['tracker_http_total']}")
        print(f"     - Announce: {self.stats['tracker_http_announce']}")
        print(f"     - Scrape: {self.stats['tracker_http_scrape']}")

        # UDP Tracker Statistics
        print(f"\n3. UDP Trackers (Centralized)")
        print(f"   {'-' * 66}")
        print(f"   Total UDP tracker packets: {self.stats['tracker_udp_total']}")
        print(f"     - Connect: {self.stats['tracker_udp_connect']}")
        print(f"     - Announce: {self.stats['tracker_udp_announce']}")
        print(f"     - Scrape: {self.stats['tracker_udp_scrape']}")

        # PEX Statistics
        print(f"\n4. PEX (Peer Exchange)")
        print(f"   {'-' * 66}")
        print(f"   Total PEX messages: {self.stats['pex_total']}")
        print(f"   Extended handshakes: {self.stats['extended_handshake']}")
        print(f"   Metadata exchanges: {self.stats['metadata_exchange']}")

        # Summary
        print(f"\n5. Summary")
        print(f"   {'-' * 66}")
        print(f"   Unique InfoHashes: {len(self.infohashes)}")

        # Coverage check
        print(f"\n6. Detection Coverage")
        print(f"   {'-' * 66}")
        has_dht = self.stats['dht_total'] > 0
        has_http_tracker = self.stats['tracker_http_total'] > 0
        has_udp_tracker = self.stats['tracker_udp_total'] > 0
        has_pex = self.stats['pex_total'] > 0

        print(f"   ✓ DHT:          {'DETECTED' if has_dht else 'NOT DETECTED'}")
        print(f"   ✓ HTTP Tracker: {'DETECTED' if has_http_tracker else 'NOT DETECTED'}")
        print(f"   ✓ UDP Tracker:  {'DETECTED' if has_udp_tracker else 'NOT DETECTED'}")
        print(f"   ✓ PEX:          {'DETECTED' if has_pex else 'NOT DETECTED'}")

        if self.infohashes:
            print(f"\n   InfoHashes discovered:")
            for ih in list(self.infohashes)[:10]:
                print(f"     {ih}")
            if len(self.infohashes) > 10:
                print(f"     ... and {len(self.infohashes) - 10} more")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Complete BitTorrent Traffic Analyzer - DHT, Trackers, and PEX',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This tool detects ALL THREE peer discovery mechanisms:
  1. DHT (Distributed Hash Table) - Decentralized
  2. Trackers (HTTP and UDP) - Centralized
  3. PEX (Peer Exchange) - Peer-to-peer via extension protocol

Examples:
  # Live capture
  sudo python3 complete_bt_analyzer.py -i eth0

  # Analyze PCAP file
  python3 complete_bt_analyzer.py -r capture.pcap

  # Limit packets
  sudo python3 complete_bt_analyzer.py -i eth0 -c 100
        """
    )

    parser.add_argument('-i', '--interface',
                        help='Network interface for live capture')

    parser.add_argument('-r', '--read',
                        help='Read from PCAP file')

    parser.add_argument('-c', '--count',
                        type=int,
                        default=0,
                        help='Number of packets to capture (0 = unlimited)')

    args = parser.parse_args()

    if not args.interface and not args.read:
        print("Error: Must specify either -i (interface) or -r (read file)")
        parser.print_help()
        import sys
        sys.exit(1)

    print("""
╔═══════════════════════════════════════════════════════════════════╗
║      Complete BitTorrent Traffic Analyzer                        ║
║                                                                   ║
║  Detects:                                                        ║
║    ✓ DHT (Distributed Hash Table)                               ║
║    ✓ HTTP Trackers                                              ║
║    ✓ UDP Trackers                                               ║
║    ✓ PEX (Peer Exchange)                                        ║
╚═══════════════════════════════════════════════════════════════════╝
""")

    analyzer = CompleteBitTorrentAnalyzer()

    try:
        if args.read:
            print(f"Reading from file: {args.read}\n")
            packets = rdpcap(args.read)

            for i, packet in enumerate(packets):
                if args.count > 0 and i >= args.count:
                    break
                analyzer.analyze_packet(packet)
        else:
            print(f"Capturing on interface: {args.interface}")
            print("Press Ctrl+C to stop\n")

            sniff(
                iface=args.interface,
                prn=analyzer.analyze_packet,
                count=args.count if args.count > 0 else 0
            )
    except KeyboardInterrupt:
        print("\n\nStopping capture...")
    except Exception as e:
        print(f"\nError: {e}")
    finally:
        analyzer.print_statistics()


if __name__ == "__main__":
    import os
    import sys

    if '-i' in sys.argv and os.geteuid() != 0:
        print("Error: Live capture requires root privileges.")
        print("Please run with: sudo python3 complete_bt_analyzer.py -i <interface>")
        exit(1)

    main()