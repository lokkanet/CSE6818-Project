#!/usr/bin/env python3
"""
BitTorrent Torrent Tracker - Identify Torrents, Seeders, and Leechers
Track which traffic belongs to which torrent and peer roles
"""

from scapy.all import *
import binascii
import struct
from datetime import datetime
from collections import defaultdict

class TorrentTracker:
    def __init__(self):
        # Track torrents by infohash
        self.torrents = defaultdict(lambda: {
            'infohash': '',
            'peers': defaultdict(lambda: {
                'ip_port': '',
                'peer_id': '',
                'role': 'unknown',  # seeder, leecher, or unknown
                'first_seen': None,
                'last_seen': None,
                'handshakes': 0,
                'pieces_sent': 0,
                'pieces_received': 0,
                'bytes_sent': 0,
                'bytes_received': 0,
                'has_bitfield': False,
                'interested': False,
                'interesting': False,
            })
        })
        
        # Track connections (src+dst) -> infohash
        self.connections = {}
        
        # Statistics
        self.stats = defaultdict(int)
    
    def analyze_packet(self, packet):
        """Analyze packet and update torrent/peer tracking"""
        timestamp = packet.time
        
        # Analyze different protocols
        if packet.haslayer(UDP):
            self.analyze_dht(packet, timestamp)
            self.analyze_tracker_udp(packet, timestamp)
        
        if packet.haslayer(TCP):
            self.analyze_handshake(packet, timestamp)
            self.analyze_pwp_messages(packet, timestamp)
    
    def analyze_dht(self, packet, timestamp):
        """Extract infohash from DHT traffic"""
        try:
            payload = bytes(packet[UDP].payload)
            
            if not payload or payload[0] != ord(b'd'):
                return
            
            # Extract info_hash from DHT
            if b'9:info_hash20:' in payload:
                idx = payload.find(b'9:info_hash20:')
                if idx != -1 and len(payload) >= idx + 34:
                    info_hash = binascii.hexlify(payload[idx+14:idx+34]).decode()
                    
                    # Just note that this torrent exists
                    if info_hash not in self.torrents:
                        self.torrents[info_hash]['infohash'] = info_hash
                        print(f"\n[NEW TORRENT DISCOVERED via DHT]")
                        print(f"  InfoHash: {info_hash}")
        except:
            pass
    
    def analyze_tracker_udp(self, packet, timestamp):
        """Extract infohash from UDP tracker"""
        try:
            payload = bytes(packet[UDP].payload)
            
            # Announce request is 98+ bytes
            if len(payload) >= 98:
                protocol_id = struct.unpack(">Q", payload[0:8])[0]
                if protocol_id == 0x41727101980:
                    action = struct.unpack(">I", payload[8:12])[0]
                    
                    if action == 1:  # Announce
                        info_hash = binascii.hexlify(payload[16:36]).decode()
                        peer_id = binascii.hexlify(payload[36:56]).decode()
                        
                        # Extract download stats
                        downloaded = struct.unpack(">Q", payload[56:64])[0]
                        left = struct.unpack(">Q", payload[64:72])[0]
                        uploaded = struct.unpack(">Q", payload[72:80])[0]
                        
                        peer_ip = packet[IP].src
                        
                        if info_hash not in self.torrents:
                            self.torrents[info_hash]['infohash'] = info_hash
                        
                        # Determine role based on 'left' parameter
                        if left == 0:
                            role = 'seeder'
                        else:
                            role = 'leecher'
                        
                        peer_key = f"{peer_ip}"
                        if peer_key not in self.torrents[info_hash]['peers']:
                            print(f"\n[NEW PEER via UDP TRACKER]")
                            print(f"  InfoHash: {info_hash}")
                            print(f"  Peer: {peer_ip}")
                            print(f"  Role: {role.upper()}")
                            print(f"  Downloaded: {downloaded} bytes")
                            print(f"  Uploaded: {uploaded} bytes")
                            print(f"  Left: {left} bytes")
                        
                        self.torrents[info_hash]['peers'][peer_key].update({
                            'ip_port': peer_ip,
                            'peer_id': peer_id,
                            'role': role,
                            'last_seen': timestamp
                        })
        except:
            pass
    
    def analyze_handshake(self, packet, timestamp):
        """Analyze BitTorrent handshake to identify torrent and peer"""
        try:
            if not packet.haslayer(Raw):
                return
            
            payload = bytes(packet[Raw].load)
            
            # Check for BitTorrent handshake
            if len(payload) >= 68 and payload[0] == 19 and payload[1:20] == b"BitTorrent protocol":
                
                # Extract infohash and peer_id
                info_hash = binascii.hexlify(payload[28:48]).decode()
                peer_id = binascii.hexlify(payload[48:68]).decode()
                
                src_ip = packet[IP].src
                src_port = packet[TCP].sport
                dst_ip = packet[IP].dst
                dst_port = packet[TCP].dport
                
                src_key = f"{src_ip}:{src_port}"
                dst_key = f"{dst_ip}:{dst_port}"
                
                # Track connection
                conn_key = f"{src_key}->{dst_key}"
                self.connections[conn_key] = info_hash
                
                # Initialize torrent if new
                if info_hash not in self.torrents:
                    self.torrents[info_hash]['infohash'] = info_hash
                    print(f"\n[NEW TORRENT DISCOVERED via HANDSHAKE]")
                    print(f"  InfoHash: {info_hash}")
                
                # Track source peer
                if src_key not in self.torrents[info_hash]['peers']:
                    print(f"\n[NEW PEER HANDSHAKE]")
                    print(f"  InfoHash: {info_hash}")
                    print(f"  Peer: {src_key}")
                    print(f"  Peer ID: {peer_id}")
                    print(f"  Connecting to: {dst_key}")
                
                peer_data = self.torrents[info_hash]['peers'][src_key]
                peer_data.update({
                    'ip_port': src_key,
                    'peer_id': peer_id,
                    'first_seen': peer_data.get('first_seen') or timestamp,
                    'last_seen': timestamp,
                    'handshakes': peer_data.get('handshakes', 0) + 1
                })
                
                self.stats['handshakes'] += 1
        except:
            pass
    
    def analyze_pwp_messages(self, packet, timestamp):
        """Analyze Peer Wire Protocol messages to determine seeder/leecher status"""
        try:
            if not packet.haslayer(Raw):
                return
            
            payload = bytes(packet[Raw].load)
            
            if len(payload) < 5:
                return
            
            # Get connection info
            src_ip = packet[IP].src
            src_port = packet[TCP].sport
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            
            src_key = f"{src_ip}:{src_port}"
            dst_key = f"{dst_ip}:{dst_port}"
            conn_key = f"{src_key}->{dst_key}"
            
            # Find which torrent this connection belongs to
            info_hash = self.connections.get(conn_key)
            if not info_hash:
                return
            
            # Parse message
            msg_length = struct.unpack(">I", payload[0:4])[0]
            
            if msg_length == 0:  # Keep-alive
                return
            
            if len(payload) < 5:
                return
            
            msg_id = payload[4]
            
            # Message types that help identify role
            msg_types = {
                0: "choke",
                1: "unchoke",
                2: "interested",
                3: "not_interested",
                4: "have",
                5: "bitfield",
                6: "request",
                7: "piece",
                8: "cancel"
            }
            
            msg_name = msg_types.get(msg_id, f"unknown_{msg_id}")
            
            peer_data = self.torrents[info_hash]['peers'][src_key]
            
            # Analyze message to determine role
            if msg_id == 5:  # Bitfield
                # Bitfield shows which pieces the peer has
                bitfield = payload[5:]
                total_bits = len(bitfield) * 8
                
                # Count how many pieces they have
                pieces_have = bin(int.from_bytes(bitfield, 'big')).count('1')
                
                peer_data['has_bitfield'] = True
                
                # If they have all pieces, they're a seeder
                # Note: This is approximate - we don't know total piece count
                if pieces_have > total_bits * 0.95:  # 95%+ completion
                    if peer_data['role'] == 'unknown':
                        peer_data['role'] = 'seeder'
                        print(f"\n[PEER IDENTIFIED AS SEEDER]")
                        print(f"  InfoHash: {info_hash}")
                        print(f"  Peer: {src_key}")
                        print(f"  Reason: Has ~{pieces_have} pieces (likely complete)")
                else:
                    if peer_data['role'] == 'unknown':
                        peer_data['role'] = 'leecher'
                        print(f"\n[PEER IDENTIFIED AS LEECHER]")
                        print(f"  InfoHash: {info_hash}")
                        print(f"  Peer: {src_key}")
                        print(f"  Reason: Has ~{pieces_have} pieces (incomplete)")
            
            elif msg_id == 2:  # Interested
                peer_data['interested'] = True
                # If interested, likely a leecher
                if peer_data['role'] == 'unknown':
                    peer_data['role'] = 'leecher'
            
            elif msg_id == 6:  # Request
                # Requesting pieces = leecher behavior
                peer_data['pieces_received'] += 1
                if peer_data['role'] == 'unknown':
                    peer_data['role'] = 'leecher'
            
            elif msg_id == 7:  # Piece
                # Sending pieces
                if len(payload) >= 13:
                    block_size = len(payload) - 13
                    peer_data['pieces_sent'] += 1
                    peer_data['bytes_sent'] += block_size
                    
                    # If sending a lot of pieces, likely a seeder
                    if peer_data['pieces_sent'] > 10 and peer_data['pieces_received'] == 0:
                        if peer_data['role'] == 'unknown':
                            peer_data['role'] = 'seeder'
                            print(f"\n[PEER IDENTIFIED AS SEEDER]")
                            print(f"  InfoHash: {info_hash}")
                            print(f"  Peer: {src_key}")
                            print(f"  Reason: Sending pieces, not requesting")
            
            peer_data['last_seen'] = timestamp
            
        except:
            pass
    
    def print_summary(self):
        """Print comprehensive summary of all torrents and peers"""
        print("\n" + "="*70)
        print("TORRENT AND PEER ANALYSIS SUMMARY")
        print("="*70)
        
        if not self.torrents:
            print("\nNo torrents detected.")
            return
        
        for info_hash, torrent_data in self.torrents.items():
            print(f"\n{'─'*70}")
            print(f"TORRENT: {info_hash}")
            print(f"{'─'*70}")
            
            peers = torrent_data['peers']
            
            if not peers:
                print("  No peers detected for this torrent")
                continue
            
            # Count seeders and leechers
            seeders = [p for p in peers.values() if p['role'] == 'seeder']
            leechers = [p for p in peers.values() if p['role'] == 'leecher']
            unknown = [p for p in peers.values() if p['role'] == 'unknown']
            
            print(f"\nPeer Summary:")
            print(f"  Total Peers: {len(peers)}")
            print(f"  Seeders: {len(seeders)}")
            print(f"  Leechers: {len(leechers)}")
            print(f"  Unknown: {len(unknown)}")
            
            # Show seeders
            if seeders:
                print(f"\n  SEEDERS:")
                for peer in seeders:
                    print(f"    {peer['ip_port']}")
                    if peer['pieces_sent'] > 0:
                        print(f"      Pieces sent: {peer['pieces_sent']}")
                        print(f"      Bytes sent: {peer['bytes_sent']:,}")
            
            # Show leechers
            if leechers:
                print(f"\n  LEECHERS:")
                for peer in leechers:
                    print(f"    {peer['ip_port']}")
                    if peer['pieces_received'] > 0:
                        print(f"      Pieces requested: {peer['pieces_received']}")
            
            # Show unknown peers
            if unknown:
                print(f"\n  UNKNOWN ROLE:")
                for peer in unknown:
                    print(f"    {peer['ip_port']}")
                    if peer['peer_id']:
                        print(f"      Peer ID: {peer['peer_id'][:20]}...")
        
        # Overall statistics
        print(f"\n{'='*70}")
        print("OVERALL STATISTICS")
        print(f"{'='*70}")
        print(f"Total Torrents: {len(self.torrents)}")
        print(f"Total Handshakes: {self.stats['handshakes']}")
        print(f"Active Connections: {len(self.connections)}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Track BitTorrent torrents and identify seeders/leechers',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This tool tracks:
  • Which traffic belongs to which torrent (by infohash)
  • Who is seeding (has complete file, sending pieces)
  • Who is leeching (downloading, requesting pieces)

Detection methods:
  • Handshakes → Identify torrent and peer
  • Bitfield messages → Check if peer has complete file
  • Piece messages → Track who sends/receives data
  • Tracker announces → Direct role information

Examples:
  # Live monitoring
  sudo python3 torrent_tracker.py -i eth0
  
  # Analyze PCAP
  python3 torrent_tracker.py -r capture.pcap
        """
    )
    
    parser.add_argument('-i', '--interface',
                       help='Network interface for live capture')
    
    parser.add_argument('-r', '--read',
                       help='Read from PCAP file')
    
    parser.add_argument('-c', '--count',
                       type=int,
                       default=0,
                       help='Number of packets to capture')
    
    args = parser.parse_args()
    
    if not args.interface and not args.read:
        print("Error: Specify either -i (interface) or -r (file)")
        parser.print_help()
        import sys
        sys.exit(1)
    
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║         BitTorrent Torrent & Peer Tracker                        ║
║                                                                   ║
║  Identifies:                                                     ║
║    • Which torrent each packet belongs to                       ║
║    • Seeders (complete file, uploading)                         ║
║    • Leechers (incomplete file, downloading)                    ║
╚═══════════════════════════════════════════════════════════════════╝
""")
    
    tracker = TorrentTracker()
    
    try:
        if args.read:
            print(f"Analyzing: {args.read}\n")
            packets = rdpcap(args.read)
            
            for i, packet in enumerate(packets):
                if args.count > 0 and i >= args.count:
                    break
                tracker.analyze_packet(packet)
                
                if (i + 1) % 1000 == 0:
                    print(f"Processed {i + 1} packets...", end='\r')
            
            print(f"Processed {len(packets)} packets... Done!")
        else:
            print(f"Capturing on: {args.interface}")
            print("Press Ctrl+C to stop\n")
            
            sniff(
                iface=args.interface,
                prn=tracker.analyze_packet,
                count=args.count if args.count > 0 else 0
            )
    
    except KeyboardInterrupt:
        print("\n\nStopping capture...")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
    finally:
        tracker.print_summary()


if __name__ == "__main__":
    import os
    import sys
    
    if '-i' in sys.argv and os.geteuid() != 0:
        print("Error: Live capture requires root privileges")
        print("Run with: sudo python3 torrent_tracker.py -i <interface>")
        exit(1)
    
    main()
