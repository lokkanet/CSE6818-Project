#!/usr/bin/env python3
"""
BitTorrent PCAP Analyzer
Analyze existing PCAP files for BitTorrent traffic and generate reports
"""

from scapy.all import *
import binascii
import struct
from collections import defaultdict, Counter
import json
import argparse

class PCAPAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.infohashes = {}  # infohash -> count
        self.peers = {}  # peer -> infohashes
        self.dht_nodes = set()
        self.conversations = defaultdict(list)  # (src, dst) -> packets
        self.stats = defaultdict(int)
        
    def load_pcap(self):
        """Load PCAP file"""
        print(f"Loading PCAP file: {self.pcap_file}")
        try:
            self.packets = rdpcap(self.pcap_file)
            print(f"Loaded {len(self.packets)} packets\n")
        except Exception as e:
            print(f"Error loading PCAP: {e}")
            exit(1)
    
    def analyze_all(self):
        """Analyze all packets"""
        print("Analyzing packets...")
        
        for i, packet in enumerate(self.packets):
            if (i + 1) % 1000 == 0:
                print(f"  Processed {i + 1}/{len(self.packets)} packets...", end='\r')
            
            self.analyze_packet(packet)
        
        print(f"  Processed {len(self.packets)}/{len(self.packets)} packets... Done!  ")
    
    def analyze_packet(self, packet):
        """Analyze individual packet"""
        # DHT analysis
        if packet.haslayer(UDP):
            self.analyze_dht(packet)
        
        # PWP analysis
        if packet.haslayer(TCP):
            self.analyze_pwp(packet)
    
    def analyze_dht(self, packet):
        """Analyze DHT packet"""
        try:
            payload = bytes(packet[UDP].payload)
            
            if not payload or payload[0] != ord(b'd'):
                return
            
            self.stats['dht_packets'] += 1
            
            # Track conversation
            src = f"{packet[IP].src}:{packet[UDP].sport}"
            dst = f"{packet[IP].dst}:{packet[UDP].dport}"
            self.conversations[(src, dst)].append(packet)
            
            # Extract info
            if b'1:q4:ping' in payload:
                self.stats['dht_ping'] += 1
            elif b'1:q9:find_node' in payload:
                self.stats['dht_find_node'] += 1
            elif b'1:q9:get_peers' in payload:
                self.stats['dht_get_peers'] += 1
            elif b'1:q13:announce_peer' in payload:
                self.stats['dht_announce_peer'] += 1
            
            # Extract node ID
            if b'2:id20:' in payload:
                idx = payload.find(b'2:id20:')
                if idx != -1 and len(payload) >= idx + 27:
                    node_id = binascii.hexlify(payload[idx+7:idx+27]).decode()
                    self.dht_nodes.add(node_id)
            
            # Extract info_hash
            if b'9:info_hash20:' in payload:
                idx = payload.find(b'9:info_hash20:')
                if idx != -1 and len(payload) >= idx + 34:
                    info_hash = binascii.hexlify(payload[idx+14:idx+34]).decode()
                    if info_hash not in self.infohashes:
                        self.infohashes[info_hash] = 0
                    self.infohashes[info_hash] += 1
                    
        except:
            pass
    
    def analyze_pwp(self, packet):
        """Analyze Peer Wire Protocol packet"""
        try:
            if not packet.haslayer(Raw):
                return
            
            payload = bytes(packet[Raw].load)
            
            if len(payload) == 0:
                return
            
            # Track conversation
            src = f"{packet[IP].src}:{packet[TCP].sport}"
            dst = f"{packet[IP].dst}:{packet[TCP].dport}"
            
            # Handshake
            if len(payload) >= 68 and payload[0] == 19 and payload[1:20] == b"BitTorrent protocol":
                info_hash = binascii.hexlify(payload[28:48]).decode()
                peer_id = binascii.hexlify(payload[48:68]).decode()
                
                if info_hash not in self.infohashes:
                    self.infohashes[info_hash] = 0
                self.infohashes[info_hash] += 1
                
                if src not in self.peers:
                    self.peers[src] = set()
                self.peers[src].add(info_hash)
                
                self.stats['handshakes'] += 1
                self.conversations[(src, dst)].append(packet)
                
            # PWP messages
            elif len(payload) >= 5:
                try:
                    msg_length = struct.unpack(">I", payload[:4])[0]
                    
                    if 0 < msg_length < 100000 and len(payload) >= 5:
                        msg_id = payload[4]
                        
                        msg_types = {
                            0: "choke", 1: "unchoke", 2: "interested",
                            3: "not_interested", 4: "have", 5: "bitfield",
                            6: "request", 7: "piece", 8: "cancel",
                            9: "port", 20: "extended"
                        }
                        
                        if msg_id in msg_types:
                            self.stats[f'pwp_{msg_types[msg_id]}'] += 1
                            self.stats['pwp_messages'] += 1
                            self.conversations[(src, dst)].append(packet)
                            
                except:
                    pass
                    
        except:
            pass
    
    def generate_report(self, output_file=None):
        """Generate analysis report"""
        report = []
        
        report.append("="*70)
        report.append("BitTorrent PCAP Analysis Report")
        report.append("="*70)
        report.append(f"PCAP File: {self.pcap_file}")
        report.append(f"Total Packets: {len(self.packets)}")
        report.append("")
        
        # DHT Statistics
        report.append("DHT (Distributed Hash Table) Traffic")
        report.append("-" * 70)
        report.append(f"Total DHT packets: {self.stats['dht_packets']}")
        report.append(f"  Ping messages: {self.stats['dht_ping']}")
        report.append(f"  Find Node messages: {self.stats['dht_find_node']}")
        report.append(f"  Get Peers messages: {self.stats['dht_get_peers']}")
        report.append(f"  Announce Peer messages: {self.stats['dht_announce_peer']}")
        report.append(f"Unique DHT nodes: {len(self.dht_nodes)}")
        report.append("")
        
        # PWP Statistics
        report.append("Peer Wire Protocol (PWP) Traffic")
        report.append("-" * 70)
        report.append(f"Total handshakes: {self.stats['handshakes']}")
        report.append(f"Total PWP messages: {self.stats['pwp_messages']}")
        report.append(f"  Choke: {self.stats['pwp_choke']}")
        report.append(f"  Unchoke: {self.stats['pwp_unchoke']}")
        report.append(f"  Interested: {self.stats['pwp_interested']}")
        report.append(f"  Not Interested: {self.stats['pwp_not_interested']}")
        report.append(f"  Have: {self.stats['pwp_have']}")
        report.append(f"  Bitfield: {self.stats['pwp_bitfield']}")
        report.append(f"  Request: {self.stats['pwp_request']}")
        report.append(f"  Piece: {self.stats['pwp_piece']}")
        report.append(f"  Cancel: {self.stats['pwp_cancel']}")
        report.append(f"  Extended: {self.stats['pwp_extended']}")
        report.append("")
        
        # InfoHash Statistics
        report.append("InfoHashes Discovered")
        report.append("-" * 70)
        report.append(f"Unique infohashes: {len(self.infohashes)}")
        
        if self.infohashes:
            report.append("\nTop 10 most active infohashes:")
            sorted_hashes = sorted(self.infohashes.items(), key=lambda x: x[1], reverse=True)
            for i, (ih, count) in enumerate(sorted_hashes[:10], 1):
                report.append(f"  {i}. {ih} ({count} occurrences)")
        
        report.append("")
        
        # Peer Statistics
        report.append("Peer Statistics")
        report.append("-" * 70)
        report.append(f"Unique peers: {len(self.peers)}")
        
        if self.peers:
            report.append("\nTop 10 most active peers:")
            sorted_peers = sorted(self.peers.items(), key=lambda x: len(x[1]), reverse=True)
            for i, (peer, hashes) in enumerate(sorted_peers[:10], 1):
                report.append(f"  {i}. {peer} ({len(hashes)} infohashes)")
        
        report.append("")
        
        # Conversation Statistics
        report.append("Conversation Statistics")
        report.append("-" * 70)
        report.append(f"Unique conversations: {len(self.conversations)}")
        
        # Find most active conversations
        sorted_convs = sorted(self.conversations.items(), key=lambda x: len(x[1]), reverse=True)
        if sorted_convs:
            report.append("\nTop 10 most active conversations:")
            for i, ((src, dst), packets) in enumerate(sorted_convs[:10], 1):
                report.append(f"  {i}. {src} <-> {dst} ({len(packets)} packets)")
        
        report.append("")
        report.append("="*70)
        
        # Print report
        report_text = "\n".join(report)
        print("\n" + report_text)
        
        # Save to file if requested
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_text)
            print(f"\nReport saved to: {output_file}")
        
        return report_text
    
    def export_infohashes(self, output_file):
        """Export infohashes to JSON"""
        data = {
            'infohashes': [
                {
                    'hash': ih,
                    'occurrences': count
                }
                for ih, count in sorted(self.infohashes.items(), key=lambda x: x[1], reverse=True)
            ],
            'total': len(self.infohashes)
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"Infohashes exported to: {output_file}")
    
    def export_peers(self, output_file):
        """Export peer information to JSON"""
        data = {
            'peers': [
                {
                    'address': peer,
                    'infohashes': list(hashes),
                    'count': len(hashes)
                }
                for peer, hashes in sorted(self.peers.items(), key=lambda x: len(x[1]), reverse=True)
            ],
            'total': len(self.peers)
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"Peer data exported to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='Analyze PCAP files for BitTorrent traffic',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze PCAP and show report
  python3 analyze_pcap.py -i capture.pcap
  
  # Save report to file
  python3 analyze_pcap.py -i capture.pcap -r report.txt
  
  # Export infohashes to JSON
  python3 analyze_pcap.py -i capture.pcap --export-infohashes hashes.json
  
  # Full analysis with all exports
  python3 analyze_pcap.py -i capture.pcap -r report.txt --export-infohashes hashes.json --export-peers peers.json
        """
    )
    
    parser.add_argument('-i', '--input',
                       required=True,
                       help='Input PCAP file to analyze')
    
    parser.add_argument('-r', '--report',
                       help='Save report to file')
    
    parser.add_argument('--export-infohashes',
                       help='Export infohashes to JSON file')
    
    parser.add_argument('--export-peers',
                       help='Export peer data to JSON file')
    
    args = parser.parse_args()
    
    # Create analyzer
    analyzer = PCAPAnalyzer(args.input)
    
    # Load and analyze
    analyzer.load_pcap()
    analyzer.analyze_all()
    
    # Generate report
    print()
    analyzer.generate_report(args.report)
    
    # Export data if requested
    if args.export_infohashes:
        print()
        analyzer.export_infohashes(args.export_infohashes)
    
    if args.export_peers:
        print()
        analyzer.export_peers(args.export_peers)

if __name__ == "__main__":
    main()
