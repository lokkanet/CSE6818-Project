#!/usr/bin/env python3
"""
BitTorrent Traffic Capture to PCAP
Captures BitTorrent traffic and saves to file for later analysis
"""

from scapy.all import *
import argparse
from datetime import datetime

def create_filters():
    """Create various BPF filters for different BitTorrent traffic"""
    filters = {
        'all': 'udp or tcp',
        'dht': 'udp portrange 6881-6889',
        'pwp': 'tcp portrange 6881-6889',
        'tracker': '(tcp port 80 or tcp port 8080 or tcp port 6969) or udp',
        'custom_port': None  # Will be set by user
    }
    return filters

def quick_analyze(packet):
    """Quick analysis during capture"""
    try:
        # DHT detection
        if packet.haslayer(UDP):
            payload = bytes(packet[UDP].payload)
            if payload and payload[0] == ord(b'd'):
                print(f"[DHT] {packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport}")
        
        # Handshake detection
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            if len(payload) >= 20 and payload[0] == 19 and payload[1:20] == b"BitTorrent protocol":
                print(f"[HANDSHAKE] {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")
                
    except:
        pass

def capture_to_pcap(interface, output_file, filter_type='all', packet_count=0, timeout=None, verbose=False):
    """Capture BitTorrent traffic to PCAP file"""
    
    filters = create_filters()
    bpf_filter = filters.get(filter_type, filters['all'])
    
    print(f"""
Starting BitTorrent Capture
{'='*50}
Interface: {interface}
Output file: {output_file}
Filter: {filter_type} ({bpf_filter})
Packet count: {'Unlimited' if packet_count == 0 else packet_count}
Timeout: {'None' if timeout is None else f'{timeout} seconds'}
Verbose: {verbose}
{'='*50}
""")
    
    print("Capturing... Press Ctrl+C to stop\n")
    
    try:
        packets = sniff(
            iface=interface,
            filter=bpf_filter,
            count=packet_count if packet_count > 0 else 0,
            timeout=timeout,
            prn=quick_analyze if verbose else None
        )
        
        # Save to PCAP
        wrpcap(output_file, packets)
        
        print(f"\n\nCapture complete!")
        print(f"Packets captured: {len(packets)}")
        print(f"Saved to: {output_file}")
        
        # Quick statistics
        tcp_count = sum(1 for p in packets if p.haslayer(TCP))
        udp_count = sum(1 for p in packets if p.haslayer(UDP))
        
        print(f"\nStatistics:")
        print(f"  TCP packets: {tcp_count}")
        print(f"  UDP packets: {udp_count}")
        
    except KeyboardInterrupt:
        print("\n\nCapture interrupted by user")
        if 'packets' in locals():
            wrpcap(output_file, packets)
            print(f"Partial capture saved to: {output_file}")
            print(f"Packets captured: {len(packets)}")

def main():
    parser = argparse.ArgumentParser(
        description='Capture BitTorrent traffic to PCAP file',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Capture all BitTorrent traffic
  sudo python3 capture_to_pcap.py -i eth0 -o bt_traffic.pcap
  
  # Capture only DHT traffic
  sudo python3 capture_to_pcap.py -i eth0 -o dht.pcap -f dht
  
  # Capture 1000 packets with verbose output
  sudo python3 capture_to_pcap.py -i eth0 -o bt.pcap -c 1000 -v
  
  # Capture for 60 seconds
  sudo python3 capture_to_pcap.py -i eth0 -o bt.pcap -t 60
        """
    )
    
    parser.add_argument('-i', '--interface', 
                       default='any',
                       help='Network interface to capture on (default: any)')
    
    parser.add_argument('-o', '--output',
                       default=f'bittorrent_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pcap',
                       help='Output PCAP file (default: bittorrent_TIMESTAMP.pcap)')
    
    parser.add_argument('-f', '--filter',
                       choices=['all', 'dht', 'pwp', 'tracker'],
                       default='all',
                       help='Traffic filter type (default: all)')
    
    parser.add_argument('-c', '--count',
                       type=int,
                       default=0,
                       help='Number of packets to capture (0 = unlimited, default: 0)')
    
    parser.add_argument('-t', '--timeout',
                       type=int,
                       default=None,
                       help='Capture timeout in seconds (default: no timeout)')
    
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Show packets as they are captured')
    
    args = parser.parse_args()
    
    # Check if running as root
    import os
    if os.geteuid() != 0:
        print("Error: This script requires root privileges.")
        print("Please run with: sudo python3 capture_to_pcap.py")
        exit(1)
    
    capture_to_pcap(
        interface=args.interface,
        output_file=args.output,
        filter_type=args.filter,
        packet_count=args.count,
        timeout=args.timeout,
        verbose=args.verbose
    )

if __name__ == "__main__":
    main()
