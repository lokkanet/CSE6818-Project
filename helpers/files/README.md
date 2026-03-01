# BitTorrent Traffic Analysis Tools using Scapy

A comprehensive set of Python tools for capturing, analyzing, and monitoring BitTorrent traffic using Scapy.

## Features

- **Real-time traffic monitoring** - Live capture and analysis of BitTorrent traffic
- **DHT protocol analysis** - Detect and analyze Distributed Hash Table communications
- **Peer Wire Protocol** - Capture handshakes, piece transfers, and protocol messages
- **Tracker detection** - Identify HTTP and UDP tracker communications
- **InfoHash extraction** - Discover and track torrent identifiers
- **PCAP capture** - Save traffic for offline analysis
- **Statistical reporting** - Generate detailed reports on captured traffic

## Installation

### Prerequisites

```bash
# Python 3.6 or higher required
python3 --version

# Install Scapy
pip install scapy

# Optional: For bencode parsing (DHT messages)
pip install bencode.py
```

### System Requirements

**Linux:**
```bash
# Install libpcap
sudo apt-get install libpcap-dev  # Debian/Ubuntu
sudo yum install libpcap-devel    # RedHat/CentOS

# Ensure you have root privileges for packet capture
```

**macOS:**
```bash
# libpcap is pre-installed
# Just install Scapy with pip
pip3 install scapy
```

## Tools Overview

### 1. bittorrent_sniffer.py - Real-time Traffic Monitor

Live capture and analysis of BitTorrent traffic with detailed packet inspection.

**Features:**
- Real-time DHT message detection
- Peer Wire Protocol handshake capture
- Message type identification
- InfoHash extraction
- Statistics summary

**Usage:**
```bash
# Basic usage - analyze all traffic
sudo python3 bittorrent_sniffer.py

# The script will show:
# - DHT queries (ping, find_node, get_peers, announce_peer)
# - Handshakes with infohashes
# - PWP messages (choke, unchoke, piece, request, etc.)
# - Statistics summary when stopped with Ctrl+C
```

**Example Output:**
```
======================================================================
[DHT QUERY] 14:32:45.123
  Source: 192.168.1.100:6881
  Destination: 45.67.89.123:6881
  Query: get_peers
  InfoHash: cb91abca6f8d6b34ff8d69540c7dc195e4fb3233
  Node ID: 8f7d6e5c4b3a2918...

======================================================================
[HANDSHAKE] 14:32:46.456
  Source: 192.168.1.100:51234
  Destination: 78.45.23.12:6881
  InfoHash: cb91abca6f8d6b34ff8d69540c7dc195e4fb3233
  Peer ID: 2d5554323030302d...
  Extensions: Supported (DHT, Extension Protocol, etc.)
```

### 2. capture_to_pcap.py - Traffic Capture Tool

Capture BitTorrent traffic and save to PCAP files for later analysis.

**Usage:**
```bash
# Capture all BitTorrent traffic
sudo python3 capture_to_pcap.py -i eth0 -o bt_traffic.pcap

# Capture only DHT traffic
sudo python3 capture_to_pcap.py -i eth0 -o dht.pcap -f dht

# Capture only Peer Wire Protocol
sudo python3 capture_to_pcap.py -i eth0 -o pwp.pcap -f pwp

# Capture 1000 packets with verbose output
sudo python3 capture_to_pcap.py -i eth0 -o bt.pcap -c 1000 -v

# Capture for 60 seconds
sudo python3 capture_to_pcap.py -i eth0 -o bt.pcap -t 60

# Capture on all interfaces
sudo python3 capture_to_pcap.py -i any -o bt.pcap
```

**Options:**
- `-i, --interface`: Network interface (default: any)
- `-o, --output`: Output PCAP file
- `-f, --filter`: Traffic type (all, dht, pwp, tracker)
- `-c, --count`: Number of packets to capture
- `-t, --timeout`: Capture timeout in seconds
- `-v, --verbose`: Show packets during capture

### 3. analyze_pcap.py - PCAP Analysis Tool

Analyze existing PCAP files and generate detailed reports.

**Usage:**
```bash
# Analyze PCAP file
python3 analyze_pcap.py -i capture.pcap

# Save report to file
python3 analyze_pcap.py -i capture.pcap -r report.txt

# Export infohashes to JSON
python3 analyze_pcap.py -i capture.pcap --export-infohashes hashes.json

# Export peer data to JSON
python3 analyze_pcap.py -i capture.pcap --export-peers peers.json

# Full analysis with all exports
python3 analyze_pcap.py -i capture.pcap -r report.txt \
  --export-infohashes hashes.json --export-peers peers.json
```

**Report Example:**
```
======================================================================
BitTorrent PCAP Analysis Report
======================================================================
PCAP File: capture.pcap
Total Packets: 5432

DHT (Distributed Hash Table) Traffic
----------------------------------------------------------------------
Total DHT packets: 1234
  Ping messages: 234
  Find Node messages: 456
  Get Peers messages: 345
  Announce Peer messages: 199
Unique DHT nodes: 567

Peer Wire Protocol (PWP) Traffic
----------------------------------------------------------------------
Total handshakes: 89
Total PWP messages: 3456
  Piece: 1234
  Request: 876
  Have: 543
  ...

InfoHashes Discovered
----------------------------------------------------------------------
Unique infohashes: 45

Top 10 most active infohashes:
  1. cb91abca6f8d6b34ff8d69540c7dc195e4fb3233 (234 occurrences)
  2. a1b2c3d4e5f6... (189 occurrences)
  ...
```

## Understanding BitTorrent Traffic Types

### DHT (Distributed Hash Table)
- **Protocol:** UDP
- **Purpose:** Decentralized peer discovery
- **Messages:**
  - `ping` - Check if node is alive
  - `find_node` - Find nodes close to a target
  - `get_peers` - Find peers for an infohash
  - `announce_peer` - Announce that peer has a torrent

### Peer Wire Protocol (PWP)
- **Protocol:** TCP
- **Purpose:** Actual file transfer between peers
- **Messages:**
  - `handshake` - Initial connection with infohash
  - `choke/unchoke` - Flow control
  - `interested/not interested` - Interest in peer's pieces
  - `have` - Announce piece availability
  - `request/piece` - Request and transfer data blocks
  - `bitfield` - Announce available pieces
  - `extended` - Extension protocol messages

### Tracker Communication
- **HTTP Tracker:** Standard HTTP GET requests
- **UDP Tracker:** Binary protocol over UDP
- **Purpose:** Get peer lists from centralized server

## Advanced Examples

### 1. Monitor specific infohash
```bash
# Use grep to filter for specific infohash
sudo python3 bittorrent_sniffer.py | grep "cb91abca6f8d6b34ff8d69540c7dc195e4fb3233"
```

### 2. Capture and analyze in pipeline
```bash
# Capture 5000 packets, then analyze
sudo python3 capture_to_pcap.py -i eth0 -o temp.pcap -c 5000
python3 analyze_pcap.py -i temp.pcap -r analysis.txt
```

### 3. Monitor DHT activity for research
```bash
# Capture DHT traffic for 1 hour
sudo python3 capture_to_pcap.py -i eth0 -o dht_1hour.pcap -f dht -t 3600

# Analyze and export data
python3 analyze_pcap.py -i dht_1hour.pcap \
  --export-infohashes popular_torrents.json \
  --export-peers peer_network.json
```

### 4. Network forensics
```bash
# Capture all traffic
sudo python3 capture_to_pcap.py -i eth0 -o evidence.pcap -t 600

# Generate detailed report
python3 analyze_pcap.py -i evidence.pcap -r forensic_report.txt
```

## Customization

### Modify Packet Analysis

Edit `bittorrent_sniffer.py` to add custom analysis:

```python
def analyze_packet(self, packet):
    # Add your custom logic here
    if packet.haslayer(UDP):
        # Custom DHT analysis
        pass
    
    if packet.haslayer(TCP):
        # Custom PWP analysis
        pass
```

### Change BPF Filters

Modify the filter in any script:

```python
# Only capture traffic on specific port
bpf_filter = "tcp port 6881"

# Capture traffic to/from specific IP
bpf_filter = "host 192.168.1.100"

# Combine filters
bpf_filter = "tcp port 6881 and host 192.168.1.100"
```

## Troubleshooting

### Permission Denied
```bash
# Run with sudo
sudo python3 bittorrent_sniffer.py

# Or set capabilities (Linux only)
sudo setcap cap_net_raw+ep $(which python3)
```

### No Packets Captured
```bash
# Check available interfaces
ip link show

# Verify interface is up
sudo ip link set eth0 up

# Check if traffic exists
sudo tcpdump -i eth0 -c 10
```

### Import Errors
```bash
# Install missing dependencies
pip install scapy bencode.py

# Upgrade Scapy
pip install --upgrade scapy
```

## Performance Tips

1. **Use specific filters** - Narrow BPF filters improve performance
2. **Limit packet count** - Use `-c` option for large captures
3. **Save to file first** - Capture to PCAP, analyze offline
4. **Use SSD storage** - For high-traffic captures

## Security & Legal Considerations

⚠️ **Important:**
- Only monitor your own network traffic
- Respect privacy and local laws
- Educational and research purposes only
- Some jurisdictions require explicit consent for network monitoring

## Contributing

Feel free to extend these tools:
- Add new protocol support (uTP, LPD, PEX)
- Improve parsing accuracy
- Add visualization features
- Create additional analysis tools

## License

These tools are provided as-is for educational purposes.

## Resources

- [BitTorrent Protocol Specification](http://www.bittorrent.org/beps/bep_0003.html)
- [DHT Protocol (BEP 5)](http://www.bittorrent.org/beps/bep_0005.html)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Wireshark BitTorrent Analysis](https://wiki.wireshark.org/BitTorrent)
