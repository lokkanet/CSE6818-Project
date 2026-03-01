# BitTorrent Peer Discovery: DHT, Trackers, and PEX

## Overview

BitTorrent clients use **THREE** main methods to discover peers:

1. **DHT (Distributed Hash Table)** - Decentralized
2. **Trackers (HTTP/UDP)** - Centralized servers
3. **PEX (Peer Exchange)** - Peer-to-peer exchange

---

## 1. DHT (Distributed Hash Table)

### What is DHT?

A **decentralized** peer discovery system. No central server needed!

- Based on Kademlia algorithm
- Peers form a distributed network
- Each peer stores info about nearby peers
- **Protocol:** UDP (usually port 6881-6889)

### How to Detect DHT in Scapy

```python
from scapy.all import *

def detect_dht(packet):
    if packet.haslayer(UDP):
        payload = bytes(packet[UDP].payload)
        
        # DHT messages are bencoded (start with 'd')
        if payload and payload[0] == ord(b'd'):
            print("DHT message detected!")
            
            # Check message type
            if b'1:q4:ping' in payload:
                print("  Type: ping")
            elif b'1:q9:find_node' in payload:
                print("  Type: find_node")
            elif b'1:q9:get_peers' in payload:
                print("  Type: get_peers")
            elif b'1:q13:announce_peer' in payload:
                print("  Type: announce_peer")

sniff(filter="udp", prn=detect_dht)
```

### DHT Message Types

| Message | Purpose |
|---------|---------|
| **ping** | Check if node is alive |
| **find_node** | Find nodes close to a target ID |
| **get_peers** | Find peers for a specific torrent |
| **announce_peer** | Announce that you have a torrent |

### DHT Packet Structure

```
Bencode dictionary:
d
  1:t2:aa          # Transaction ID
  1:y1:q           # Message type (q=query, r=response, e=error)
  1:q9:get_peers   # Query name
  1:ad             # Arguments dictionary
    2:id20:...     # Node ID (20 bytes)
    9:info_hash20:...  # InfoHash (20 bytes)
  e
e
```

### Detection Characteristics

✅ **Protocol:** UDP  
✅ **Port:** Usually 6881-6889 (but can be any)  
✅ **Signature:** Starts with 'd' (bencode)  
✅ **Contains:** Transaction ID, message type, query/response  

---

## 2. Centralized Trackers

Trackers are **centralized servers** that keep lists of peers.

### 2A. HTTP Trackers

Traditional web-based trackers using HTTP protocol.

#### How to Detect HTTP Trackers

```python
from scapy.all import *

def detect_http_tracker(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        
        # Check for tracker requests
        if b'GET /announce' in payload:
            print("HTTP Tracker: Announce request")
            
            # Extract tracker URL
            if b'Host: ' in payload:
                host_start = payload.find(b'Host: ') + 6
                host_end = payload.find(b'\r\n', host_start)
                host = payload[host_start:host_end]
                print(f"  Tracker: {host.decode()}")
        
        elif b'GET /scrape' in payload:
            print("HTTP Tracker: Scrape request")

sniff(filter="tcp", prn=detect_http_tracker)
```

#### HTTP Tracker Request Format

```
GET /announce?info_hash=%12%34%56...&peer_id=-UT2000-...&port=6881&uploaded=0&downloaded=0&left=12345&event=started HTTP/1.1
Host: tracker.example.com
User-Agent: uTorrent/2000
```

**Parameters:**
- `info_hash`: Torrent identifier (URL-encoded)
- `peer_id`: Client identifier
- `port`: Listening port
- `uploaded/downloaded/left`: Statistics
- `event`: started/completed/stopped

#### Detection Characteristics

✅ **Protocol:** TCP (HTTP)  
✅ **Port:** Usually 80, 8080, 6969  
✅ **Signature:** "GET /announce" or "GET /scrape"  
✅ **Contains:** info_hash parameter in URL  

---

### 2B. UDP Trackers

More efficient binary protocol for trackers.

#### How to Detect UDP Trackers

```python
from scapy.all import *
import struct

def detect_udp_tracker(packet):
    if packet.haslayer(UDP):
        payload = bytes(packet[UDP].payload)
        
        # UDP tracker connect request is 16 bytes
        if len(payload) == 16:
            protocol_id = struct.unpack(">Q", payload[0:8])[0]
            
            # Magic constant for UDP tracker
            if protocol_id == 0x41727101980:
                action = struct.unpack(">I", payload[8:12])[0]
                
                actions = {0: "connect", 1: "announce", 2: "scrape"}
                print(f"UDP Tracker: {actions.get(action, 'unknown')}")
        
        # Announce request is 98 bytes
        elif len(payload) >= 98:
            protocol_id = struct.unpack(">Q", payload[0:8])[0]
            if protocol_id == 0x41727101980:
                action = struct.unpack(">I", payload[8:12])[0]
                if action == 1:  # Announce
                    info_hash = payload[16:36].hex()
                    print(f"UDP Tracker Announce: {info_hash}")

sniff(filter="udp", prn=detect_udp_tracker)
```

#### UDP Tracker Protocol (BEP 15)

**Connect Request (16 bytes):**
```
Offset  Size    Name            Value
0       64-bit  protocol_id     0x41727101980 (magic constant)
8       32-bit  action          0 (connect)
12      32-bit  transaction_id  Random
```

**Announce Request (98 bytes):**
```
Offset  Size    Name            
0       64-bit  connection_id   (from connect response)
8       32-bit  action          1 (announce)
12      32-bit  transaction_id  
16      20-byte info_hash       
36      20-byte peer_id         
56      64-bit  downloaded      
64      64-bit  left            
72      64-bit  uploaded        
80      32-bit  event           (0=none, 1=completed, 2=started, 3=stopped)
84      32-bit  IP address      (0=default)
88      32-bit  key             
92      32-bit  num_want        (-1=default)
94      16-bit  port            
```

#### Detection Characteristics

✅ **Protocol:** UDP  
✅ **Port:** Varies (common: 6969, 8080)  
✅ **Signature:** Protocol ID = 0x41727101980  
✅ **Contains:** Action code (0=connect, 1=announce, 2=scrape)  

---

## 3. PEX (Peer Exchange)

Peers share their peer lists **directly** with each other via the Extension Protocol.

### What is PEX?

- Peers tell each other about other peers they know
- Uses BitTorrent Extension Protocol (BEP 10)
- Reduces tracker load
- **Protocol:** TCP (within BitTorrent connection)

### How to Detect PEX in Scapy

```python
from scapy.all import *
import struct

def detect_pex(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        
        if len(payload) < 6:
            return
        
        try:
            msg_length = struct.unpack(">I", payload[0:4])[0]
            
            if msg_length > 0 and len(payload) >= 6:
                msg_id = payload[4]
                
                # Message ID 20 = Extended Protocol
                if msg_id == 20:
                    ext_msg_id = payload[5]
                    
                    if ext_msg_id == 0:
                        print("Extended Handshake")
                        
                        # Check if PEX is supported
                        if b'ut_pex' in payload:
                            print("  Client supports PEX!")
                    
                    elif ext_msg_id == 1:
                        print("PEX Message (Peer Exchange)")
                        print("  Peers are being exchanged!")
                        
        except:
            pass

sniff(filter="tcp", prn=detect_pex)
```

### PEX Message Structure

**Extended Handshake (establishes support):**
```
<length><20><0><bencoded_dict>

Bencoded dictionary:
d
  1:md
    7:ut_pexi1e    # PEX extension ID = 1
    11:ut_metadatai2e
  e
  1:pi6881e        # Listening port
  1:v13:uTorrent 2.0
e
```

**PEX Message (actual peer exchange):**
```
<length><20><1><bencoded_dict>

Bencoded dictionary:
d
  5:added<length>:<compact_peers>  # New peers (6 bytes each: 4 IP + 2 port)
  7:added.f<length>:<flags>        # Flags for added peers
  7:dropped<length>:<compact_peers> # Removed peers
e
```

### Detection Characteristics

✅ **Protocol:** TCP (within BitTorrent PWP connection)  
✅ **Message ID:** 20 (Extended Protocol)  
✅ **Extended Message ID:** 0 (handshake) or 1 (ut_pex)  
✅ **Contains:** Bencoded peer lists  

---

## Comparison Table

| Feature | DHT | HTTP Tracker | UDP Tracker | PEX |
|---------|-----|--------------|-------------|-----|
| **Architecture** | Decentralized | Centralized | Centralized | P2P |
| **Protocol** | UDP | TCP (HTTP) | UDP | TCP (Extension) |
| **Port** | 6881-6889 | 80, 8080, 6969 | Varies | Same as PWP |
| **Advantages** | No server needed | Simple, reliable | Fast, efficient | No tracker needed |
| **Disadvantages** | Complex, slower | Single point of failure | Not widely supported | Requires connection |
| **Detection** | Bencode 'd' | "GET /announce" | Magic constant | Message ID 20 |

---

## Complete Detection Code

Here's how to detect ALL THREE:

```python
from scapy.all import *
import struct

class BitTorrentDetector:
    def detect_all(self, packet):
        # 1. Check for DHT (UDP, bencode)
        if packet.haslayer(UDP):
            payload = bytes(packet[UDP].payload)
            if payload and payload[0] == ord(b'd'):
                print("✓ DHT detected")
                return
            
            # 2. Check for UDP Tracker
            if len(payload) >= 16:
                try:
                    protocol_id = struct.unpack(">Q", payload[0:8])[0]
                    if protocol_id == 0x41727101980:
                        print("✓ UDP Tracker detected")
                        return
                except:
                    pass
        
        # 3. Check for HTTP Tracker and PEX (TCP)
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            
            # HTTP Tracker
            if b'GET /announce' in payload or b'GET /scrape' in payload:
                print("✓ HTTP Tracker detected")
                return
            
            # PEX (Extended Protocol)
            if len(payload) >= 6:
                try:
                    msg_id = payload[4]
                    if msg_id == 20:  # Extended protocol
                        ext_msg_id = payload[5]
                        if ext_msg_id in [0, 1]:
                            print("✓ PEX detected")
                            return
                except:
                    pass

detector = BitTorrentDetector()
sniff(prn=detector.detect_all, filter="tcp or udp")
```

---

## Real-World Usage

Most modern BitTorrent clients use **ALL THREE** simultaneously:

1. **DHT** - Primary method, always running
2. **Trackers** - Backup method, faster initial peer discovery
3. **PEX** - Supplementary method, reduces tracker load

### Typical Flow:

```
Client starts download:
├─ 1. Contact HTTP/UDP tracker (fast initial peers)
├─ 2. Enable DHT (long-term peer discovery)
└─ 3. Once connected to peers, enable PEX (ongoing peer discovery)
```

---

## Answer to Your Question

**Is the original Scapy code capable of catching all three?**

### Original Code Coverage:

✅ **DHT** - YES (fully covered)  
⚠️ **HTTP Trackers** - PARTIALLY (detects but limited parsing)  
❌ **UDP Trackers** - NO (not implemented)  
❌ **PEX** - NO (not implemented)  

### New Complete Analyzer Coverage:

✅ **DHT** - FULLY COVERED  
✅ **HTTP Trackers** - FULLY COVERED  
✅ **UDP Trackers** - FULLY COVERED  
✅ **PEX** - FULLY COVERED  

The new `complete_bt_analyzer.py` detects **ALL THREE** mechanisms!

---

## Testing Your Detection

### Generate Test Traffic:

```bash
# 1. Start a BitTorrent client
# Most clients use all three methods

# 2. Capture traffic
sudo python3 complete_bt_analyzer.py -i eth0

# You should see:
# - DHT queries (ping, find_node, get_peers)
# - HTTP/UDP tracker requests
# - PEX messages (if connected to peers)
```

### What to Expect:

**First few seconds:**
- Tracker announces (HTTP/UDP)
- DHT bootstrap queries

**After 1-2 minutes:**
- Regular DHT queries
- PEX exchanges (if connected to peers)
- Periodic tracker announces

---

## Summary

Three peer discovery methods, three different detection approaches:

1. **DHT**: Look for bencode 'd' in UDP packets
2. **HTTP Tracker**: Look for "GET /announce" in TCP packets
3. **UDP Tracker**: Look for magic constant 0x41727101980 in UDP
4. **PEX**: Look for message ID 20 with ext_msg_id 0 or 1 in TCP

Use the `complete_bt_analyzer.py` to catch them all!
