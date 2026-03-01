# Identifying Torrents and Seeders/Leechers from Traffic

## The Challenge

When analyzing BitTorrent traffic, you need to answer:
1. **Which torrent does this traffic belong to?**
2. **Is this peer a seeder or leecher?**

---

## Part 1: Identifying Which Torrent (InfoHash)

### The Key: InfoHash

Every torrent is identified by a unique **20-byte SHA-1 hash** called the **InfoHash**.

**InfoHash = SHA-1 hash of the torrent's metadata**

### Where to Find InfoHash

#### 1. **In Handshakes** (Most Reliable)

```python
# BitTorrent handshake structure (68 bytes):
# [1 byte: 19][19 bytes: "BitTorrent protocol"][8 bytes: reserved]
# [20 bytes: INFOHASH][20 bytes: peer_id]

payload = bytes(packet[Raw].load)

if len(payload) >= 68 and payload[0] == 19:
    infohash = payload[28:48]  # Bytes 28-48
    infohash_hex = binascii.hexlify(infohash).decode()
    
    print(f"InfoHash: {infohash_hex}")
    # This packet belongs to torrent: infohash_hex
```

**Example:**
```
InfoHash: cb91abca6f8d6b34ff8d69540c7dc195e4fb3233
         └─ This identifies a specific torrent
```

#### 2. **In DHT Messages**

```python
# DHT get_peers or announce_peer contain infohash
payload = bytes(packet[UDP].payload)

if b'9:info_hash20:' in payload:
    idx = payload.find(b'9:info_hash20:')
    infohash = payload[idx+14:idx+34]
    infohash_hex = binascii.hexlify(infohash).decode()
```

#### 3. **In Tracker Announces**

**UDP Tracker:**
```python
# Announce request (98 bytes)
# Bytes 16-36 contain infohash
infohash = payload[16:36]
```

**HTTP Tracker:**
```
GET /announce?info_hash=%CB%91%AB%CA...
                        └─ URL-encoded infohash
```

### Tracking Connections to Torrents

Once you see a handshake, you know:
```python
# Connection: 192.168.1.100:51234 -> 45.67.89.12:6881
# InfoHash: cb91abca6f8d6b34ff8d69540c7dc195e4fb3233

# All subsequent traffic between these IPs/ports belongs to this torrent
connection_map = {
    "192.168.1.100:51234 -> 45.67.89.12:6881": "cb91abca6f8d6b34ff8d69540c7dc195e4fb3233"
}
```

**Key Point:** After handshake, map the connection (src:port -> dst:port) to the infohash!

---

## Part 2: Identifying Seeders vs Leechers

### Definitions

**Seeder:**
- Has the **complete** file
- **Uploads** pieces to others
- **Does not download** (already has everything)

**Leecher:**
- Has **incomplete** file (or none)
- **Downloads** pieces from others
- May also upload pieces they have

### Detection Methods

#### Method 1: **Tracker Announces** (Most Reliable)

UDP and HTTP trackers tell you directly!

**UDP Tracker Announce:**
```python
# Bytes 64-72: "left" field (bytes left to download)
left = struct.unpack(">Q", payload[64:72])[0]

if left == 0:
    print("SEEDER - Has complete file")
else:
    print(f"LEECHER - {left} bytes remaining")
```

**HTTP Tracker:**
```
GET /announce?...&left=0&...
                  └─ 0 = seeder
                     
GET /announce?...&left=1234567&...
                  └─ >0 = leecher
```

#### Method 2: **Bitfield Message** (Very Reliable)

The bitfield shows which pieces a peer has.

```python
# Message ID 5 = bitfield
if msg_id == 5:
    bitfield = payload[5:]
    
    # Count how many pieces they have
    total_bits = len(bitfield) * 8
    pieces_have = bin(int.from_bytes(bitfield, 'big')).count('1')
    
    completion = pieces_have / total_bits
    
    if completion > 0.99:  # 99%+ = seeder
        print("SEEDER - Has all/nearly all pieces")
    else:
        print(f"LEECHER - Has {completion*100:.1f}% of pieces")
```

**Example:**
```
Bitfield: 11111111 11111111 11111111 11111111
          └─ All 1s = Has all pieces = SEEDER

Bitfield: 11110011 10101100 00110111 01010011
          └─ Mix of 0s and 1s = Missing pieces = LEECHER
```

#### Method 3: **Traffic Patterns** (Behavioral)

Watch what they do:

**Seeders typically:**
- Send "piece" messages (msg_id 7)
- Do NOT send "request" messages (msg_id 6)
- Send "not interested" (msg_id 3) to others

**Leechers typically:**
- Send "interested" (msg_id 2)
- Send "request" messages (msg_id 6)
- Receive "piece" messages

```python
# Track behavior
peer_stats = {
    'pieces_sent': 0,
    'pieces_received': 0,
    'requests_sent': 0
}

if msg_id == 7:  # Piece
    if src == our_peer:
        peer_stats['pieces_sent'] += 1

if msg_id == 6:  # Request
    if src == our_peer:
        peer_stats['requests_sent'] += 1

# Analyze
if peer_stats['pieces_sent'] > 10 and peer_stats['requests_sent'] == 0:
    print("Likely SEEDER - Only uploads, no requests")
elif peer_stats['requests_sent'] > 0:
    print("LEECHER - Requesting pieces")
```

#### Method 4: **Have Messages** (Approximate)

```python
# Message ID 4 = have (announces a piece)
# If peer announces ALL pieces → seeder
# If peer announces some pieces → leecher

pieces_announced = set()

if msg_id == 4:
    piece_index = struct.unpack(">I", payload[5:9])[0]
    pieces_announced.add(piece_index)

# If they announce every piece 0-N → seeder
```

---

## Complete Example

Here's how to track everything:

```python
from scapy.all import *
import binascii
import struct

# Data structures
torrents = {}  # infohash -> peer data
connections = {}  # "ip:port->ip:port" -> infohash

def analyze_packet(packet):
    # 1. Check for handshake (identifies torrent)
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        
        if len(payload) >= 68 and payload[0] == 19:
            infohash = binascii.hexlify(payload[28:48]).decode()
            peer_id = binascii.hexlify(payload[48:68]).decode()
            
            src = f"{packet[IP].src}:{packet[TCP].sport}"
            dst = f"{packet[IP].dst}:{packet[TCP].dport}"
            
            # Map connection to torrent
            connections[f"{src}->{dst}"] = infohash
            
            # Initialize torrent tracking
            if infohash not in torrents:
                torrents[infohash] = {}
            
            # Track peer
            if src not in torrents[infohash]:
                torrents[infohash][src] = {
                    'peer_id': peer_id,
                    'role': 'unknown',
                    'pieces_sent': 0,
                    'requests_sent': 0
                }
            
            print(f"Handshake: {src} for torrent {infohash}")
    
    # 2. Check for PWP messages (determines role)
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        
        if len(payload) >= 5:
            src = f"{packet[IP].src}:{packet[TCP].sport}"
            conn_key = f"{src}->{packet[IP].dst}:{packet[TCP].dport}"
            
            # Find which torrent this belongs to
            infohash = connections.get(conn_key)
            if not infohash:
                return
            
            msg_id = payload[4]
            
            # Bitfield (most reliable)
            if msg_id == 5:
                bitfield = payload[5:]
                pieces = bin(int.from_bytes(bitfield, 'big')).count('1')
                total = len(bitfield) * 8
                
                if pieces > total * 0.95:
                    torrents[infohash][src]['role'] = 'seeder'
                    print(f"{src} is a SEEDER for {infohash}")
                else:
                    torrents[infohash][src]['role'] = 'leecher'
                    print(f"{src} is a LEECHER for {infohash}")
            
            # Request (leecher behavior)
            elif msg_id == 6:
                torrents[infohash][src]['requests_sent'] += 1
                if torrents[infohash][src]['role'] == 'unknown':
                    torrents[infohash][src]['role'] = 'leecher'
            
            # Piece (seeder behavior)
            elif msg_id == 7:
                torrents[infohash][src]['pieces_sent'] += 1
    
    # 3. Check tracker announces (direct role info)
    if packet.haslayer(UDP):
        payload = bytes(packet[UDP].payload)
        
        if len(payload) >= 98:
            try:
                protocol_id = struct.unpack(">Q", payload[0:8])[0]
                if protocol_id == 0x41727101980:
                    action = struct.unpack(">I", payload[8:12])[0]
                    
                    if action == 1:  # Announce
                        infohash = binascii.hexlify(payload[16:36]).decode()
                        left = struct.unpack(">Q", payload[64:72])[0]
                        
                        peer_ip = packet[IP].src
                        
                        if infohash not in torrents:
                            torrents[infohash] = {}
                        
                        if peer_ip not in torrents[infohash]:
                            torrents[infohash][peer_ip] = {}
                        
                        if left == 0:
                            torrents[infohash][peer_ip]['role'] = 'seeder'
                            print(f"{peer_ip} is SEEDER (tracker announce)")
                        else:
                            torrents[infohash][peer_ip]['role'] = 'leecher'
                            print(f"{peer_ip} is LEECHER ({left} bytes left)")
            except:
                pass

# Run analysis
sniff(prn=analyze_packet, filter="tcp or udp")
```

---

## Summary: Quick Detection Guide

### To identify which torrent:
1. ✅ **Handshake** → Extract infohash from bytes 28-48
2. ✅ **DHT messages** → Look for "9:info_hash20:"
3. ✅ **Tracker announces** → Extract from announce request

### To identify seeder vs leecher:

| Method | Reliability | How to Detect |
|--------|-------------|---------------|
| **Tracker announce** | ⭐⭐⭐⭐⭐ | Check "left" field: 0 = seeder, >0 = leecher |
| **Bitfield message** | ⭐⭐⭐⭐ | Count 1s: all 1s = seeder, mixed = leecher |
| **Traffic pattern** | ⭐⭐⭐ | Only sends pieces = seeder, sends requests = leecher |
| **Have messages** | ⭐⭐ | Announces all pieces = seeder |

---

## Real-World Example

```
# Capture shows:

[Handshake]
  192.168.1.100:51234 -> 45.67.89.12:6881
  InfoHash: cb91abca6f8d6b34ff8d69540c7dc195e4fb3233
  → This connection belongs to torrent cb91ab...

[Bitfield from 45.67.89.12]
  11111111 11111111 11111111 11111111
  → 45.67.89.12 is a SEEDER (has all pieces)

[Request from 192.168.1.100]
  Message ID: 6 (request)
  Piece: 12
  → 192.168.1.100 is a LEECHER (requesting pieces)

[Piece from 45.67.89.12 to 192.168.1.100]
  Message ID: 7 (piece)
  Size: 16384 bytes
  → SEEDER uploading to LEECHER

CONCLUSION:
  Torrent: cb91abca6f8d6b34ff8d69540c7dc195e4fb3233
  Seeder: 45.67.89.12:6881
  Leecher: 192.168.1.100:51234
```

---

## Using the Tool

```bash
# Run the tracker tool
sudo python3 torrent_tracker.py -i eth0

# Output will show:
# - New torrents discovered (by infohash)
# - New peers for each torrent
# - Whether each peer is seeder or leecher
# - Traffic statistics per peer
```

The tool automatically:
1. Maps all traffic to torrents (by infohash)
2. Identifies seeders and leechers
3. Tracks upload/download behavior
4. Shows summary for each torrent
