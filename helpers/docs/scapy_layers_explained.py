#!/usr/bin/env python3
"""
Understanding Scapy Packet Layers - Educational Guide
Demonstrates how packet[UDP], packet[TCP], etc. work
"""

from scapy.all import *

print("""
╔═══════════════════════════════════════════════════════════════════╗
║         Understanding Scapy Packet Layer Access                  ║
╚═══════════════════════════════════════════════════════════════════╝
""")

# ============================================================================
# CONCEPT 1: Network packets are like LAYERS of an onion
# ============================================================================

print("\n" + "="*70)
print("CONCEPT 1: Packets Have Layers (Like an Onion)")
print("="*70)

print("""
A network packet is built in layers:

    ┌─────────────────────────────────────┐
    │  Application Layer (HTTP, DNS, etc) │  ← Your data
    ├─────────────────────────────────────┤
    │  Transport Layer (TCP/UDP)          │  ← Port numbers
    ├─────────────────────────────────────┤
    │  Network Layer (IP)                 │  ← IP addresses
    ├─────────────────────────────────────┤
    │  Link Layer (Ethernet)              │  ← MAC addresses
    └─────────────────────────────────────┘

Each layer wraps the layer above it.
""")

# ============================================================================
# CONCEPT 2: How to Access Layers in Scapy
# ============================================================================

print("\n" + "="*70)
print("CONCEPT 2: Accessing Layers in Scapy")
print("="*70)

# Create a sample packet
print("\n# Creating a sample DNS query packet:")
print("packet = IP(dst='8.8.8.8')/UDP(dport=53)/DNS(qd=DNSQR(qname='google.com'))")

packet = IP(dst='8.8.8.8')/UDP(dport=53)/DNS(qd=DNSQR(qname='google.com'))

print("\n# Show the packet structure:")
print("packet.show()")
print("-" * 70)
packet.show()

print("\n" + "="*70)
print("THREE WAYS TO ACCESS LAYERS:")
print("="*70)

# Method 1: Using brackets with layer name
print("\n1. Using BRACKETS: packet[UDP]")
print("   This accesses the UDP layer of the packet")
print(f"   packet[UDP] = {packet[UDP]}")
print(f"   Type: {type(packet[UDP])}")

# Method 2: Using getlayer()
print("\n2. Using getlayer(): packet.getlayer(UDP)")
print("   Same as packet[UDP], just more explicit")
print(f"   packet.getlayer(UDP) = {packet.getlayer(UDP)}")

# Method 3: Using haslayer() to check first
print("\n3. Using haslayer() to check: if packet.haslayer(UDP)")
print(f"   packet.haslayer(UDP) = {packet.haslayer(UDP)}")
print(f"   packet.haslayer(TCP) = {packet.haslayer(TCP)}")

# ============================================================================
# CONCEPT 3: Accessing Layer Fields
# ============================================================================

print("\n" + "="*70)
print("CONCEPT 3: Accessing Fields Within Layers")
print("="*70)

print("\nOnce you have a layer, you can access its fields:")

print("\n# IP Layer Fields:")
print(f"packet[IP].src    = {packet[IP].src}    # Source IP")
print(f"packet[IP].dst    = {packet[IP].dst}    # Destination IP")
print(f"packet[IP].proto  = {packet[IP].proto}  # Protocol number (17=UDP)")
print(f"packet[IP].ttl    = {packet[IP].ttl}    # Time to live")

print("\n# UDP Layer Fields:")
print(f"packet[UDP].sport = {packet[UDP].sport} # Source port")
print(f"packet[UDP].dport = {packet[UDP].dport} # Destination port")
print(f"packet[UDP].len   = {packet[UDP].len}   # UDP length")

print("\n# DNS Layer Fields:")
print(f"packet[DNS].qd.qname = {packet[DNS].qd.qname} # Query name")

# ============================================================================
# CONCEPT 4: Why Use packet[UDP] Instead of Other Methods?
# ============================================================================

print("\n" + "="*70)
print("CONCEPT 4: Why packet[UDP] is Convenient")
print("="*70)

print("""
Instead of manually parsing bytes, Scapy does it for you:

WITHOUT Scapy (raw bytes):
    payload = packet_bytes[42:]  # Skip IP and UDP headers
    sport = struct.unpack('>H', payload[0:2])[0]
    dport = struct.unpack('>H', payload[2:4])[0]
    # Complex, error-prone!

WITH Scapy:
    sport = packet[UDP].sport  # Simple!
    dport = packet[UDP].dport  # Easy to read!
""")

# ============================================================================
# CONCEPT 5: Practical Examples
# ============================================================================

print("\n" + "="*70)
print("CONCEPT 5: Practical Examples")
print("="*70)

print("\n# Example 1: Check if packet is UDP")
print("if packet.haslayer(UDP):")
print("    print('This is a UDP packet')")

if packet.haslayer(UDP):
    print("    → This is a UDP packet ✓")

print("\n# Example 2: Get UDP ports")
print("if packet.haslayer(UDP):")
print("    src_port = packet[UDP].sport")
print("    dst_port = packet[UDP].dport")
print(f"    → Source: {packet[UDP].sport}, Destination: {packet[UDP].dport}")

print("\n# Example 3: Access payload data")
print("if packet.haslayer(UDP):")
print("    payload = bytes(packet[UDP].payload)")
print(f"    → Payload: {bytes(packet[UDP].payload)[:50]}...")

print("\n# Example 4: Check multiple layers")
print("if packet.haslayer(IP) and packet.haslayer(UDP):")
print(f"    → IP: {packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport}")

# ============================================================================
# CONCEPT 6: Real-world BitTorrent Example
# ============================================================================

print("\n" + "="*70)
print("CONCEPT 6: BitTorrent DHT Detection Example")
print("="*70)

print("""
def analyze_packet(packet):
    # Check if this is a UDP packet
    if packet.haslayer(UDP):
        
        # Get UDP source and destination ports
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        
        # Get the payload (the actual data)
        payload = bytes(packet[UDP].payload)
        
        # DHT messages start with 'd' (bencode dictionary)
        if payload and payload[0] == ord(b'd'):
            print(f"DHT packet found!")
            print(f"From: {packet[IP].src}:{sport}")
            print(f"To: {packet[IP].dst}:{dport}")
            print(f"Payload: {payload[:50]}")
""")

# ============================================================================
# CONCEPT 7: Common Layer Names
# ============================================================================

print("\n" + "="*70)
print("CONCEPT 7: Common Scapy Layer Names")
print("="*70)

print("""
Common layers you can access with packet[LAYER]:

Network Layers:
- Ether    : Ethernet (MAC addresses)
- IP       : IPv4 (IP addresses)
- IPv6     : IPv6
- ARP      : Address Resolution Protocol

Transport Layers:
- TCP      : Transmission Control Protocol (packet[TCP].sport, packet[TCP].dport)
- UDP      : User Datagram Protocol (packet[UDP].sport, packet[UDP].dport)
- ICMP     : Internet Control Message Protocol

Application Layers:
- DNS      : Domain Name System
- HTTP     : Hypertext Transfer Protocol
- Raw      : Raw data/payload (packet[Raw].load)

Custom:
- You can also define your own layers!
""")

# ============================================================================
# CONCEPT 8: Handling Missing Layers
# ============================================================================

print("\n" + "="*70)
print("CONCEPT 8: Handling Missing Layers (IMPORTANT!)")
print("="*70)

print("""
ALWAYS check if a layer exists before accessing it:

BAD (will crash if no UDP):
    sport = packet[UDP].sport  # ERROR if packet has no UDP layer!

GOOD:
    if packet.haslayer(UDP):
        sport = packet[UDP].sport  # Safe!

ALSO GOOD (returns None if layer doesn't exist):
    udp_layer = packet.getlayer(UDP)
    if udp_layer:
        sport = udp_layer.sport
""")

# Demonstrate the error
print("\n# Let's try accessing a layer that doesn't exist:")
print("tcp_packet = IP(dst='1.1.1.1')/TCP(dport=80)")
tcp_packet = IP(dst='1.1.1.1')/TCP(dport=80)

print(f"tcp_packet.haslayer(TCP) = {tcp_packet.haslayer(TCP)}  # True")
print(f"tcp_packet.haslayer(UDP) = {tcp_packet.haslayer(UDP)}  # False")

print("\n# Safe way:")
print("if tcp_packet.haslayer(UDP):")
print("    print(tcp_packet[UDP].sport)")
print("else:")
print("    print('No UDP layer')")

if tcp_packet.haslayer(UDP):
    print(tcp_packet[UDP].sport)
else:
    print("    → No UDP layer ✓")

# ============================================================================
# CONCEPT 9: Complete Example - Packet Analysis Function
# ============================================================================

print("\n" + "="*70)
print("CONCEPT 9: Complete Packet Analysis Function")
print("="*70)

print("""
def analyze_any_packet(packet):
    \"\"\"Analyze any packet and show its layers\"\"\"
    
    # Check Ethernet layer
    if packet.haslayer(Ether):
        print(f"[Ethernet] {packet[Ether].src} -> {packet[Ether].dst}")
    
    # Check IP layer
    if packet.haslayer(IP):
        print(f"[IP] {packet[IP].src} -> {packet[IP].dst}")
    
    # Check TCP layer
    if packet.haslayer(TCP):
        print(f"[TCP] Port {packet[TCP].sport} -> {packet[TCP].dport}")
        print(f"      Flags: {packet[TCP].flags}")
    
    # Check UDP layer
    if packet.haslayer(UDP):
        print(f"[UDP] Port {packet[UDP].sport} -> {packet[UDP].dport}")
        print(f"      Length: {packet[UDP].len}")
    
    # Check for payload
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        print(f"[Payload] {len(payload)} bytes")
        print(f"          {payload[:50]}...")
""")

def analyze_any_packet(packet):
    """Analyze any packet and show its layers"""
    
    print("\nAnalyzing packet:")
    print("-" * 50)
    
    # Check Ethernet layer
    if packet.haslayer(Ether):
        print(f"[Ethernet] {packet[Ether].src} -> {packet[Ether].dst}")
    
    # Check IP layer
    if packet.haslayer(IP):
        print(f"[IP] {packet[IP].src} -> {packet[IP].dst}")
    
    # Check TCP layer
    if packet.haslayer(TCP):
        print(f"[TCP] Port {packet[TCP].sport} -> {packet[TCP].dport}")
        print(f"      Flags: {packet[TCP].flags}")
    
    # Check UDP layer
    if packet.haslayer(UDP):
        print(f"[UDP] Port {packet[UDP].sport} -> {packet[UDP].dport}")
        print(f"      Length: {packet[UDP].len}")
    
    # Check for payload
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        print(f"[Payload] {len(payload)} bytes")
        print(f"          {payload[:50]}...")

# Test it
print("\nTesting with our DNS packet:")
analyze_any_packet(packet)

# ============================================================================
# SUMMARY
# ============================================================================

print("\n" + "="*70)
print("SUMMARY - Key Takeaways")
print("="*70)

print("""
1. packet[UDP] accesses the UDP layer of a packet
   - It's like saying "give me the UDP part of this packet"

2. Always check if layer exists first:
   if packet.haslayer(UDP):
       do_something(packet[UDP])

3. Access fields with dot notation:
   packet[UDP].sport   # Source port
   packet[UDP].dport   # Destination port
   packet[UDP].len     # UDP length

4. Get payload data:
   payload = bytes(packet[UDP].payload)

5. Common pattern in packet analysis:
   if packet.haslayer(UDP):
       src = f"{packet[IP].src}:{packet[UDP].sport}"
       dst = f"{packet[IP].dst}:{packet[UDP].dport}"
       data = bytes(packet[UDP].payload)

This is much easier than parsing raw bytes manually!
""")

print("\n" + "="*70)
print("Want to try it yourself? Run:")
print("  from scapy.all import *")
print("  packet = sniff(count=1)[0]")
print("  packet.show()")
print("  packet[IP].src if packet.haslayer(IP) else None")
print("="*70 + "\n")
