import struct
from scapy.all import *

PROTOCOL_ID = 0x41727101980


def parse_udp_tracker(payload, src_ip, src_port):
    if len(payload) < 8:
        return

    # --- CONNECT REQUEST (16 bytes) ---
    if len(payload) >= 16:
        protocol_id = int.from_bytes(payload[0:8], 'big')
        if protocol_id == PROTOCOL_ID:
            action = int.from_bytes(payload[8:12], 'big')
            transaction_id = int.from_bytes(payload[12:16], 'big')
            if action == 0:
                print(f"[CONNECT REQUEST] from {src_ip}:{src_port} transaction_id={transaction_id}")
                return

    # --- CONNECT RESPONSE (16 bytes) ---
    if action == 0 and len(payload) >= 16:
        transaction_id = int.from_bytes(payload[4:8], 'big')
        connection_id = int.from_bytes(payload[8:16], 'big')
        print(f"[CONNECT RESPONSE] transaction_id={transaction_id} connection_id={connection_id}")

    # --- ANNOUNCE REQUEST (98 bytes) ---
    elif action == 1 and len(payload) >= 98:
        transaction_id = int.from_bytes(payload[12:16], 'big')
        info_hash = payload[16:36].hex()
        peer_id = payload[36:56]
        downloaded = int.from_bytes(payload[56:64], 'big')
        left = int.from_bytes(payload[64:72], 'big')
        uploaded = int.from_bytes(payload[72:80], 'big')
        event = int.from_bytes(payload[80:84], 'big')
        port = int.from_bytes(payload[96:98], 'big')

        events = {0: "none", 1: "completed", 2: "started", 3: "stopped"}
        print(f"[ANNOUNCE REQUEST] from {src_ip}:{src_port}")
        print(f"  info_hash={info_hash}")
        print(f"  peer_id={peer_id}")
        print(f"  downloaded={downloaded} left={left} uploaded={uploaded}")
        print(f"  event={events.get(event, event)} port={port}")

    # --- ANNOUNCE RESPONSE ---
    elif action == 1 and len(payload) >= 20:
        transaction_id = int.from_bytes(payload[4:8], 'big')
        interval = int.from_bytes(payload[8:12], 'big')
        leechers = int.from_bytes(payload[12:16], 'big')
        seeders = int.from_bytes(payload[16:20], 'big')
        print(f"[ANNOUNCE RESPONSE] interval={interval} seeders={seeders} leechers={leechers}")

        # parse peers (6 bytes each: 4 IP + 2 port)
        offset = 20
        while offset + 6 <= len(payload):
            ip = '.'.join(str(b) for b in payload[offset:offset + 4])
            port = int.from_bytes(payload[offset + 4:offset + 6], 'big')
            print(f"  peer: {ip}:{port}")
            offset += 6

    # --- SCRAPE REQUEST ---
    elif action == 2 and len(payload) >= 16:
        transaction_id = int.from_bytes(payload[12:16], 'big')
        print(f"[SCRAPE REQUEST] transaction_id={transaction_id}")
        offset = 16
        while offset + 20 <= len(payload):
            info_hash = payload[offset:offset + 20].hex()
            print(f"  info_hash={info_hash}")
            offset += 20

    # --- SCRAPE RESPONSE ---
    elif action == 2 and len(payload) >= 8:
        transaction_id = int.from_bytes(payload[4:8], 'big')
        print(f"[SCRAPE RESPONSE] transaction_id={transaction_id}")
        offset = 8
        while offset + 12 <= len(payload):
            seeders = int.from_bytes(payload[offset:offset + 4], 'big')
            completed = int.from_bytes(payload[offset + 4:offset + 8], 'big')
            leechers = int.from_bytes(payload[offset + 8:offset + 12], 'big')
            print(f"  seeders={seeders} completed={completed} leechers={leechers}")
            offset += 12

    # --- ERROR RESPONSE ---
    elif action == 3 and len(payload) >= 8:
        transaction_id = int.from_bytes(payload[4:8], 'big')
        message = payload[8:].decode(errors='replace')
        print(f"[ERROR] transaction_id={transaction_id} message={message}")


def packet_callback(pkt):
    if pkt.haslayer(UDP) and pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)
        parse_udp_tracker(payload, pkt[IP].src, pkt[UDP].sport)


sniff(filter="udp", prn=packet_callback)
