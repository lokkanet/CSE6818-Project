import struct
import hashlib
import bencodepy
from scapy.all import rdpcap, TCP

# Load torrent metadata
with open("target.torrent", "rb") as f:
    torrent = bencodepy.decode(f.read())

info = torrent[b"info"]
piece_length = info[b"piece length"]
pieces_hashes = [info[b"pieces"][i:i+20] for i in range(0, len(info[b"pieces"]), 20)]

# Buffer to collect blocks per piece
piece_buffer = {}

# Parse PCAP
packets = rdpcap("capture.pcap")
for pkt in packets:
    if TCP in pkt and pkt[TCP].payload:
        payload = bytes(pkt[TCP].payload)
        # Parse BT messages from payload stream
        # (requires reassembling TCP stream first)
        # Extract PIECE messages (msg_id == 7)
        # piece_index, begin, block = struct.unpack(...)
        pass

# Verify and write pieces
for idx, blocks in piece_buffer.items():
    piece_data = reassemble_blocks(blocks)
    sha1 = hashlib.sha1(piece_data).digest()
    if sha1 == pieces_hashes[idx]:
        print(f"Piece {idx} verified")
        write_to_output(idx, piece_data, piece_length)