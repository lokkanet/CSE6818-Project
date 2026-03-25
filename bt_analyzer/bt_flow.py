import struct
import os
import hashlib
import requests
from collections import defaultdict
from tcp_stream import TCPStream

# \x13 is byte hexadecimal value 13 equals 19 in decimal
BT_HANDSHAKE = b"\x13BitTorrent protocol"
# length 1 + 19 + 8 + 20 + 20
HANDSHAKE_LEN = 68

MSG_NAMES = {
    0: "CHOKE", 1: "UNCHOKE", 2: "INTERESTED",
    3: "NOT_INTERESTED", 4: "HAVE", 5: "BITFIELD",
    6: "REQUEST", 7: "PIECE", 8: "CANCEL",
    9: "PORT",
}


class BTFlowParser:
    def __init__(self, flow_id):
        self.flow_id = flow_id
        self.stream = TCPStream()
        self.handshake_done = False
        self.info_hash = None
        self.torrent_file_path = ""
        self.peer_id = None
        self.messages = []
        self.piece_blocks = defaultdict(dict)

    def feed(self, seq, data):
        self.stream.add(seq, data)
        self._parse()

    def _parse(self):
        if not self.handshake_done:
            self._try_handshake()
        while self.handshake_done:
            if not self._try_message():
                break

    def _try_handshake(self):
        if self.stream.available() < HANDSHAKE_LEN:
            return
        if self.stream.peek(len(BT_HANDSHAKE)) != BT_HANDSHAKE:
            return
        raw = self.stream.read(HANDSHAKE_LEN)
        self.info_hash = raw[28:48].hex()
        self.peer_id = raw[48:68]
        self.handshake_done = True
        self._torrent_file_download()
        si, sp, di, dp = self.flow_id
        print(f"\n[HANDSHAKE] {si}:{sp} -> {di}:{dp}")
        print(f"  info_hash : {self.info_hash}")
        print(f"  peer_id   : {self.peer_id!r}")

    def _torrent_file_download(self):
        # if os.path.exists(f"{self.info_hash}.torrent"):
        #     self.torrent_file_path = f"{self.info_hash}.torrent"
        #     return
        with requests.get(f"https://itorrents.org/torrent/{self.info_hash}.torrent") as response:
            response.raise_for_status()
            with open(f"{self.info_hash}.torrent", 'wb') as file:
                file.write(response.content)

        self.torrent_file_path = f"{self.info_hash}.torrent"

    def _try_message(self):
        if self.stream.available() < 4:
            return False

        msg_len = struct.unpack("!I", self.stream.peek(4))[0]

        if msg_len == 0:  # keepalive
            self.stream.read(4)
            self.messages.append({"type": "KEEPALIVE"})
            return True

        if msg_len > 2 * 1024 * 1024:  # sanity guard
            return False

        if self.stream.available() < 4 + msg_len:
            return False

        self.stream.read(4)
        msg_data = self.stream.read(msg_len)
        msg_id = msg_data[0]
        payload = msg_data[1:]

        msg = {"type": MSG_NAMES.get(msg_id, f"UNKNOWN({msg_id})"),
               "msg_id": msg_id, "length": msg_len}

        if msg_id == 4 and len(payload) >= 4:  # HAVE
            msg["piece_index"] = struct.unpack("!I", payload[:4])[0]

        elif msg_id == 5:  # BITFIELD
            msg["pieces_have"] = sum(bin(b).count("1") for b in payload)

        elif msg_id == 6 and len(payload) >= 12:  # REQUEST
            msg["piece_index"], msg["begin"], msg["block_length"] = \
                struct.unpack("!III", payload[:12])

        elif msg_id == 7 and len(payload) >= 8:  # PIECE ← what we want
            idx = struct.unpack("!I", payload[0:4])[0]
            begin = struct.unpack("!I", payload[4:8])[0]
            data = payload[8:]
            msg.update({"piece_index": idx, "begin": begin,
                        "block_length": len(data),
                        "block_sha1": hashlib.sha1(data).hexdigest()})
            self.piece_blocks[idx][begin] = data  # buffer for reconstruction

        elif msg_id == 8 and len(payload) >= 12:  # CANCEL
            msg["piece_index"], msg["begin"], msg["block_length"] = \
                struct.unpack("!III", payload[:12])

        self.messages.append(msg)
        return True
