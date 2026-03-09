import sys
from scapy.all import *
import binascii
import struct
import json
from datetime import datetime
from collections import defaultdict
from base.models import BaseNetworkPacket, NetworkPacket, BitTorrentPacket


class BitTorrentSniffer:
    def __init__(self):
        self.infohashes = set()
        self.peers = set()
        self.nodes = set()
        self.dt = None

    def parse_bencode_simple(self, data):
        try:
            #  extracting basic info, not fully parsing
            result = {}
            if b'1:q' in data:
                if b'4:ping' in data:
                    result['query'] = 'ping'
                elif b'9:find_node' in data:
                    result['query'] = 'find_node'
                elif b'9:get_peers' in data:
                    result['query'] = 'get_peers'
                elif b'13:announce_peer' in data:
                    result['query'] = 'announce_peer'

            if b'1:y1:r' in data:
                result['type'] = 'response'
            elif b'1:y1:q' in data:
                result['type'] = 'query'
            elif b'1:y1:e' in data:
                result['type'] = 'error'

            return result
        except:
            return {}

    def extract_info_hash(self, payload):
        info_hash = ''
        if b'9:info_hash20:' in payload:
            idx = payload.find(b'9:info_hash20:')
            if idx != -1 and len(payload) >= idx + 34:
                info_hash = binascii.hexlify(payload[(idx + 14):(idx + 34)]).decode()
                print(f"  InfoHash: {info_hash}")
                self.infohashes.add(info_hash)
        return info_hash

    def extract_node_id(self, payload):
        node_id_hex = ''
        if b'2:id20:' in payload:
            idx = payload.find(b'2:id20:')
            if idx != -1 and len(payload) >= idx + 27:
                node_id = payload[(idx + 7):(idx + 27)]
                node_id_hex = binascii.hexlify(node_id).decode()
                print(f"  Node ID: {node_id_hex}")
                self.nodes.add(node_id_hex)
        return node_id_hex

    def analyze_packet(self, packet):
        """Main packet analysis dispatcher"""
        try:
            # print("$$$$$$$$$$$$$$$$$$$$$$$\n",
            #       packet.show(dump=True),
            #       "\n$$$$$$$$$$$$$$$$$$$$$$$\n")

            self.dt = datetime.fromtimestamp(packet.time)

            if packet.haslayer(UDP):
                self.analyze_dht(packet)
                self.analyze_tracker_udp(packet)
                self.analyze_pwp_packet(packet)

            if packet.haslayer(TCP):
                self.analyze_tracker_http(packet)
                self.analyze_pwp_packet(packet)
                self.analyze_pex(packet)

        except Exception as e:
            pass

    def make_instance(self, dictionary):
        BaseNetworkPacket.objects.create(
            source_ip=dictionary["src"],
            source_port=dictionary["sport"],
            destination_ip=dictionary["dst"],
            destination_port=dictionary["dport"],
            transport_protocol=dictionary["transport_protocol"],
            protocol=dictionary["protocol"],
            timestamp = self.dt,
            payload=dictionary["payload"],
            payload_dict=dictionary["payload_dict"],

        )
        print("make instance success")
        pass

    def analyze_dht(self, packet):
        try:
            payload = bytes(packet[UDP].payload)

            # DHT messages are bencoded dictionaries
            # if not payload or (payload[0] != ord(b'd') and payload[-1] != ord(b'e')):
            #     return

            if not payload or payload[0] != ord(b'd'):
                return

            # source and destination ips and port
            src = f"{packet[IP].src}:{packet[UDP].sport}"
            dst = f"{packet[IP].dst}:{packet[UDP].dport}"
            node_id = ""
            info_hash = ""
            # Parse basic structure
            parsed = self.parse_bencode_simple(payload)

            if parsed:
                # msg types - response, query, error, unknown
                msg_type = parsed.get('type', 'unknown')
                # query types - ping, find_node, get_peers, announce_peer, ''
                query = parsed.get('query', '')

                # timestamp

                print(f"\n{'=' * 70}")
                print(f"[DHT {msg_type.upper()}] {self.dt.strftime('%H:%M:%S.%f')[:-3]}")
                print(f"  Source: {src}")
                print(f"  Destination: {dst}")

                # Try to extract node ID
                if b'2:id20:' in payload:
                    node_id = self.extract_node_id(payload)

                # Try to extract info_hash for get_peers/announce_peer
                if b'9:info_hash20:' in payload:
                    info_hash = self.extract_info_hash(payload)

                # Show raw payload
                print(f"  Payload : {payload}")

                dict_ = {
                    "src": packet[IP].src,
                    "sport": packet[UDP].sport,
                    "dst": packet[IP].dst,
                    "dport": packet[UDP].dport,
                    "transport_protocol": "udp",
                    "protocol": "dht",
                    "payload": payload,
                    "payload_dict": {
                        "type": "dht",
                        "msg_type": f" DHT {msg_type.upper()}",
                        "msg": msg_type,
                        "msg_dict": {},
                        "info_hash": info_hash,
                        "node_id": node_id
                    }
                }
                self.make_instance(dict_)

        except Exception as e:
            pass

    def analyze_tracker_udp(self, packet):
        """Analyze UDP Tracker Protocol (BEP 15)"""
        try:
            payload = bytes(packet[UDP].payload)
            if len(payload) < 16:
                return

            protocol_id = 0x41727101980
            src = f"{packet[IP].src}:{packet[UDP].sport}"
            dst = f"{packet[IP].dst}:{packet[UDP].dport}"

            first_4_bytes = int.from_bytes(payload[0:4], 'big')
            third_4_bytes = int.from_bytes(payload[8:12], 'big')
            first_8_bytes = int.from_bytes(payload[0:8], 'big')
            # print(f"\n{'=' * 70}")

            if first_8_bytes == protocol_id:
                action = "Connect Request"
                transaction_id = int.from_bytes(payload[12:16], 'big')
                print(f"""
                    [UDP TRACKER] {self.dt.strftime('%H:%M:%S.%f')[:-3]}
                                  """)

                print(f"  Source: {src}")
                print(f"  Destination: {dst}")
                # Show raw payload
                print(f"  Payload : {payload}")
                print(f"""
                action: {action}
                trasaction_id : {transaction_id}

                    """)

                dict_ = {
                    "src": packet[IP].src,
                    "sport": packet[UDP].sport,
                    "dst": packet[IP].dst,
                    "dport": packet[UDP].dport,
                    "transport_protocol": "udp",
                    "protocol": "tracker",
                    "payload": payload,
                    "payload_dict": {
                        "type": "udp tracker",
                        "msg_type": f"  {action}",
                        "msg": "",
                        "msg_dict": {},
                        "transaction_id": transaction_id
                    }
                }
                self.make_instance(dict_)

            elif first_4_bytes == 0:
                action = "Connect Response"
                transaction_id = int.from_bytes(payload[4:8], 'big')
                connection_id = int.from_bytes(payload[8:16], 'big')
                print(f"""
                    [UDP TRACKER] {self.dt.strftime('%H:%M:%S.%f')[:-3]}
                                  """)

                print(f"  Source: {src}")
                print(f"  Destination: {dst}")
                # Show raw payload
                print(f"  Payload : {payload}")
                print(f"""
                action: {action}
                trasaction_id : {transaction_id}
                connection_id :{connection_id}

                    """)
                dict_ = {
                    "src": packet[IP].src,
                    "sport": packet[UDP].sport,
                    "dst": packet[IP].dst,
                    "dport": packet[UDP].dport,
                    "transport_protocol": "udp",
                    "protocol": "tracker",
                    "payload": payload,
                    "payload_dict": {
                        "type": "udp tracker",
                        "msg_type": f"  {action}",
                        "msg": "",
                        "msg_dict": {},
                        "transaction_id": transaction_id,
                        "connection_id": connection_id

                    }
                }
                self.make_instance(dict_)

            if third_4_bytes == 1 and len(payload) >= 98:
                action = "Announce Request"

                connection_id = first_8_bytes
                transaction_id = int.from_bytes(payload[12:16], 'big')
                info_hash = payload[16:36].hex()
                peer_id = payload[36:56]
                downloaded = int.from_bytes(payload[56:64], 'big')
                left = int.from_bytes(payload[64:72], 'big')
                uploaded = int.from_bytes(payload[72:80], 'big')
                event = int.from_bytes(payload[80:84], 'big')
                port = int.from_bytes(payload[96:98], 'big')
                print(f"""
                    [UDP TRACKER] {self.dt.strftime('%H:%M:%S.%f')[:-3]}
                                  """)

                print(f"  Source: {src}")
                print(f"  Destination: {dst}")
                # Show raw payload
                print(f"  Payload : {payload}")
                print(f"""
                action: {action}
                trasaction_id : {transaction_id}
                connection_id :{connection_id}
                info_hash : {info_hash}
                peer_id : {peer_id}
                downloaded : {downloaded}
                left: {left}
                uploaded : {uploaded}
                event : {event}
                port : {port}

                    """)
                dict_ = {
                    "src": packet[IP].src,
                    "sport": packet[UDP].sport,
                    "dst": packet[IP].dst,
                    "dport": packet[UDP].dport,
                    "transport_protocol": "udp",
                    "protocol": "tracker",
                    "payload": payload,
                    "payload_dict": {
                        "type": "udp tracker",
                        "msg_type": f"  {action}",
                        "msg": "",
                        "msg_dict": {},
                        "transaction_id": transaction_id,
                        "connection_id": connection_id,

                        "info_hash": info_hash,
                        "peer_id": peer_id,
                        "downloaded": downloaded,
                        "left": left,
                        "uploaded": uploaded,
                        "event": event,
                        "port": port,
                    }
                }
                self.make_instance(dict_)


            elif first_4_bytes == 1 and len(payload) >= 20:
                action = "Announce Response"

                transaction_id = int.from_bytes(payload[4:8], 'big')
                interval = int.from_bytes(payload[8:12], 'big')
                leechers = int.from_bytes(payload[12:16], 'big')
                seeders = int.from_bytes(payload[16:20], 'big')
                offset = 20
                while offset + 6 <= len(payload):
                    ip = '.'.join(str(b) for b in payload[offset:offset + 4])
                    port = int.from_bytes(payload[offset + 4:offset + 6], 'big')
                    print(f"  peer: {ip}:{port}")
                    offset += 6
                print(f"""
                    [UDP TRACKER] {self.dt.strftime('%H:%M:%S.%f')[:-3]}
                                  """)

                print(f"  Source: {src}")
                print(f"  Destination: {dst}")
                # Show raw payload
                print(f"  Payload : {payload}")
                print(f"""
                action: {action}
                trasaction_id : {transaction_id}

                interval : {interval}
                leechers : {leechers}
                seeders: {seeders}
                    """)

                dict_ = {
                    "src": packet[IP].src,
                    "sport": packet[UDP].sport,
                    "dst": packet[IP].dst,
                    "dport": packet[UDP].dport,
                    "transport_protocol": "udp",
                    "protocol": "tracker",
                    "payload": payload,
                    "payload_dict": {
                        "type": "udp tracker",
                        "msg_type": f"  {action}",
                        "msg": "",
                        "msg_dict": {},
                        "transaction_id": transaction_id,
                        "interval": interval,
                        "leechers": leechers,
                        "seeders": seeders,
                    }
                }
                self.make_instance(dict_)

            if third_4_bytes == 2 and len(payload) >= 16:
                action = "SCRAPE Request"
                transaction_id = int.from_bytes(payload[12:16], 'big')
                print(f"[SCRAPE REQUEST] transaction_id={transaction_id}")
                offset = 16
                while offset + 20 <= len(payload):
                    info_hash = payload[offset:offset + 20].hex()
                    print(f"  info_hash={info_hash}")
                    offset += 20
                print(f"""
                    [UDP TRACKER] {self.dt.strftime('%H:%M:%S.%f')[:-3]}
                                  """)

                print(f"  Source: {src}")
                print(f"  Destination: {dst}")
                # Show raw payload
                print(f"  Payload : {payload}")
                print(f"""
                action: {action}
                trasaction_id : {transaction_id}

                    """)
                dict_ = {
                    "src": packet[IP].src,
                    "sport": packet[UDP].sport,
                    "dst": packet[IP].dst,
                    "dport": packet[UDP].dport,
                    "transport_protocol": "udp",
                    "protocol": "tracker",
                    "payload": payload,
                    "payload_dict": {
                        "type": "udp tracker",
                        "msg_type": f"  {action}",
                        "msg": "",
                        "msg_dict": {},
                        "transaction_id": transaction_id,
                    }
                }
                self.make_instance(dict_)


            elif first_4_bytes == 2 and len(payload) >= 8:
                action = "SCRAPE Response"

                transaction_id = int.from_bytes(payload[4:8], 'big')
                offset = 8
                while offset + 12 <= len(payload):
                    seeders = int.from_bytes(payload[offset:offset + 4], 'big')
                    completed = int.from_bytes(payload[offset + 4:offset + 8], 'big')
                    leechers = int.from_bytes(payload[offset + 8:offset + 12], 'big')
                    offset += 12
                print(f"""
                    [UDP TRACKER] {self.dt.strftime('%H:%M:%S.%f')[:-3]}
                                  """)

                print(f"  Source: {src}")
                print(f"  Destination: {dst}")
                # Show raw payload
                print(f"  Payload : {payload}")
                print(f"""
                action: {action}
                trasaction_id : {transaction_id}

                    """)
                dict_ = {
                    "src": packet[IP].src,
                    "sport": packet[UDP].sport,
                    "dst": packet[IP].dst,
                    "dport": packet[UDP].dport,
                    "transport_protocol": "udp",
                    "protocol": "tracker",
                    "payload": payload,
                    "payload_dict": {
                        "type": "udp tracker",
                        "msg_type": f"  {action}",
                        "msg": "",
                        "msg_dict": {},
                        "transaction_id": transaction_id,

                    }
                }
                self.make_instance(dict_)

            if first_4_bytes == 3 and len(payload) >= 8:
                transaction_id = int.from_bytes(payload[4:8], 'big')
                message = payload[8:].decode(errors='replace')
                print(f"[ERROR] transaction_id={transaction_id} message={message}")



        except Exception as e:
            pass

    def analyze_tracker_http(self, packet):
        """Analyze HTTP Tracker requests"""
        try:
            if not packet.haslayer(Raw):
                return

            payload = bytes(packet[Raw].load)
            src = f"{packet[IP].src}:{packet[TCP].sport}"
            dst = f"{packet[IP].dst}:{packet[TCP].dport}"
            action = ""
            hosts_list = []
            info_hash = ""
            # Check for HTTP tracker requests
            if b'GET /announce' in payload or b'GET /scrape' in payload:

                print(f"\n{'=' * 70}")
                print(f"[HTTP TRACKER] {self.dt.strftime('%H:%M:%S.%f')[:-3]}")
                print(f"  Source: {src}")
                print(f"  Destination: {dst}")

                # Determine type
                if b'GET /announce' in payload:
                    print(f"  Type: Announce")
                    action = "Announce"
                elif b'GET /scrape' in payload:
                    print(f"  Type: Scrape")
                    action = "Scrape"

                # Try to extract info_hash from URL
                if b'info_hash=' in payload:
                    try:
                        # Find info_hash in the request
                        info_hash = self.extract_info_hash(payload)
                        # URL-encoded infohash is typically 60 chars (20 bytes * 3 for %XX)
                        # This is simplified - real parsing would decode URL encoding
                        print(f"  Contains info_hash parameter")
                    except:
                        pass

                # Extract tracker URL/host
                if b'Host: ' in payload:
                    host_start = payload.find(b'Host: ') + 6
                    host_end = payload.find(b'\r\n', host_start)
                    if host_end != -1:
                        host = payload[host_start:host_end].decode('utf-8', errors='ignore')
                        print(f"  Tracker: {host}")
                        hosts_list.append(host)

                dict_ = {
                    "src": packet[IP].src,
                    "sport": packet[TCP].sport,
                    "dst": packet[IP].dst,
                    "dport": packet[TCP].dport,
                    "transport_protocol": "udp",
                    "protocol": "tracker",
                    "payload": payload,
                    "payload_dict": {
                        "type": "udp tracker",
                        "msg_type": f"  {action}",
                        "msg": "",
                        "msg_dict": {},
                        "trackers": hosts_list,
                        "info_hash": info_hash,
                    }
                }
                self.make_instance(dict_)
        except Exception as e:
            pass

    def analyze_pex(self, packet):
        """Analyze PEX (Peer Exchange) - Extended Protocol"""
        try:
            if not packet.haslayer(Raw):
                return

            payload = bytes(packet[Raw].load)
            if len(payload) < 5:
                return

            # Check for extended protocol messages
            # Message format: <length><message_id><extended_message_id><payload>
            try:
                msg_length = struct.unpack(">I", payload[0:4])[0]

                if msg_length > 0 and msg_length < 100000 and len(payload) >= 5:
                    msg_id = payload[4]

                    # Message ID 20 = Extended protocol
                    if msg_id == 20 and len(payload) >= 6:
                        ext_msg_id = payload[5]

                        src = f"{packet[IP].src}:{packet[TCP].sport}"
                        dst = f"{packet[IP].dst}:{packet[TCP].dport}"

                        dt = datetime.fromtimestamp(packet.time)
                        time_str = dt.strftime('%H:%M:%S.%f')[:-3]
                        action = ""
                        msg_type = ""
                        # Extended message ID 0 = Handshake,1 = ut_pex (Peer Exchange),2 = ut_metadata

                        if ext_msg_id == 0:
                            print(f"\n{'=' * 70}")
                            print(f"[EXTENDED HANDSHAKE] {time_str}")
                            print(f"  Source: {src}")
                            print(f"  Destination: {dst}")
                            print(f"  Type: Extension Protocol Handshake")
                            action = "EXTENDED HANDSHAKE"
                            msg_type = "Extension Protocol Handshake"
                            # Try to parse the bencoded dictionary
                            ext_payload = payload[6:]
                            if ext_payload and ext_payload[0] == ord(b'd'):
                                # Check for ut_pex support
                                if b'ut_pex' in ext_payload:
                                    print(f"  Supports: PEX (Peer Exchange)")
                                if b'ut_metadata' in ext_payload:
                                    print(f"  Supports: Metadata Exchange")


                        elif ext_msg_id == 1:
                            print(f"\n{'=' * 70}")
                            print(f"[PEX - PEER EXCHANGE] {time_str}")
                            print(f"  Source: {src}")
                            print(f"  Destination: {dst}")
                            print(f"  Type: ut_pex (Peer Exchange)")
                            action = "PEER EXCHANGE"
                            msg_type = "ut_pex (Peer Exchange)"
                            # PEX payload is bencoded
                            ext_payload = payload[6:]

                            # Try to count peers
                            # PEX sends peer lists in 'added' and 'added.f' fields
                            if b'5:added' in ext_payload:
                                # Find the peer list
                                # Format: 5:added<length>:<compact_peer_list>
                                # Each peer is 6 bytes (4 bytes IP + 2 bytes port)
                                try:
                                    added_idx = ext_payload.find(b'5:added')
                                    # This is simplified - proper bencode parsing needed
                                    print(f"  Peers being exchanged: (peer list present)")
                                except:
                                    pass


                        elif ext_msg_id == 2:
                            print(f"\n{'=' * 70}")
                            print(f"[METADATA EXCHANGE] {time_str}")
                            print(f"  Source: {src}")
                            print(f"  Destination: {dst}")
                            print(f"  Type: ut_metadata (Metadata Exchange)")
                            action = "METADATA EXCHANGE"
                            msg_type = "ut_metadata (Metadata Exchange)"

                        dict_ = {
                            "src": packet[IP].src,
                            "sport": packet[TCP].sport,
                            "dst": packet[IP].dst,
                            "dport": packet[TCP].dport,
                            "transport_protocol": "udp",
                            "protocol": "tracker",
                            "payload": payload,
                            "payload_dict": {
                                "type": "udp tracker",
                                "msg_type": f"  {action}",
                                "msg": msg_type,
                                "msg_dict": {},
                            }
                        }
                        self.make_instance(dict_)


            except struct.error:
                pass

        except Exception as e:
            pass

    def analyze_pwp_packet(self, packet):
        """Analyze Peer Wire Protocol traffic"""
        try:
            if not packet.haslayer(Raw):
                return

            payload = bytes(packet[Raw].load)

            if len(payload) == 0:
                return

            src = f"{packet[IP].src}:{packet[TCP].sport}"
            dst = f"{packet[IP].dst}:{packet[TCP].dport}"

            # Check for BitTorrent handshake
            if len(payload) >= 68 and payload[0] == 19 and payload[1:20] == b"BitTorrent protocol":
                info_hash = binascii.hexlify(payload[28:48]).decode()
                peer_id = payload[48:68]

                print(f"\n{'=' * 70}")
                print(f"[HANDSHAKE] {datetime.now().strftime('%H:%M:%S.%f')[:-3]}")
                print(f"  Source: {src}")
                print(f"  Destination: {dst}")
                print(f"  InfoHash: {info_hash}")
                print(f"  Peer ID: {binascii.hexlify(peer_id).decode()}")

                dict_ = {
                    "src": packet[IP].src,
                    "sport": packet[TCP].sport,
                    "dst": packet[IP].dst,
                    "dport": packet[TCP].dport,
                    "transport_protocol": "udp",
                    "protocol": "tracker",
                    "payload": payload,
                    "payload_dict": {
                        "type": "udp tracker",
                        "msg_type": f"PWP HANDSHAKE",
                        "msg": "",
                        "msg_dict": {},
                        "info_hash": info_hash,
                        "peer_id": f"{binascii.hexlify(peer_id).decode()}",

                    }
                }
                self.make_instance(dict_)

                # Check for extension support
                reserved = payload[20:28]
                if reserved[5] & 0x10:
                    print(f"  Extensions: Supported (DHT, Extension Protocol, etc.)")

                self.infohashes.add(info_hash)
                self.peers.add(f"{packet[IP].src}:{packet[TCP].sport}")

            # Check for PWP messages (after handshake)

            else:
                length = int.from_bytes(payload[:4], 'big')
                msg_id = payload[4]

                msg_types = {
                    0: "choke",
                    1: "unchoke",
                    2: "interested",
                    3: "not interested",
                    4: "have",
                    5: "bitfield",
                    6: "request",
                    7: "piece",  # <-- actual data
                    8: "cancel"
                }

                msg_name = msg_types.get(msg_id, f"unknown({msg_id})")

                if msg_id == 7:
                    # piece message: index(4) + offset(4) + data
                    index = int.from_bytes(payload[5:9], 'big')
                    offset = int.from_bytes(payload[9:13], 'big')
                    data_len = length - 9
                    print(
                        f"[PIECE] {src} -> {dst} | index={index} offset={offset} data={data_len} bytes")

                    dict_ = {
                        "src": packet[IP].src,
                        "sport": packet[TCP].sport,
                        "dst": packet[IP].dst,
                        "dport": packet[TCP].dport,
                        "transport_protocol": "udp/tcp",
                        "protocol": "PWP Packet",
                        "payload": payload,
                        "payload_dict": {
                            "type": "pwp Packet",
                            "msg_type": f"PIECE",
                            "msg": "",
                            "msg_dict": {},
                            "index": index,
                            "offset": offset,
                            "data": data_len,

                        }
                    }
                    self.make_instance(dict_)
                else:
                    print(f"[{msg_name.upper()}] {src} -> {dst}")


        except Exception as e:
            pass

    def catching_all_piece(self, packet):
        try:
            if not packet.haslayer(TCP):
                return
            if not packet.haslayer(Raw):
                return

            payload = bytes(packet[Raw].load)

            if len(payload) == 0:
                return

        except:
            pass


def main():
    sniffer = BitTorrentSniffer()
    bpf_filter = "udp or tcp"
    is_pcap = True
    try:
        if is_pcap:
            pcap_file = "adele.pcap"
            sniff(
                offline=pcap_file,
                prn=sniffer.analyze_packet,
                store=0
            )
        else:
            sniff(
                filter=bpf_filter,
                prn=sniffer.analyze_packet,
                store=0
            )
    except KeyboardInterrupt:
        print("\n\nStopping capture...")
