def parse_dht_packet(payload_bytes):
    try:
        decoded = bencodepy.decode(payload_bytes)
    except Exception as e:
        print(f"Failed to decode bencoding: {e}")
        return None

    msg_type = decoded.get(b'y', b'').decode('utf-8', errors='ignore')

    result = {'type': msg_type}

    # Query (request) — contains key 'a' (arguments) and 'q' (query type)
    if msg_type == 'q':
        query_type = decoded.get(b'q', b'').decode('utf-8', errors='ignore')
        args = decoded.get(b'a', {})
        result['query'] = query_type

        # Sender node ID (present in all queries)
        if b'id' in args:
            result['node_id'] = args[b'id'].hex()

        if query_type == 'get_peers':
            if b'info_hash' in args:
                result['info_hash'] = args[b'info_hash'].hex()
                print(f"[get_peers] info_hash: {result['info_hash']}")

        elif query_type == 'announce_peer':
            if b'info_hash' in args:
                result['info_hash'] = args[b'info_hash'].hex()
            if b'port' in args:
                result['port'] = args[b'port']
            if b'implied_port' in args:
                result['implied_port'] = args[b'implied_port']
            print(f"[announce_peer] info_hash: {result.get('info_hash')} port: {result.get('port')}")

        elif query_type == 'find_node':
            if b'target' in args:
                result['target'] = args[b'target'].hex()
            print(f"[find_node] target: {result.get('target')}")

        elif query_type == 'ping':
            print(f"[ping] from node: {result.get('node_id')}")

    # Response — contains key 'r'
    elif msg_type == 'r':
        resp = decoded.get(b'r', {})
        result['response'] = {}

        if b'id' in resp:
            result['response']['node_id'] = resp[b'id'].hex()

        # find_node / get_peers response contains 'nodes'
        if b'nodes' in resp:
            result['response']['nodes'] = parse_compact_nodes(resp[b'nodes'])

        # get_peers response may contain 'values' (peer list) or 'nodes'
        if b'values' in resp:
            result['response']['peers'] = parse_compact_peers(resp[b'values'])

        # get_peers response contains a token
        if b'token' in resp:
            result['response']['token'] = resp[b'token'].hex()

        print(f"[response] from node: {result['response'].get('node_id')}")

    # Error — contains key 'e'
    elif msg_type == 'e':
        error = decoded.get(b'e', [])
        if len(error) >= 2:
            result['error_code'] = error[0]
            result['error_msg'] = error[1].decode('utf-8', errors='ignore')
        print(f"[error] code: {result.get('error_code')} msg: {result.get('error_msg')}")

    else:
        print(f"Unknown message type: {msg_type}")

    # Transaction ID and version (present in all messages)
    if b't' in decoded:
        result['transaction_id'] = decoded[b't'].hex()
    if b'v' in decoded:
        result['version'] = decoded[b'v']

    return result


def parse_compact_nodes(raw_nodes):
    """Parse compact node info: 20 bytes node_id + 4 bytes IP + 2 bytes port"""
    nodes = []
    for i in range(0, len(raw_nodes), 26):
        if i + 26 > len(raw_nodes):
            break
        chunk = raw_nodes[i:i + 26]
        node_id = chunk[:20].hex()
        ip = ".".join(str(b) for b in chunk[20:24])
        port = int.from_bytes(chunk[24:26], 'big')
        nodes.append({'node_id': node_id, 'ip': ip, 'port': port})
    return nodes


def parse_compact_peers(raw_peers):
    """Parse compact peer info: 4 bytes IP + 2 bytes port"""
    peers = []
    for peer in raw_peers:
        if len(peer) == 6:
            ip = ".".join(str(b) for b in peer[:4])
            port = int.from_bytes(peer[4:6], 'big')
            peers.append({'ip': ip, 'port': port})
    return peers


# Safe wrapper for your packet capture code
def extract_info_hash(payload_bytes):
    result = parse_dht_packet(payload_bytes)
    if result is None:
        return None

    # Only queries of type get_peers or announce_peer have info_hash
    if result.get('type') == 'q' and result.get('info_hash'):
        return result['info_hash']

    return None  # Responses and other types don't have info_hash


def main_load(payload):
    # raw = bytes.fromhex(
    #     f"{payload}"
    #     .replace(" ", "").replace("\n", "")
    # )
    decoded = bencodepy.decode(payload)

    result = parse_dht_packet(decoded)
    return result

#

import pyshark
import bencodepy

capture = pyshark.LiveCapture(
    interface='Wi-Fi',
    # bpf_filter='' ,
    display_filter='bt-dht'
)
for packet in capture:
    # print(packet)
    # print(packet.show())

    print("-------------------------------------------------------------")

    try:
        # parsing packet
        if hasattr(packet, 'udp') and 'BT-DHT' in str(packet.layers):
            payload = packet.udp.payload
            print(f'BT payload: {payload}')
            # hex_split = payload.split(':')
            # hex_as_chars = map(lambda x: chr(int(x, 16)), hex_split)
            # human_readable = ''.join(hex_as_chars)
            # print(f'Decoded payload: {human_readable}')
            #
            # # # getting info hash
            # payload = bytes.fromhex(
            #     f"{payload}".replace(
            #         ":", ""))
            # #
            # # decoded = bencodepy.decode(payload)
            # # info_hash = decoded[b'a'][b'info_hash']
            # # print(info_hash.hex())
            #
            # result = main_load(payload)
            # print(result)

    except AttributeError as error:
        print("did not find any")

    # try:
    #     # obtain all the field names within the ETH packets
    #     field_names = packet.eth._all_fields
    #
    #     # obtain all the field values
    #     field_values = packet.eth._all_fields.values()
    #
    #     # enumerate the field names and field values
    #     for field_name, field_value in zip(field_names, field_values):
    #         print(f'{field_name}:  {field_value}')
    # except AttributeError as error:
    #     print("did not find any")

    try:
        for layer in packet.layers:
            print(layer)
            print("......")

            if "BT-DHT" in layer:
                print(layer["info_hash"])

    except:
        print("did not find any")
#
#
# capture = pyshark.LiveCapture(interface='your capture interface', display_filter='eth')
# for packet in capture:
#     try:
#         # obtain all the field names within the ETH packets
#         field_names = packet.eth._all_fields
#
#         # obtain all the field values
#         field_values = packet.eth._all_fields.values()
#
#         # enumerate the field names and field values
#         for field_name, field_value in zip(field_names, field_values):
#             print(f'{field_name}:  {field_value}')
#     except AttributeError as error:
#
