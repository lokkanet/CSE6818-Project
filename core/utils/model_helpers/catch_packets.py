import os
import pyshark
import bencodepy

# from test import main_load


capture = pyshark.LiveCapture(
    interface='Wi-Fi',
    # bpf_filter='' ,
    display_filter='bt-dht'
)
for packet in capture:
    has_info_hash = False

    print("-------------------------------------------------------------")

    if hasattr(packet, 'udp') and 'BT-DHT' in str(packet.layers):
        payload = packet.udp.payload
        print(f'BT payload: {payload}')
        hex_split = payload.split(':')
        hex_as_chars = map(lambda x: chr(int(x, 16)), hex_split)
        human_readable = ''.join(hex_as_chars)
        print(f'Decoded payload: {human_readable}')

        # # getting info hash
        payload = bytes.fromhex(
            f"{payload}".replace(
                ":", ""))

        decoded = bencodepy.decode(payload)

        try:
            info_hash = decoded[b'a'][b'info_hash']

            print(info_hash.hex())
            has_info_hash = True
        except:
            print("no info_hash")

        if has_info_hash:
            source_ip = str(packet.ip.src)
            destination_ip = str(packet.ip.dst)


