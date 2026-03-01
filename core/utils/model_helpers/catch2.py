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
    # print(packet)
    # print(packet.show())

    print("-------------------------------------------------------------")

    try:
        # parsing packet
        if hasattr(packet, 'udp') and 'BT-DHT' in str(packet.layers):
            payload = packet.udp.payload
            print(f'BT payload: {payload}')


    except AttributeError as error:
        print("did not find any")

    try:
        # obtain all the field names within the ETH packets
        field_names = packet.eth._all_fields

        # obtain all the field values
        field_values = packet.eth._all_fields.values()

        # enumerate the field names and field values
        for field_name, field_value in zip(field_names, field_values):
            print(f'{field_name}:  {field_value}')
    except AttributeError as error:
        print("did not find any")

    try:
        for layer in packet.layers:
            print(f"\n{'=' * 50}")
            print(f"Layer:       {layer.layer_name}")
            print(f"Type:        {type(layer)}")
            print(f"field_names: {layer.field_names}")
            print(f"\n--- _all_fields ---")
            for k, v in layer._all_fields.items():
                print(f"  {k}: {v}")
            print(f"\n--- get_field loop ---")
            for name in layer.field_names:
                f = layer.get_field(name)
                if f:
                    print(f"  {name}: raw={f.raw_value}  show={f.showname}")




    except:
        print("did not find any")
