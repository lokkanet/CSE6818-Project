from django.core.management.base import BaseCommand
from base.models import NetworkPacket, BitTorrentPacket
import pyshark
import bencodepy
from utils.analyzer import BitTorrentSniffer

class Command(BaseCommand):
    help = 'My custom command'

    def add_arguments(self, parser):
        # optional arguments
        parser.add_argument('--count', type=int, default=10)

    def handle(self, *args, **options):
        capture = pyshark.LiveCapture(
            interface='Wi-Fi',
            display_filter='bt-dht'
        )
        for packet in capture:
            has_info_hash = False

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
                    has_info_hash = True
                    info_hash = info_hash.hex()

                    if has_info_hash:
                        source_ip = str(packet.ip.src)
                        destination_ip = str(packet.ip.dst)

                        if info_hash != -1:
                            packet = NetworkPacket.objects.create(
                                source_ip=source_ip,
                                destination_ip=destination_ip,
                                info_hash=info_hash

                            )
                            self.stdout.write(f'Created packet {packet.id}')

                            self.stdout.write(self.style.SUCCESS('Done!'))
                except:
                    info_hash = -1
                    self.stdout.write(self.style.ERROR('no hash!'))




