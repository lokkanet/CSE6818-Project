from django.core.management.base import BaseCommand
import pyshark
import bencodepy
from utils.analyzer import *


class Command(BaseCommand):
    help = 'My custom command'

    def add_arguments(self, parser):
        # optional arguments
        parser.add_argument('--count', type=int, default=10)

    def handle(self, *args, **options):
        try:
            sniffer = BitTorrentSniffer()
            bpf_filter = "udp or tcp"

            try:
                sniff(
                    filter=bpf_filter,
                    prn=sniffer.analyze_packet,
                    store=0
                )
            except KeyboardInterrupt:
                print("\n\nStopping capture...")

            self.stdout.write(self.style.SUCCESS('Done!'))
        except:
            info_hash = -1
            self.stdout.write(self.style.ERROR('no hash!'))
