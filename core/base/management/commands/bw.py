import time
from scapy.all import sniff, IP
from django.core.management.base import BaseCommand
from base.models import Analytics, BaseNetworkPacket, NetworkPacket, BitTorrentPacket
import pyshark
import bencodepy
from utils.analyzer import BitTorrentSniffer

class BandwidthMonitor:
    def __init__(self):
        self.total_bytes = 0
        self.start_time = time.time()
        self.interval_bytes = 0
        self.last_interval = time.time()

    def analyze(self, pkt):
        if not pkt.haslayer(IP):
            return

        pkt_size = len(pkt)
        self.total_bytes += pkt_size
        self.interval_bytes += pkt_size

        now = time.time()

        # print bandwidth every second
        if now - self.last_interval >= 1.0:
            elapsed = now - self.last_interval
            bps = self.interval_bytes / elapsed
            kbps = bps / 1024
            mbps = kbps / 1024

            print(f"Bandwidth: {mbps:.2f} MB/s | {kbps:.2f} KB/s | Total: {self.total_bytes / (1024 * 1024):.2f} MB")

            self.interval_bytes = 0
            self.last_interval = now



class Command(BaseCommand):
    help = 'My custom command'

    def add_arguments(self, parser):
        # optional arguments
        parser.add_argument('--count', type=int, default=10)

    def handle(self, *args, **options):
        unique_info_hash = list(set(list(BitTorrentPacket.objects.values_list("info_hash", flat=True))))[0]
        total_packets = BaseNetworkPacket.objects.all().count()
        total_dht_packets = BaseNetworkPacket.objects.filter(
            protocol="dht",

        ).count()
        total_dht_packets_others = BaseNetworkPacket.objects.filter(
            protocol="dht",
            payload_dict__has_key="info_hash"

        ).count()
        total_dht_packets_with_other_info_hash = BaseNetworkPacket.objects.filter(
            protocol="dht",
            payload_dict__has_key="info_hash"

        ).exclude(
            payload_dict__info_hash=unique_info_hash
        ).count()
        total_tracker_packets = BaseNetworkPacket.objects.filter(
            protocol="tracker"
        ).count()
        total_pwp_packets = BaseNetworkPacket.objects.filter(
            protocol="PWP Packet"
        ).count()
        total_piece_packets = BaseNetworkPacket.objects.filter(
            payload_dict__msg_type="PIECE"
        ).count()
        total_info_hashes_packets = BaseNetworkPacket.objects.filter(
            payload_dict__has_key="info_hash"
        ).count()

        total_handshakes = NetworkPacket.objects.all().count()
        total_unique_handshakes = NetworkPacket.objects.values('destination_ip').distinct().count()

        self.stdout.write(self.style.SUCCESS(
            f"""
            unique_info_hash = {unique_info_hash}

            total_packets = {total_packets}
        total_dht_packets = {total_dht_packets}
        total_dht_packets_others = {total_dht_packets_others}
        total_dht_packets_with_other_info_hash = {total_dht_packets_with_other_info_hash}
        total_tracker_packets = {total_tracker_packets}
        total_pwp_packets = {total_pwp_packets}
        total_piece_packets = {total_piece_packets}
        total_info_hashes_packets = {total_info_hashes_packets}
        total_handshakes = {total_handshakes}
        total_unique_handshakes = {total_unique_handshakes}

            """
        ))
        monitor = BandwidthMonitor()
        sniff(filter="ip", prn=monitor.analyze, store=0)

        # self.stdout.write(self.style.ERROR('no hash!'))


