from django.core.management.base import BaseCommand
from base.models import Analytics, BaseNetworkPacket, NetworkPacket, BitTorrentPacket
import pyshark
import bencodepy
from utils.analyzer import BitTorrentSniffer


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
        total_tracker_packets_with_other_info_hash = BaseNetworkPacket.objects.filter(
            protocol="tracker",
            payload_dict__has_key="info_hash"

        ).exclude(
            payload_dict__info_hash=unique_info_hash
        ).count()
        total_tracker_packets_with_other_info_hash = BaseNetworkPacket.objects.filter(
            protocol="tracker",
            payload_dict__info_hash=unique_info_hash
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
        total_unique_handshakes_hosts = list(NetworkPacket.objects.values_list('destination_ip', flat=True).distinct())

        lib_reliability = BitTorrentPacket.objects.filter(

        )
        self.stdout.write(self.style.SUCCESS(
            f"""
            unique_info_hash = {unique_info_hash}
            
            total_packets = {total_packets}
        total_dht_packets = {total_dht_packets}
        total_dht_packets_others = {total_dht_packets_others}
        total_dht_packets_with_other_info_hash = {total_dht_packets_with_other_info_hash}
        total_tracker_packets = {total_tracker_packets}
        total_tracker_packets_with_other_info_hash={total_tracker_packets_with_other_info_hash}
        total_pwp_packets = {total_pwp_packets}
        total_piece_packets = {total_piece_packets}
        total_info_hashes_packets = {total_info_hashes_packets}
        total_handshakes = {total_handshakes}
        total_unique_handshakes = {total_unique_handshakes}
total_unique_handshakes_hosts= {total_unique_handshakes_hosts}
            """
        ))

        # self.stdout.write(self.style.ERROR('no hash!'))
