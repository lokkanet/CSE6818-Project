from datetime import datetime, timedelta
from django.dispatch import receiver
from django.db.models.signals import post_save, pre_save
from base.models import BaseNetworkPacket, NetworkPacket, BitTorrentPacket
from utils.model_helpers.libtor2 import get_metadata_from_infohash
import threading


def create_bt(instance):
    try:
        if instance.info_hash:
            print("HERRRRRRRRRRR")
            bt_meta = get_metadata_from_infohash(instance.info_hash)
            print("2HERRRRRRRRRRR", bt_meta)

            BitTorrentPacket.objects.create(
                net_packet=instance,
                info_hash=instance.info_hash,
                bittorrent_metadata=bt_meta
            )
    except:
        print("could not create ")


@receiver(post_save, sender=NetworkPacket)
def create_instance(sender, instance, created, **kwargs):
    try:
        if created:
            thread = threading.Thread(target=create_bt, args=(instance,))
            thread.start()

    except:
        print("thread fail")


@receiver(post_save, sender=BaseNetworkPacket)
def create_instance(sender, instance, created, **kwargs):
    try:
        if created:
            if "msg_type" in instance.payload_dict and "info_hash" in instance.payload_dict:
                if instance.payload_dict["msg_type"] == "PWP HANDSHAKE":
                    NetworkPacket.objects.create(
                        source_ip=instance.source_ip,
                        destination_ip=instance.destination_ip,
                        info_hash=instance.payload_dict["info_hash"]
                    )
    except:
        print("NetworkPacket instance creation failed")
