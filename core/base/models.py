from django.db import models
import uuid


class BaseNetworkPacket(models.Model):
    source_ip = models.CharField(max_length=255, null=True, blank=True)
    source_port = models.CharField(max_length=255, null=True, blank=True)
    destination_ip = models.CharField(max_length=255, null=True, blank=True)
    destination_port = models.CharField(max_length=255, null=True, blank=True)
    transport_protocol = models.CharField(max_length=255, null=True, blank=True)
    protocol = models.CharField(max_length=255, null=True, blank=True)
    # type_of_packet - dht , tracker http/udp, pwp, pex
    timestamp = models.DateTimeField(null=True, blank=True)
    payload = models.CharField(max_length=2000, null=True, blank=True)
    payload_dict = models.JSONField(default=dict, null=True, blank=True)

    def __str__(self):
        return f"{self.id}"


class NetworkPacket(models.Model):
    source_ip = models.CharField(max_length=255, null=True, blank=True)
    destination_ip = models.CharField(max_length=255)
    info_hash = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return f"{self.id}"

    class Meta:
        ordering = ("source_ip",)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

        # if self._state.adding:
        #     try:
        #         BitTorrentPacket.objects.create(
        #             net_packet_id = self.id,
        #
        #         )
        #     except BitTorrentPacket.DoesNotExist:
        #         pass


class BitTorrentPacket(models.Model):
    net_packet = models.ForeignKey(
        NetworkPacket, on_delete=models.CASCADE, related_name="network_packet_bittorrent_packet"
    )
    info_hash = models.CharField(max_length=255, null=True, blank=True)
    bittorrent_metadata = models.JSONField(default=dict, null=True, blank=True)

    def __str__(self):
        return f"{self.net_packet.id}"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)


class Analytics(models.Model):
    total_packets = models.DecimalField(default=0, max_digits=10, decimal_places=2)
    total_dht_packets = models.DecimalField(default=0, max_digits=10, decimal_places=2)
    total_tracker_packets = models.DecimalField(default=0, max_digits=10, decimal_places=2)
    total_pwp_packets = models.DecimalField(default=0, max_digits=10, decimal_places=2)
    total_piece_packets = models.DecimalField(default=0, max_digits=10, decimal_places=2)
    total_info_hashes_packets = models.DecimalField(default=0, max_digits=10, decimal_places=2)

    def __str__(self):
        return f"{self.id}"
