import libtorrent as lt
import time


def get_metadata_from_infohash(info_hash_hex):
    print("fetching...")
    dht_routers = [
        "router.bittorrent.com:6881",
        "dht.transmissionbt.com:6881",
        "router.utorrent.com:6881"
    ]

    settings = {
        'enable_dht': True,
        'enable_lsd': True,
        'enable_upnp': True,
        'enable_natpmp': True,
        'alert_mask': lt.alert.category_t.all_categories,
        'dht_bootstrap_nodes': ','.join(dht_routers),
    }

    ses = lt.session(settings)

    magnet_uri = f"magnet:?xt=urn:btih:{info_hash_hex}"
    params = lt.parse_magnet_uri(magnet_uri)
    params.save_path = "../../.."
    params.flags |= lt.torrent_flags.upload_mode
    params.flags |= lt.torrent_flags.auto_managed

    handle = ses.add_torrent(params)

    timeout = 60
    start_time = time.time()
    metadata_received = False

    while not metadata_received:
        alerts = ses.pop_alerts()
        for alert in alerts:
            if isinstance(alert, lt.metadata_received_alert):
                metadata_received = True
                break
            elif isinstance(alert, lt.metadata_failed_alert):
                ses.remove_torrent(handle)
                return -1
            elif isinstance(alert, lt.dht_stats_alert):
                dht_nodes = alert.routing_table

        ses.post_dht_stats()

        time.sleep(0.5)

        if time.time() - start_time > timeout:
            ses.remove_torrent(handle)
            return {}

    print("\n\nMetadata downloaded successfully!")

    torrent_info = handle.torrent_file()

    if torrent_info is None:
        ses.remove_torrent(handle)
        return {}
    file_storage = torrent_info.files()

    meta_data = {
        'name': torrent_info.name(),
        'num_files': file_storage.num_files(),
        'total_size': torrent_info.total_size(),
        'piece_length': torrent_info.piece_length(),
        'num_pieces': torrent_info.num_pieces(),
        'creator': torrent_info.creator() if torrent_info.creator() else "Unknown",
        'comment': torrent_info.comment() if torrent_info.comment() else "",
        'info_hash': str(torrent_info.info_hashes().get_best()),
        'files': [
            {
                'path': file_storage.file_path(i),
                'size': file_storage.file_size(i)
            } for i in range(file_storage.num_files())
        ]
    }

    ses.remove_torrent(handle)

    return meta_data

