import libtorrent as lt
import time


def get_metadata_from_infohash(info_hash_hex):
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
    params.save_path = "../../../.."
    params.flags |= lt.torrent_flags.upload_mode
    params.flags |= lt.torrent_flags.auto_managed

    handle = ses.add_torrent(params)

    print(f"Fetching metadata for info hash: {info_hash_hex}")
    print("Connecting to DHT and peers...")

    timeout = 60
    start_time = time.time()
    metadata_received = False
    dht_nodes = 0

    while not metadata_received:
        alerts = ses.pop_alerts()
        for alert in alerts:
            if isinstance(alert, lt.metadata_received_alert):
                metadata_received = True
                break
            elif isinstance(alert, lt.metadata_failed_alert):
                print("\nMetadata fetch failed.")
                ses.remove_torrent(handle)
                return None
            # Track DHT node count via alerts instead of ses.status()
            elif isinstance(alert, lt.dht_stats_alert):
                dht_nodes = alert.routing_table

        # Post a DHT stats request instead of calling ses.status()
        ses.post_dht_stats()

        time.sleep(0.5)

        # Get peer count directly from handle status flags (not deprecated)
        num_peers = handle.status(lt.torrent_handle.query_accurate_download_counters).num_peers

        print(
            f"\rPeers: {num_peers} | "
            f"DHT nodes: {dht_nodes} | "
            f"Time: {int(time.time() - start_time)}s",
            end="", flush=True
        )

        if time.time() - start_time > timeout:
            print("\n\nTimeout: Could not fetch metadata")
            ses.remove_torrent(handle)
            return None

    print("\n\nMetadata downloaded successfully!")

    torrent_info = handle.torrent_file()

    if torrent_info is None:
        print("Error: Could not retrieve torrent file info.")
        ses.remove_torrent(handle)
        return None

    file_storage = torrent_info.files()

    metadata = {
        'name': torrent_info.name(),
        'num_files': file_storage.num_files(),
        'total_size': torrent_info.total_size(),
        'piece_length': torrent_info.piece_length(),
        'num_pieces': torrent_info.num_pieces(),
        'creator': torrent_info.creator() if torrent_info.creator() else "Unknown",
        'comment': torrent_info.comment() if torrent_info.comment() else "",
        'info_hash': str(torrent_info.info_hashes().get_best()),
        'files': []
    }

    for i in range(file_storage.num_files()):
        file_info = {
            'path': file_storage.file_path(i),
            'size': file_storage.file_size(i)
        }
        metadata['files'].append(file_info)

    ses.remove_torrent(handle)

    return metadata


if __name__ == "__main__":
    info_hash = "146e045d43bde19c75101a0bfd84bae4781c9686"

    metadata = get_metadata_from_infohash(info_hash)

    if metadata:
        print("\n" + "=" * 50)
        print("TORRENT METADATA")
        print("=" * 50)
        print(f"Name:         {metadata['name']}")
        print(f"Info Hash:    {metadata['info_hash']}")
        print(f"Total Size:   {metadata['total_size'] / (1024 ** 3):.2f} GB")
        print(f"Files:        {metadata['num_files']}")
        print(f"Piece Length: {metadata['piece_length'] / 1024} KB")
        print(f"Num Pieces:   {metadata['num_pieces']}")
        print(f"Creator:      {metadata['creator']}")
        print(f"Comment:      {metadata['comment']}")
        print("\nFiles:")
        for file in metadata['files']:
            size_mb = file['size'] / (1024 ** 2)
            print(f"  - {file['path']} ({size_mb:.2f} MB)")