import libtorrent as lt
import time


def get_metadata_from_infohash(info_hash_hex):
    ses = lt.session()

    # Configure session settings for DHT and metadata fetching
    settings = {
        'enable_dht': True,
        'enable_lsd': True,
        'enable_upnp': True,
        'enable_natpmp': True,
    }
    ses.apply_settings(settings)

    # Add DHT bootstrap nodes
    ses.add_dht_router("router.bittorrent.com", 6881)
    ses.add_dht_router("dht.transmissionbt.com", 6881)
    ses.add_dht_router("router.utorrent.com", 6881)

    # Create add_torrent_params
    params = lt.add_torrent_params()
    params.info_hash = lt.sha1_hash(bytes.fromhex(info_hash_hex))

    # Set save path (metadata will be stored temporarily)
    params.save_path = ".."

    # Important: Set flags to only download metadata
    params.flags |= lt.torrent_flags.upload_mode

    # Add the torrent to the session
    handle = ses.add_torrent(params)

    print(f"Fetching metadata for info hash: {info_hash_hex}")
    print("Connecting to DHT and peers...")

    # Wait for metadata to be downloaded
    timeout = 60  # seconds
    start_time = time.time()

    while not handle.has_metadata():
        time.sleep(0.5)

        status = handle.status()
        print(f"\rProgress: {status.num_peers} peers connected", end="", flush=True)

        if time.time() - start_time > timeout:
            print("\n\nTimeout: Could not fetch metadata")
            ses.remove_torrent(handle)
            return None

    print("\n\nMetadata downloaded successfully!")

    # Get the torrent info
    torrent_info = handle.torrent_file()

    # Extract metadata
    metadata = {
        'name': torrent_info.name(),
        'num_files': torrent_info.num_files(),
        'total_size': torrent_info.total_size(),
        'piece_length': torrent_info.piece_length(),
        'num_pieces': torrent_info.num_pieces(),
        'creator': torrent_info.creator() if torrent_info.creator() else "Unknown",
        'comment': torrent_info.comment() if torrent_info.comment() else "",
        'files': []
    }

    # Get file information
    files = torrent_info.files()
    for i in range(files.num_files()):
        file_info = {
            'path': files.file_path(i),
            'size': files.file_size(i)
        }
        metadata['files'].append(file_info)

    # Clean up
    ses.remove_torrent(handle)

    return metadata


# Example usage
if __name__ == "__main__":
    # Example info hash (Ubuntu torrent)
    info_hash = "146e045d43bde19c75101a0bfd84bae4781c9686"

    metadata = get_metadata_from_infohash(info_hash)

    if metadata:
        print("\n" + "=" * 50)
        print("TORRENT METADATA")
        print("=" * 50)
        print(f"Name: {metadata['name']}")
        print(f"Total Size: {metadata['total_size'] / (1024 ** 3):.2f} GB")
        print(f"Number of Files: {metadata['num_files']}")
        print(f"Piece Length: {metadata['piece_length'] / 1024} KB")
        print(f"Creator: {metadata['creator']}")
        print(f"Comment: {metadata['comment']}")
        print("\nFiles:")
        for file in metadata['files']:
            print(f"  - {file['path']} ({file['size'] / (1024 ** 2):.2f} MB)")





