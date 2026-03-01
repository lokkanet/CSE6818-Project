import time, sys, libtorrent as lt

# https://www.libtorrent.org/reference-Alerts.html#alert_category_t
#alert_mask = 0b111111111111111111111111
alert_mask = 0  # lt.alert.category_t.torrent_log_notification
ses = lt.session({
    'upload_rate_limit': 0
    , 'download_rate_limit': 0
    , 'active_downloads': -1
    , 'active_limit': -1
    , 'alert_mask': alert_mask
})


def add_infohash(ih):
    link = 'magnet:?xt=urn:btih:' + ih

    params = {
        'save_path': 'data/',
        # 'auto_managed': False,
        # 'upload_mode': True
        #,'stop_when_ready': True
        #,'paused': True
        #, 'file_priorities': [0] * 1000
    }

    handle = lt.add_magnet_uri(ses, link, params)
    handle.resume()

    return handle


torrents = []
for infohash in open('list.txt').readlines():
    infohash = infohash.strip()
    torrents.append((infohash, add_infohash(infohash)))

#print(handle.get_torrent_info())
#print(handle.is_valid(), handle.has_metadata(), handle.trackers())

while True:
    print('-------')

    alerts = ses.pop_alerts()
    for a in alerts: print(a.message())

    for infohash, handle in torrents:
        info = handle.get_torrent_info()
        stat = handle.status()
        size = info.total_size() if info is not None else None
        print(f'{infohash}: size={size}, qp={stat.queue_position}, paused={stat.paused}, state={stat.state}')

    time.sleep(0.5)
