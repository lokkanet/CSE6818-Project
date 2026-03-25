from bencode import bdecode
import hashlib


class TorrentMeta:

    def __init__(self, path):
        with open(path, 'rb') as f:
            raw = f.read()
        torrent, _ = bdecode(raw)
        info = torrent[b'info']

        self.piece_length = info[b'piece length']
        pieces_raw = info[b'pieces']
        self.piece_hashes = [pieces_raw[i * 20:(i + 1) * 20]
                             for i in range(len(pieces_raw) // 20)]
        self.num_pieces = len(self.piece_hashes)
        self.name = info.get(b'name', b'unknown').decode('utf-8', 'replace')

        # Build file table with absolute byte offsets in the concatenated stream
        self.files = []
        if b'files' in info:
            offset = 0
            for fi in info[b'files']:
                size = fi[b'length']
                name = b'/'.join(fi[b'path']).decode('utf-8', 'replace')
                self.files.append({'name': name, 'size': size,
                                   'start': offset, 'end': offset + size})
                offset += size
            self.total_size = offset
        else:
            size = info[b'length']
            self.files = [{'name': self.name, 'size': size,
                           'start': 0, 'end': size}]
            self.total_size = size

    # ── verification ─────────────────────────────────────────────────────

    def verify_piece(self, idx, data):
        """SHA1-verify assembled piece against the torrent hash list."""
        if idx >= self.num_pieces:
            return False
        return hashlib.sha1(data).digest() == self.piece_hashes[idx]

    def expected_piece_size(self, idx):

        if idx == self.num_pieces - 1:
            rem = self.total_size % self.piece_length
            return rem if rem else self.piece_length
        return self.piece_length

    # ── file mapping ──────────────────────────────────────────────────────

    def file_slice(self, piece_idx):

        p_start = piece_idx * self.piece_length
        p_end = min(p_start + self.piece_length, self.total_size)
        slices = []
        for f in self.files:
            if f['end'] <= p_start or f['start'] >= p_end:
                continue
            seg_start = max(p_start, f['start'])
            seg_end = min(p_end, f['end'])
            slices.append({
                'file': f,
                'piece_offset': seg_start - p_start,
                'file_offset': seg_start - f['start'],
                'length': seg_end - seg_start,
            })
        return slices

    def pieces_for_file(self, filename):
        f = next((x for x in self.files if x['name'] == filename), None)
        if not f:
            return []
        first = f['start'] // self.piece_length
        last = (f['end'] - 1) // self.piece_length
        return list(range(first, last + 1))

    def print_layout(self):
        print(f"  Name         : {self.name}")
        print(f"  Piece length : {self.piece_length:,} bytes ({self.piece_length // 1024} KB)")
        print(f"  Num pieces   : {self.num_pieces}")
        print(f"  Total size   : {self.total_size:,} bytes ({self.total_size / 1024 / 1024:.2f} MB)")
        print(f"\n  Files:")
        for i, f in enumerate(self.files):
            print(f"    [{i:>2}]  {f['size']:>12,} bytes   {f['name']}")
