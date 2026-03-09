import struct
import hashlib
import os
import sys
import argparse
import threading
from queue import Queue, Empty
from collections import defaultdict

from scapy.all import rdpcap, sniff, IP, TCP


def bdecode(data, idx=0):
    t = data[idx:idx+1]
    if t == b'd':
        idx += 1; d = {}
        while data[idx:idx+1] != b'e':
            k, idx = bdecode(data, idx)
            v, idx = bdecode(data, idx)
            d[k] = v
        return d, idx + 1
    elif t == b'l':
        idx += 1; lst = []
        while data[idx:idx+1] != b'e':
            v, idx = bdecode(data, idx)
            lst.append(v)
        return lst, idx + 1
    elif t == b'i':
        end = data.index(b'e', idx)
        return int(data[idx+1:end]), end + 1
    else:
        colon = data.index(b':', idx)
        n     = int(data[idx:colon])
        start = colon + 1
        return data[start:start+n], start + n



class TorrentMeta:

    def __init__(self, path):
        with open(path, 'rb') as f:
            raw = f.read()
        torrent, _ = bdecode(raw)
        info = torrent[b'info']

        self.piece_length = info[b'piece length']
        pieces_raw        = info[b'pieces']
        self.piece_hashes = [pieces_raw[i*20:(i+1)*20]
                             for i in range(len(pieces_raw) // 20)]
        self.num_pieces   = len(self.piece_hashes)
        self.name         = info.get(b'name', b'unknown').decode('utf-8', 'replace')

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
            self.files      = [{'name': self.name, 'size': size,
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
        p_end   = min(p_start + self.piece_length, self.total_size)
        slices  = []
        for f in self.files:
            if f['end'] <= p_start or f['start'] >= p_end:
                continue
            seg_start = max(p_start, f['start'])
            seg_end   = min(p_end,   f['end'])
            slices.append({
                'file':         f,
                'piece_offset': seg_start - p_start,
                'file_offset':  seg_start - f['start'],
                'length':       seg_end - seg_start,
            })
        return slices

    def pieces_for_file(self, filename):
        f = next((x for x in self.files if x['name'] == filename), None)
        if not f:
            return []
        first = f['start'] // self.piece_length
        last  = (f['end'] - 1) // self.piece_length
        return list(range(first, last + 1))

    def print_layout(self):
        print(f"  Name         : {self.name}")
        print(f"  Piece length : {self.piece_length:,} bytes ({self.piece_length//1024} KB)")
        print(f"  Num pieces   : {self.num_pieces}")
        print(f"  Total size   : {self.total_size:,} bytes ({self.total_size/1024/1024:.2f} MB)")
        print(f"\n  Files:")
        for i, f in enumerate(self.files):
            print(f"    [{i:>2}]  {f['size']:>12,} bytes   {f['name']}")



class TCPStream:

    def __init__(self):
        self.segments = {}      # seq -> bytes
        self.next_seq = None
        self.buffer   = b""

    def add(self, seq, data):
        if not data:
            return
        if self.next_seq is None:
            self.next_seq = seq
        self.segments[seq] = data
        while self.next_seq in self.segments:
            chunk          = self.segments.pop(self.next_seq)
            self.buffer   += chunk
            self.next_seq += len(chunk)

    def peek(self, n):
        return self.buffer[:n] if len(self.buffer) >= n else None

    def read(self, n):
        if len(self.buffer) < n:
            return None
        data, self.buffer = self.buffer[:n], self.buffer[n:]
        return data

    def available(self):
        return len(self.buffer)


BT_HANDSHAKE  = b"\x13BitTorrent protocol"
HANDSHAKE_LEN = 68   # 1 + 19 + 8 + 20 + 20

MSG_NAMES = {
    0: "CHOKE",        1: "UNCHOKE",         2: "INTERESTED",
    3: "NOT_INTERESTED", 4: "HAVE",          5: "BITFIELD",
    6: "REQUEST",      7: "PIECE",           8: "CANCEL",
    9: "PORT",
}


class BTFlowParser:


    def __init__(self, flow_id):
        self.flow_id        = flow_id   # (src_ip, src_port, dst_ip, dst_port)
        self.stream         = TCPStream()
        self.handshake_done = False
        self.info_hash      = None
        self.peer_id        = None
        self.messages       = []
        self.piece_blocks   = defaultdict(dict)  # idx -> {begin: data}

    def feed(self, seq, data):
        self.stream.add(seq, data)
        self._parse()

    def _parse(self):
        if not self.handshake_done:
            self._try_handshake()
        while self.handshake_done:
            if not self._try_message():
                break

    def _try_handshake(self):
        if self.stream.available() < HANDSHAKE_LEN:
            return
        if self.stream.peek(len(BT_HANDSHAKE)) != BT_HANDSHAKE:
            return
        raw            = self.stream.read(HANDSHAKE_LEN)
        self.info_hash = raw[28:48].hex()
        self.peer_id   = raw[48:68]
        self.handshake_done = True
        si, sp, di, dp = self.flow_id
        print(f"\n[HANDSHAKE] {si}:{sp} -> {di}:{dp}")
        print(f"  info_hash : {self.info_hash}")
        print(f"  peer_id   : {self.peer_id!r}")

    def _try_message(self):

        if self.stream.available() < 4:
            return False

        msg_len = struct.unpack("!I", self.stream.peek(4))[0]

        if msg_len == 0:                         # keepalive
            self.stream.read(4)
            self.messages.append({"type": "KEEPALIVE"})
            return True

        if msg_len > 2 * 1024 * 1024:           # sanity guard
            return False

        if self.stream.available() < 4 + msg_len:
            return False

        self.stream.read(4)
        msg_data = self.stream.read(msg_len)
        msg_id   = msg_data[0]
        payload  = msg_data[1:]

        msg = {"type":   MSG_NAMES.get(msg_id, f"UNKNOWN({msg_id})"),
               "msg_id": msg_id, "length": msg_len}

        if msg_id == 4 and len(payload) >= 4:        # HAVE
            msg["piece_index"] = struct.unpack("!I", payload[:4])[0]

        elif msg_id == 5:                            # BITFIELD
            msg["pieces_have"] = sum(bin(b).count("1") for b in payload)

        elif msg_id == 6 and len(payload) >= 12:     # REQUEST
            msg["piece_index"], msg["begin"], msg["block_length"] = \
                struct.unpack("!III", payload[:12])

        elif msg_id == 7 and len(payload) >= 8:      # PIECE ← what we want
            idx   = struct.unpack("!I", payload[0:4])[0]
            begin = struct.unpack("!I", payload[4:8])[0]
            data  = payload[8:]
            msg.update({"piece_index": idx, "begin": begin,
                        "block_length": len(data),
                        "block_sha1": hashlib.sha1(data).hexdigest()})
            self.piece_blocks[idx][begin] = data     # buffer for reconstruction

        elif msg_id == 8 and len(payload) >= 12:     # CANCEL
            msg["piece_index"], msg["begin"], msg["block_length"] = \
                struct.unpack("!III", payload[:12])

        self.messages.append(msg)
        return True

flows: dict = {}   # flow_id -> BTFlowParser


def handle_packet(pkt):

    if not (IP in pkt and TCP in pkt):
        return
    if not pkt[TCP].payload:
        return

    src_ip   = pkt[IP].src
    dst_ip   = pkt[IP].dst
    src_port = pkt[TCP].sport
    dst_port = pkt[TCP].dport
    seq      = pkt[TCP].seq
    payload  = bytes(pkt[TCP].payload)

    flow_id = (src_ip, src_port, dst_ip, dst_port)
    if flow_id not in flows:
        flows[flow_id] = BTFlowParser(flow_id)
    flows[flow_id].feed(seq, payload)


def process_pcap(path):
    print(f"[*] Reading {path} ...")
    pkts = rdpcap(path)
    print(f"[*] {len(pkts)} packets loaded")
    for pkt in pkts:
        handle_packet(pkt)


def process_live(iface, bpf_filter, timeout=None):
    q = Queue(maxsize=50_000)

    def _cap():
        print(f"[*] Capturing on '{iface}'  filter='{bpf_filter}'  (Ctrl+C to stop)")
        sniff(iface=iface, filter=bpf_filter,
              prn=lambda p: q.put_nowait(p), store=False, timeout=timeout)
        q.put(None)   # sentinel

    def _proc():
        while True:
            try:
                pkt = q.get(timeout=1)
                if pkt is None:
                    break
                handle_packet(pkt)
            except Empty:
                continue
            except KeyboardInterrupt:
                break

    threading.Thread(target=_cap, daemon=True).start()
    t = threading.Thread(target=_proc)
    t.start(); t.join()


FILE_SIGS = [
    (0, b"ID3",               "MP3 (ID3 tag)"),
    (0, b"\xff\xfb",          "MP3 (MPEG frame)"),
    (0, b"\xff\xf3",          "MP3 (MPEG frame)"),
    (0, b"\xff\xf2",          "MP3 (MPEG frame)"),
    (0, b"fLaC",              "FLAC"),
    (0, b"OggS",              "OGG"),
    (0, b"RIFF",              "WAV/AVI"),
    (4, b"ftyp",              "MP4/M4A/AAC"),
    (0, b"\x1a\x45\xdf\xa3", "MKV/WebM"),
    (0, b"\x89PNG",           "PNG"),
    (0, b"\xff\xd8\xff",      "JPEG"),
    (0, b"\x25\x50\x44\x46", "PDF"),
    (0, b"PK\x03\x04",        "ZIP/DOCX/EPUB"),
    (0, b"Rar!",              "RAR"),
    (0, b"\x7fELF",           "ELF Binary"),
    (0, b"MZ",                "PE/EXE"),
]


def detect_file_type(data):
    found = []
    for check_off, sig, name in FILE_SIGS:
        pos = 0
        while True:
            pos = data.find(sig, pos)
            if pos == -1:
                break
            if check_off == 0 or pos == check_off:
                found.append((pos, name))
            pos += 1
    return found


_BITRATES    = [0,32,40,48,56,64,80,96,112,128,160,192,224,256,320,0]
_SAMPLERATES = [44100, 48000, 32000, 0]


def scan_mp3_frames(data, max_frames=20):
    frames, i = [], 0
    while i < len(data) - 4 and len(frames) < max_frames:
        if data[i] == 0xff and (data[i+1] & 0xe0) == 0xe0:
            b1, b2, b3 = data[i+1], data[i+2], data[i+3]
            ver  = (b1 >> 3) & 3;  layer = (b1 >> 1) & 3
            br_i = (b2 >> 4) & 0xf; sr_i = (b2 >> 2) & 3
            pad  = (b2 >> 1) & 1;   ch   = (b3 >> 6) & 3
            if ver == 3 and layer == 1 and 0 < br_i < 15 and sr_i < 3:
                br = _BITRATES[br_i]; sr = _SAMPLERATES[sr_i]
                fs = 144 * br * 1000 // sr + pad
                frames.append({"offset": i, "bitrate": br, "samplerate": sr,
                                "stereo": ch != 3, "frame_size": fs})
                i += max(fs, 1); continue
        i += 1
    return frames


def infer_piece_length(pieces):
    max_end = 0
    for blocks in pieces.values():
        for begin, data in blocks.items():
            max_end = max(max_end, begin + len(data))
    for std in [32768, 65536, 131072, 262144, 524288, 1048576]:
        if max_end <= std:
            return std
    return max_end


def _check_contiguous(blocks):
    begins   = sorted(blocks)
    expected = begins[0]
    for b in begins:
        if b != expected:
            return False
        expected = b + len(blocks[b])
    return True


def reconstruct_all(output_dir, torrent: TorrentMeta = None):

    pieces_dir = os.path.join(output_dir, "pieces")
    files_dir  = os.path.join(output_dir, "files")
    os.makedirs(pieces_dir, exist_ok=True)
    if torrent:
        os.makedirs(files_dir, exist_ok=True)

    merged = defaultdict(dict)
    for parser in flows.values():
        if not parser.handshake_done:
            continue
        for idx, blocks in parser.piece_blocks.items():
            merged[idx].update(blocks)

    if not merged:
        return merged, 0, [], {}

    piece_length = torrent.piece_length if torrent else infer_piece_length(merged)


    file_bufs = {}
    if torrent:
        for f in torrent.files:
            file_bufs[f['name']] = bytearray(f['size'])

    report  = []
    abs_map = {}

    for idx in sorted(merged):
        blocks        = merged[idx]
        piece_base    = idx * piece_length
        sorted_begins = sorted(blocks)

        total_bytes    = sum(len(d) for d in blocks.values())
        exp_size       = torrent.expected_piece_size(idx) if torrent else piece_length
        coverage_pct   = total_bytes / exp_size * 100
        starts_at_zero = 0 in sorted_begins
        is_contiguous  = _check_contiguous(blocks)
        is_complete    = is_contiguous and starts_at_zero and total_bytes >= exp_size

        gaps = []
        if is_contiguous and starts_at_zero:
            # clean path — just concatenate in order
            assembled = b"".join(blocks[b] for b in sorted_begins)
        else:
            # sparse path — null-fill gaps so the piece has correct byte positions
            end_pos  = sorted_begins[-1] + len(blocks[sorted_begins[-1]])
            buf      = bytearray(end_pos)
            expected = sorted_begins[0]
            for b in sorted_begins:
                if b > expected:
                    gaps.append((expected, b - expected))   # record the gap
                buf[b: b + len(blocks[b])] = blocks[b]
                expected = b + len(blocks[b])
            assembled = bytes(buf)

        sha1_actual   = hashlib.sha1(assembled).hexdigest()
        sha1_expected = torrent.piece_hashes[idx].hex() if torrent else None
        # Only attempt verification when piece is fully assembled
        verified      = torrent.verify_piece(idx, assembled) if (torrent and is_complete) else None

        file_slices = []
        if torrent:
            file_slices = torrent.file_slice(idx)
            for sl in file_slices:
                fname    = sl['file']['name']
                p_off    = sl['piece_offset']
                f_off    = sl['file_offset']
                length   = sl['length']
                segment  = assembled[p_off: p_off + length]
                if len(segment) == length:
                    file_bufs[fname][f_off: f_off + length] = segment

        suffix    = "verified" if verified else ("complete" if is_complete else "partial")
        out_piece = os.path.join(pieces_dir, f"piece_{idx:05d}_{suffix}.bin")
        with open(out_piece, "wb") as f:
            f.write(assembled)

        for begin, data in blocks.items():
            abs_map[piece_base + begin] = data

        file_types = detect_file_type(assembled)
        mp3_frames = (scan_mp3_frames(assembled)
                      if any("MP3" in t[1] for t in file_types) else None)

        report.append({
            "piece_idx":      idx,
            "piece_base":     piece_base,
            "blocks":         len(blocks),
            "bytes_captured": total_bytes,
            "expected_size":  exp_size,
            "coverage_pct":   coverage_pct,
            "starts_at_zero": starts_at_zero,
            "is_contiguous":  is_contiguous,
            "is_complete":    is_complete,
            "verified":       verified,
            "sha1_actual":    sha1_actual,
            "sha1_expected":  sha1_expected,
            "gaps":           gaps,
            "file_slices":    file_slices,
            "file_types":     file_types,
            "mp3_frames":     mp3_frames,
            "output_file":    out_piece,
        })

    if torrent:
        for fname, buf in file_bufs.items():
            if any(b != 0 for b in buf):   # skip untouched files
                out_path = os.path.join(files_dir, fname)
                with open(out_path, "wb") as f:
                    f.write(buf)
                print(f"[+] Written: {out_path}")

    return merged, piece_length, report, abs_map



def print_report(piece_length, report, abs_map, torrent: TorrentMeta = None):
    SEP  = "=" * 72
    LINE = "─" * 72

    print(f"\n{SEP}")
    print(" BITTORRENT FORENSIC RECONSTRUCTION REPORT")
    print(SEP)

    # ── torrent metadata ──────────────────────────────────────────────────
    if torrent:
        print(f"\n{LINE}")
        print(" TORRENT METADATA")
        print(LINE)
        torrent.print_layout()

    # ── flow summary ──────────────────────────────────────────────────────
    bt_flows = {fid: p for fid, p in flows.items() if p.handshake_done}
    print(f"\n{LINE}")
    print(f" FLOWS  ({len(bt_flows)} BitTorrent  /  {len(flows)} total TCP)")
    print(LINE)
    for fid, parser in bt_flows.items():
        si, sp, di, dp = fid
        counts = defaultdict(int)
        for m in parser.messages:
            counts[m["type"]] += 1
        bf = [m for m in parser.messages if m.get("msg_id") == 5]
        print(f"\n  {si}:{sp} -> {di}:{dp}")
        print(f"  info_hash : {parser.info_hash}")
        print(f"  peer_id   : {parser.peer_id!r}")
        if bf:
            print(f"  BITFIELD  : peer had {bf[0]['pieces_have']} pieces at connect time")
        print(f"  messages  : {dict(counts)}")

    # ── piece analysis ────────────────────────────────────────────────────
    if not report:
        print(f"\n[!] No PIECE messages found.")
        print("    Possible causes: encrypted traffic (MSE/PE), mid-session capture.")
        return

    print(f"\n{LINE}")
    print(f" PIECE ANALYSIS  (piece_length = {piece_length:,} bytes = {piece_length//1024} KB)")
    print(LINE)

    for e in report:
        idx    = e["piece_idx"]
        status = ("✓ VERIFIED" if e["verified"] is True
                  else "✓ COMPLETE" if e["is_complete"]
                  else "✗ FAILED"   if e["verified"] is False
                  else "~ PARTIAL")

        print(f"\n  Piece {idx}  [{status}]")
        print(f"  File offset   : {e['piece_base']:,} bytes  "
              f"({e['piece_base']/1024/1024:.3f} MB)")
        print(f"  Coverage      : {e['bytes_captured']:,} / {e['expected_size']:,} bytes"
              f"  ({e['coverage_pct']:.1f}%)")
        print(f"  Contiguous    : {e['is_contiguous']}  |  Starts at 0 : {e['starts_at_zero']}")

        for gap_start, gap_len in e["gaps"]:
            print(f"  GAP           : offset {gap_start:,}  —  {gap_len:,} bytes missing")

        # SHA1 line(s)
        if e["sha1_expected"]:
            match_str = ("✓ MATCH"    if e["verified"] is True
                         else "✗ MISMATCH" if e["verified"] is False
                         else "— (incomplete, not verified)")
            print(f"  SHA1 expected : {e['sha1_expected']}")
            print(f"  SHA1 actual   : {e['sha1_actual']}  [{match_str}]")
        else:
            print(f"  SHA1          : {e['sha1_actual']}")

        # file mapping (torrent mode)
        if e["file_slices"]:
            for sl in e["file_slices"]:
                f   = sl["file"]
                pct = sl["length"] / f["size"] * 100
                print(f"  Maps to file  : {f['name']}")
                print(f"    piece_offset: {sl['piece_offset']:,}")
                print(f"    file_offset : {sl['file_offset']:,} — "
                      f"{sl['file_offset']+sl['length']:,}  "
                      f"({sl['length']:,} bytes = {pct:.2f}% of file)")

        # file type detection
        seen = set()
        for foff, ftype in e["file_types"]:
            if ftype not in seen:
                print(f"  Detected      : {ftype}  (at relative offset {foff:,})")
                seen.add(ftype)

        if e["mp3_frames"]:
            f0 = e["mp3_frames"][0]
            print(f"  MP3 frames    : {len(e['mp3_frames'])} found  |  "
                  f"{f0['bitrate']} kbps  |  {f0['samplerate']} Hz  |  "
                  f"{'stereo' if f0['stereo'] else 'mono'}")

        print(f"  Saved to      : {e['output_file']}")

    print(f"\n{LINE}")
    print(" ABSOLUTE BYTE MAP")
    print(LINE)
    for off in sorted(abs_map):
        d = abs_map[off]
        label = ""
        if torrent:
            for f in torrent.files:
                if f['start'] <= off < f['end']:
                    label = f"  ← {f['name']}  @ file+{off - f['start']:,}"
                    break
        print(f"  {off:>14,}  ({off/1024/1024:>8.3f} MB)  "
              f"{len(d):>7,} bytes  {d[:6].hex()}{label}")

    if torrent:
        print(f"\n{LINE}")
        print(" FILE RECONSTRUCTION SUMMARY")
        print(LINE)
        # Group by file name
        file_coverage = defaultdict(lambda: {"written": 0, "verified": 0, "total": 0})
        for e in report:
            for sl in e["file_slices"]:
                fn = sl["file"]["name"]
                file_coverage[fn]["total"]   = sl["file"]["size"]
                file_coverage[fn]["written"] += sl["length"]
                if e["verified"]:
                    file_coverage[fn]["verified"] += sl["length"]

        for fname, cov in file_coverage.items():
            pct = cov["written"] / cov["total"] * 100 if cov["total"] else 0
            vpct = cov["verified"] / cov["total"] * 100 if cov["total"] else 0
            print(f"\n  {fname}")
            print(f"    recovered : {cov['written']:>10,} / {cov['total']:>10,} bytes  ({pct:.2f}%)")
            print(f"    verified  : {cov['verified']:>10,} bytes  ({vpct:.2f}%)")

    verified = sum(1 for e in report if e["verified"] is True)
    failed   = sum(1 for e in report if e["verified"] is False)
    complete = sum(1 for e in report if e["is_complete"] and e["verified"] is None)
    partial  = sum(1 for e in report if not e["is_complete"])
    total_b  = sum(e["bytes_captured"] for e in report)

    print(f"\n{SEP}")
    print(f" SUMMARY")
    print(f"  Pieces    : {len(report)} total  |  {verified} verified  |  "
          f"{failed} failed  |  {complete} complete  |  {partial} partial")
    print(f"  Recovered : {total_b:,} bytes  ({total_b/1024:.1f} KB)")
    print(SEP)


def main():
    ap = argparse.ArgumentParser(
        description="BitTorrent forensic tool — Scapy + torrent-aware reconstruction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 bt_forensic.py capture.pcap --torrent file.torrent --output-dir ./evidence
  python3 bt_forensic.py capture.pcap --output-dir ./evidence
  sudo python3 bt_forensic.py --live --iface eth0 --torrent file.torrent --output-dir ./evidence
  sudo python3 bt_forensic.py --live --iface eth0 --timeout 120
        """
    )

    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("pcap",   nargs="?",           help="Path to .pcap file")
    src.add_argument("--live", action="store_true", help="Live capture mode (requires root)")

    ap.add_argument("--torrent",        help="Path to .torrent file")
    ap.add_argument("--iface",          default="eth0",       help="Interface (live mode)")
    ap.add_argument("--filter",         default="tcp",        help="BPF filter (live mode)")
    ap.add_argument("--timeout",        type=int,             help="Capture timeout seconds")
    ap.add_argument("--output-dir",     default="./recovered",help="Output directory")
    ap.add_argument("--no-reconstruct", action="store_true",  help="Report only, no disk output")
    args = ap.parse_args()

    torrent = None
    if args.torrent:
        if not os.path.exists(args.torrent):
            print(f"Error: torrent not found: {args.torrent}")
            sys.exit(1)
        torrent = TorrentMeta(args.torrent)
        print(f"[*] Torrent  : {torrent.name}")
        print(f"    {torrent.num_pieces} pieces × {torrent.piece_length//1024} KB  |  "
              f"{len(torrent.files)} files  |  {torrent.total_size/1024/1024:.1f} MB total")

    if args.live:
        process_live(args.iface, args.filter, args.timeout)
    else:
        if not os.path.exists(args.pcap):
            print(f"Error: pcap not found: {args.pcap}")
            sys.exit(1)
        process_pcap(args.pcap)

    bt_flows = {fid: p for fid, p in flows.items() if p.handshake_done}
    if not bt_flows:
        print("\n[!] No BitTorrent flows detected.")
        print("    Possible causes: encrypted traffic (MSE/PE), mid-session capture.")
        sys.exit(0)

    total_blocks = sum(len(b) for p in bt_flows.values()
                       for b in p.piece_blocks.values())
    print(f"\n[*] {len(bt_flows)} BT flows  |  {total_blocks} blocks captured")

    out_dir = "/tmp/bt_noop" if args.no_reconstruct else args.output_dir
    if not args.no_reconstruct:
        print(f"[*] Reconstructing into {out_dir} ...")

    merged, piece_length, report, abs_map = reconstruct_all(out_dir, torrent)
    print_report(piece_length, report, abs_map, torrent)


if __name__ == "__main__":
    main()
