import os
import sys
import hashlib
from collections import defaultdict
import argparse
from datetime import datetime
from scapy.all import rdpcap, sniff, IP, TCP
from bt_flow import BTFlowParser
from file_type_detect import detect_file_type, scan_mp3_frames
from torrent_metadata import TorrentMeta
from print_report import print_report
# flows
flows: dict = {}


def handle_packet(pkt):
    if not (IP in pkt and TCP in pkt):
        return
    if not pkt[TCP].payload:
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    src_port = pkt[TCP].sport
    dst_port = pkt[TCP].dport
    seq = pkt[TCP].seq
    payload = bytes(pkt[TCP].payload)

    flow_id = (src_ip, src_port, dst_ip, dst_port)
    if flow_id not in flows:
        flows[flow_id] = BTFlowParser(flow_id)
    flows[flow_id].feed(seq, payload)


def process_pcap(path):
    print(f"[*] Reading {path} ...")
    packets = rdpcap(path)
    print(f"[*] {len(packets)} packets loaded")
    for pkt in packets:
        handle_packet(pkt)







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
    os.makedirs(files_dir, exist_ok=True)




    merged = defaultdict(dict)
    for flw in flows.values():
        if not flw.handshake_done:
            continue
        if not torrent:
            torrent = TorrentMeta(flw.torrent_file_path)
            if torrent.name:
                os.makedirs(f"{files_dir}/{torrent.name}", exist_ok=True)
                files_dir = files_dir + f"/{torrent.name}"
                os.makedirs(f"{pieces_dir}/{torrent.name}", exist_ok=True)
                pieces_dir = pieces_dir + f"/{torrent.name}"

        for idx, blocks in flw.piece_blocks.items():
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
                if "/" in fname:
                    fname = fname.split("/")[-1]
                with open(f"{files_dir}/{fname}", "wb") as f:
                    f.write(buf)
                print(f"[+] Written: {files_dir}/{fname}")

    return merged, piece_length, report, abs_map



def main():
    start = datetime.now()
    ap = argparse.ArgumentParser(
        description="BitTorrent forensic tool — Scapy + torrent-aware reconstruction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
            Example:
              python3 forensic.py capture.pcap 
        """
    )

    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("pcap",   nargs="?", help="Path to .pcap file")
    args = ap.parse_args()

    if args.pcap:
        process_pcap(args.pcap)


    bt_flows = {fid: p for fid, p in flows.items() if p.handshake_done}
    print("bt flows",bt_flows)
    if not bt_flows:
        print("\n[!] No BitTorrent flows detected.")
        print("    Possible causes: encrypted traffic (MSE/PE), mid-session capture.")
        sys.exit(0)

    total_blocks = sum(len(b) for p in bt_flows.values()
                       for b in p.piece_blocks.values())

    print(f"\n[*] {len(bt_flows)} BT flows  |  {total_blocks} blocks captured")

    out_dir = current_directory = os.getcwd()
    print(f"[*] Reconstructing into {out_dir} ...")

    merged, piece_length, report, abs_map = reconstruct_all(out_dir)
    print_report(piece_length, report, abs_map, flows)
    time_diff = datetime.now() - start
    print("time diff", time_diff)


if __name__ == "__main__":
    main()