from collections import defaultdict
from torrent_metadata import TorrentMeta

def print_report(piece_length, report, abs_map, flows):
    SEP = "=" * 72
    LINE = "─" * 72

    print(f"\n{SEP}")
    print(" BITTORRENT FORENSIC RECONSTRUCTION REPORT")
    print(SEP)

    for flw in flows.values():
        if flw.torrent_file_path!="":
            torrent = TorrentMeta(flw.torrent_file_path)

            if torrent:
                print(f"\n{LINE}")
                print(" TORRENT METADATA")
                print(LINE)
                torrent.print_layout()


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
    print(f" PIECE ANALYSIS  (piece_length = {piece_length:,} bytes = {piece_length // 1024} KB)")
    print(LINE)

    for e in report:
        idx = e["piece_idx"]
        status = ("✓ VERIFIED" if e["verified"] is True
                  else "✓ COMPLETE" if e["is_complete"]
        else "✗ FAILED" if e["verified"] is False
        else "~ PARTIAL")

        print(f"\n  Piece {idx}  [{status}]")
        print(f"  File offset   : {e['piece_base']:,} bytes  "
              f"({e['piece_base'] / 1024 / 1024:.3f} MB)")
        print(f"  Coverage      : {e['bytes_captured']:,} / {e['expected_size']:,} bytes"
              f"  ({e['coverage_pct']:.1f}%)")
        print(f"  Contiguous    : {e['is_contiguous']}  |  Starts at 0 : {e['starts_at_zero']}")

        for gap_start, gap_len in e["gaps"]:
            print(f"  GAP           : offset {gap_start:,}  —  {gap_len:,} bytes missing")

        # SHA1 line(s)
        if e["sha1_expected"]:
            match_str = ("✓ MATCH" if e["verified"] is True
                         else "✗ MISMATCH" if e["verified"] is False
            else "— (incomplete, not verified)")
            print(f"  SHA1 expected : {e['sha1_expected']}")
            print(f"  SHA1 actual   : {e['sha1_actual']}  [{match_str}]")
        else:
            print(f"  SHA1          : {e['sha1_actual']}")

        # file mapping (torrent mode)
        if e["file_slices"]:
            for sl in e["file_slices"]:
                f = sl["file"]
                pct = sl["length"] / f["size"] * 100
                print(f"  Maps to file  : {f['name']}")
                print(f"    piece_offset: {sl['piece_offset']:,}")
                print(f"    file_offset : {sl['file_offset']:,} — "
                      f"{sl['file_offset'] + sl['length']:,}  "
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
        print(f"  {off:>14,}  ({off / 1024 / 1024:>8.3f} MB)  "
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
                file_coverage[fn]["total"] = sl["file"]["size"]
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
    failed = sum(1 for e in report if e["verified"] is False)
    complete = sum(1 for e in report if e["is_complete"] and e["verified"] is None)
    partial = sum(1 for e in report if not e["is_complete"])
    total_b = sum(e["bytes_captured"] for e in report)

    print(f"\n{SEP}")
    print(f" SUMMARY")
    print(f"  Pieces    : {len(report)} total  |  {verified} verified  |  "
          f"{failed} failed  |  {complete} complete  |  {partial} partial")
    print(f"  Recovered : {total_b:,} bytes  ({total_b / 1024:.1f} KB)")
    print(SEP)
