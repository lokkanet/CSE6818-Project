FILE_SIGS = [
    (0, b"ID3", "MP3 (ID3 tag)"),
    (0, b"\xff\xfb", "MP3 (MPEG frame)"),
    (0, b"\xff\xf3", "MP3 (MPEG frame)"),
    (0, b"\xff\xf2", "MP3 (MPEG frame)"),
    (0, b"fLaC", "FLAC"),
    (0, b"OggS", "OGG"),
    (0, b"RIFF", "WAV/AVI"),
    (4, b"ftyp", "MP4/M4A/AAC"),
    (0, b"\x1a\x45\xdf\xa3", "MKV/WebM"),
    (0, b"\x89PNG", "PNG"),
    (0, b"\xff\xd8\xff", "JPEG"),
    (0, b"\x25\x50\x44\x46", "PDF"),
    (0, b"PK\x03\x04", "ZIP/DOCX/EPUB"),
    (0, b"Rar!", "RAR"),
    (0, b"\x7fELF", "ELF Binary"),
    (0, b"MZ", "PE/EXE"),
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


_BITRATES = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]
_SAMPLERATES = [44100, 48000, 32000, 0]


def scan_mp3_frames(data, max_frames=20):
    frames, i = [], 0
    while i < len(data) - 4 and len(frames) < max_frames:
        if data[i] == 0xff and (data[i + 1] & 0xe0) == 0xe0:
            b1, b2, b3 = data[i + 1], data[i + 2], data[i + 3]
            ver = (b1 >> 3) & 3;
            layer = (b1 >> 1) & 3
            br_i = (b2 >> 4) & 0xf;
            sr_i = (b2 >> 2) & 3
            pad = (b2 >> 1) & 1;
            ch = (b3 >> 6) & 3
            if ver == 3 and layer == 1 and 0 < br_i < 15 and sr_i < 3:
                br = _BITRATES[br_i];
                sr = _SAMPLERATES[sr_i]
                fs = 144 * br * 1000 // sr + pad
                frames.append({"offset": i, "bitrate": br, "samplerate": sr,
                               "stereo": ch != 3, "frame_size": fs})
                i += max(fs, 1);
                continue
        i += 1
    return frames
