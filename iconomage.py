#!/usr/bin/env python3
"""
iconomage — single-image intelligence extraction for JPEG and PNG.

Design goals:
  * The forensic CORE is pure standard library (no pip installs needed):
      - container parsing (JPEG segments, PNG chunks)
      - full EXIF/TIFF IFD walk (IFD0, ExifSubIFD, GPS, IFD1/thumbnail)
      - IPTC + XMP extraction
      - cryptographic hashing
      - strings (ASCII + UTF-16LE)
      - trailing-data + embedded-file carving (magic-byte scan)
  * The PIXEL layer is optional (needs Pillow):
      - perceptual hashes (aHash / dHash / pHash, pure-python DCT)
      - naive LSB steganography extraction
      - Error Level Analysis (ELA)

Usage:
    python3 iconomage.py target.jpg
    python3 iconomage.py target.png --json report.json --outdir carved/ --stego --ela
    python3 iconomage.py target.jpg --strings-min 6

Nothing here phones home, scrapes faces, or matches identities. It reads a
file you already have and tells you everything the file is willing to admit.
"""

import argparse
import binascii
import hashlib
import io
import json
import math
import os
import struct
import sys
import zlib

# ----------------------------------------------------------------------------
# Optional pixel-domain dependency
# ----------------------------------------------------------------------------
try:
    from PIL import Image, ImageChops
    HAVE_PIL = True
except Exception:
    HAVE_PIL = False


# ============================================================================
#  SECTION 1 — HASHING
# ============================================================================

def crypto_hashes(data: bytes) -> dict:
    """Standard cryptographic + non-crypto digests for matching against
    known-image sets, malware repos, and dedup."""
    out = {}
    for name in ("md5", "sha1", "sha256", "sha512"):
        h = hashlib.new(name)
        h.update(data)
        out[name] = h.hexdigest()
    out["blake2b"] = hashlib.blake2b(data).hexdigest()
    out["crc32"] = format(binascii.crc32(data) & 0xFFFFFFFF, "08x")
    return out


def _dct_1d(vec):
    n = len(vec)
    factor = math.pi / n
    out = [0.0] * n
    for u in range(n):
        s = 0.0
        for x in range(n):
            s += vec[x] * math.cos((x + 0.5) * u * factor)
        out[u] = s
    return out


def _dct_2d(matrix):
    rows = [_dct_1d(r) for r in matrix]
    n = len(rows)
    m = len(rows[0])
    cols = [[rows[r][c] for r in range(n)] for c in range(m)]
    cols = [_dct_1d(c) for c in cols]
    return [[cols[c][r] for c in range(m)] for r in range(n)]


def _bits_to_hex(bits):
    val = 0
    for b in bits:
        val = (val << 1) | (1 if b else 0)
    return format(val, "0{}x".format(len(bits) // 4))


def perceptual_hashes(path: str) -> dict:
    """aHash, dHash, pHash. These survive resize / re-compress, so two files
    with the same pHash are almost certainly the same picture even after
    edits. Requires Pillow."""
    if not HAVE_PIL:
        return {"_note": "Pillow not installed; perceptual hashes skipped."}
    out = {}
    try:
        img = Image.open(path).convert("L")
    except Exception as e:
        return {"_error": str(e)}

    # aHash — 8x8, threshold at mean
    a = img.resize((8, 8), Image.LANCZOS)
    px = list(a.tobytes())
    mean = sum(px) / len(px)
    out["ahash"] = _bits_to_hex([p > mean for p in px])

    # dHash — 9x8, compare horizontally adjacent pixels
    d = img.resize((9, 8), Image.LANCZOS)
    dp = list(d.tobytes())
    bits = []
    for row in range(8):
        for col in range(8):
            left = dp[row * 9 + col]
            right = dp[row * 9 + col + 1]
            bits.append(left > right)
    out["dhash"] = _bits_to_hex(bits)

    # pHash — 32x32 -> DCT -> top-left 8x8 -> median threshold
    p = img.resize((32, 32), Image.LANCZOS)
    mat = [[p.getpixel((c, r)) for c in range(32)] for r in range(32)]
    dct = _dct_2d(mat)
    low = [dct[r][c] for r in range(8) for c in range(8)]
    med = sorted(low)[len(low) // 2]
    out["phash"] = _bits_to_hex([v > med for v in low])
    return out


# ============================================================================
#  SECTION 2 — EXIF / TIFF IFD PARSER  (pure stdlib)
# ============================================================================

# Type -> byte size
_TIFF_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1,
                   8: 2, 9: 4, 10: 8, 11: 4, 12: 8}

# Most intelligence-relevant tags. Unknown tags are still reported by ID.
_TAGS_IFD = {
    0x0100: "ImageWidth", 0x0101: "ImageLength", 0x010E: "ImageDescription",
    0x010F: "Make", 0x0110: "Model", 0x0112: "Orientation",
    0x011A: "XResolution", 0x011B: "YResolution", 0x0128: "ResolutionUnit",
    0x0131: "Software", 0x0132: "DateTime", 0x013B: "Artist",
    0x013C: "HostComputer", 0x8298: "Copyright", 0x8769: "ExifIFDPointer",
    0x8825: "GPSInfoIFDPointer", 0xA005: "InteropIFDPointer",
    0x0201: "ThumbnailJPEGOffset", 0x0202: "ThumbnailJPEGLength",
    0x9C9B: "XPTitle", 0x9C9C: "XPComment", 0x9C9D: "XPAuthor",
    0x9C9E: "XPKeywords", 0x9C9F: "XPSubject",
}
_TAGS_EXIF = {
    0x829A: "ExposureTime", 0x829D: "FNumber", 0x8822: "ExposureProgram",
    0x8827: "ISOSpeedRatings", 0x9000: "ExifVersion",
    0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
    0x9010: "OffsetTime", 0x9011: "OffsetTimeOriginal",
    0x9012: "OffsetTimeDigitized", 0x9201: "ShutterSpeedValue",
    0x9202: "ApertureValue", 0x9204: "ExposureBiasValue",
    0x9207: "MeteringMode", 0x9209: "Flash", 0x920A: "FocalLength",
    0x927C: "MakerNote", 0x9286: "UserComment", 0xA000: "FlashpixVersion",
    0xA001: "ColorSpace", 0xA002: "PixelXDimension",
    0xA003: "PixelYDimension", 0xA005: "InteropIFDPointer",
    0xA20E: "FocalPlaneXResolution", 0xA40A: "Sharpness",
    0xA420: "ImageUniqueID", 0xA430: "CameraOwnerName",
    0xA431: "BodySerialNumber", 0xA432: "LensSpecification",
    0xA433: "LensMake", 0xA434: "LensModel", 0xA435: "LensSerialNumber",
    0xA460: "CompositeImage",
}
_TAGS_GPS = {
    0x0000: "GPSVersionID", 0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef", 0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef", 0x0006: "GPSAltitude", 0x0007: "GPSTimeStamp",
    0x0008: "GPSSatellites", 0x0010: "GPSImgDirectionRef",
    0x0011: "GPSImgDirection", 0x0012: "GPSMapDatum",
    0x001B: "GPSProcessingMethod", 0x001D: "GPSDateStamp",
}


def _u(endian, fmt, data, off):
    return struct.unpack_from(endian + fmt, data, off)[0]


def _read_value(tiff, endian, typ, count, value_off_field, base):
    """Resolve a single IFD entry's value(s)."""
    size = _TIFF_TYPE_SIZE.get(typ, 1) * count
    if size <= 4:
        # inline value: stored left-justified in the 4-byte field, file endianness
        raw = struct.pack(("<" if endian == "<" else ">") + "I", value_off_field)
        data = raw[:size]
    else:
        off = value_off_field
        if off + size > len(tiff):
            return None
        data = tiff[off:off + size]

    def vals():
        res = []
        if typ in (1, 6, 7):           # BYTE / SBYTE / UNDEFINED
            return list(data[:count])
        if typ == 2:                   # ASCII
            return data.split(b"\x00", 1)[0].decode("latin-1", "replace")
        step = _TIFF_TYPE_SIZE[typ]
        for i in range(count):
            chunk = data[i * step:(i + 1) * step]
            if typ == 3:
                res.append(_u(endian, "H", chunk, 0))
            elif typ == 4:
                res.append(_u(endian, "I", chunk, 0))
            elif typ == 8:
                res.append(_u(endian, "h", chunk, 0))
            elif typ == 9:
                res.append(_u(endian, "i", chunk, 0))
            elif typ == 5:             # RATIONAL
                n = _u(endian, "I", chunk, 0); d = _u(endian, "I", chunk, 4)
                res.append((n, d))
            elif typ == 10:            # SRATIONAL
                n = _u(endian, "i", chunk, 0); d = _u(endian, "i", chunk, 4)
                res.append((n, d))
            elif typ == 11:
                res.append(struct.unpack_from(endian + "f", chunk, 0)[0])
            elif typ == 12:
                res.append(struct.unpack_from(endian + "d", chunk, 0)[0])
        return res

    return vals()


def _rational_to_float(v):
    try:
        n, d = v
        return n / d if d else 0.0
    except Exception:
        return v


def _gps_to_decimal(coord, ref):
    try:
        deg = _rational_to_float(coord[0])
        mins = _rational_to_float(coord[1])
        secs = _rational_to_float(coord[2])
        dec = deg + mins / 60.0 + secs / 3600.0
        if ref in ("S", "W"):
            dec = -dec
        return round(dec, 7)
    except Exception:
        return None


def _parse_ifd(tiff, endian, ifd_off, tagmap):
    """Return (entries_dict, next_ifd_offset)."""
    out = {}
    if ifd_off + 2 > len(tiff):
        return out, 0
    count = _u(endian, "H", tiff, ifd_off)
    p = ifd_off + 2
    for _ in range(count):
        if p + 12 > len(tiff):
            break
        tag = _u(endian, "H", tiff, p)
        typ = _u(endian, "H", tiff, p + 2)
        cnt = _u(endian, "I", tiff, p + 4)
        voff = _u(endian, "I", tiff, p + 8)
        name = tagmap.get(tag, "Tag_0x%04X" % tag)
        val = _read_value(tiff, endian, typ, cnt, voff, 0)
        if isinstance(val, list) and len(val) == 1:
            val = val[0]
        out[name] = {"raw": val, "type": typ, "_tag": tag}
        p += 12
    next_off = _u(endian, "I", tiff, p) if p + 4 <= len(tiff) else 0
    return out, next_off


def parse_exif(tiff: bytes) -> dict:
    """Walk the full TIFF structure: IFD0, Exif SubIFD, GPS IFD, IFD1."""
    result = {"_present": True}
    if len(tiff) < 8:
        return {"_present": False}
    bo = tiff[:2]
    if bo == b"II":
        endian = "<"
    elif bo == b"MM":
        endian = ">"
    else:
        return {"_present": False, "_error": "bad byte order"}

    ifd0_off = _u(endian, "I", tiff, 4)
    ifd0, next_off = _parse_ifd(tiff, endian, ifd0_off, _TAGS_IFD)

    flat = {}

    def absorb(d, prefix=""):
        for k, v in d.items():
            flat[prefix + k] = _humanize(k, v)

    absorb(ifd0)

    # Decode Windows XP* UTF-16 tags
    for xp in ("XPTitle", "XPComment", "XPAuthor", "XPKeywords", "XPSubject"):
        if xp in ifd0 and isinstance(ifd0[xp]["raw"], list):
            try:
                flat[xp] = bytes(ifd0[xp]["raw"]).decode("utf-16-le").rstrip("\x00")
            except Exception:
                pass

    # Exif SubIFD
    if "ExifIFDPointer" in ifd0:
        off = ifd0["ExifIFDPointer"]["raw"]
        if isinstance(off, int):
            sub, _ = _parse_ifd(tiff, endian, off, _TAGS_EXIF)
            absorb(sub, "Exif.")
            # MakerNote: report presence + vendor hint, do not blindly decode
            if "MakerNote" in sub:
                mn = sub["MakerNote"]["raw"]
                length = len(mn) if isinstance(mn, (bytes, list)) else 0
                flat["Exif.MakerNote"] = (
                    "<present, %d bytes — vendor-specific; "
                    "decode with per-make logic>" % length
                )

    # GPS IFD
    gps_decimal = None
    if "GPSInfoIFDPointer" in ifd0:
        off = ifd0["GPSInfoIFDPointer"]["raw"]
        if isinstance(off, int):
            gps, _ = _parse_ifd(tiff, endian, off, _TAGS_GPS)
            absorb(gps, "GPS.")
            lat = gps.get("GPSLatitude", {}).get("raw")
            latref = gps.get("GPSLatitudeRef", {}).get("raw")
            lon = gps.get("GPSLongitude", {}).get("raw")
            lonref = gps.get("GPSLongitudeRef", {}).get("raw")
            if lat and lon:
                dlat = _gps_to_decimal(lat, latref)
                dlon = _gps_to_decimal(lon, lonref)
                if dlat is not None and dlon is not None:
                    gps_decimal = (dlat, dlon)

    # IFD1 — embedded thumbnail (often un-stripped after a crop!)
    thumb = None
    if next_off:
        ifd1, _ = _parse_ifd(tiff, endian, next_off, _TAGS_IFD)
        absorb(ifd1, "IFD1.")
        toff = ifd1.get("ThumbnailJPEGOffset", {}).get("raw")
        tlen = ifd1.get("ThumbnailJPEGLength", {}).get("raw")
        if isinstance(toff, int) and isinstance(tlen, int) and toff + tlen <= len(tiff):
            thumb = tiff[toff:toff + tlen]

    for ptr in ("ExifIFDPointer", "GPSInfoIFDPointer", "InteropIFDPointer",
                "Exif.InteropIFDPointer"):
        flat.pop(ptr, None)

    return {"_present": True, "tags": flat,
            "gps_decimal": gps_decimal, "_thumbnail": thumb}


def _humanize(name, entry):
    """Turn rationals into readable floats for common tags."""
    raw = entry["raw"]
    if isinstance(raw, tuple) and len(raw) == 2 and all(isinstance(x, int) for x in raw):
        return _rational_to_float(raw)
    if isinstance(raw, list) and raw and isinstance(raw[0], tuple):
        return [_rational_to_float(x) for x in raw]
    return raw


# ============================================================================
#  SECTION 3 — JPEG CONTAINER
# ============================================================================

def parse_jpeg(data: bytes) -> dict:
    out = {"format": "JPEG", "segments": [], "exif": None,
           "xmp": None, "iptc": None, "trailing_offset": None,
           "dimensions": None, "quant_tables": 0, "huffman_tables": 0,
           "compressed_ranges": []}
    if data[:2] != b"\xff\xd8":
        out["_error"] = "no SOI marker"
        return out

    i = 2
    n = len(data)
    while i < n - 1:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7 or marker == 0x01:
            i += 2
            if marker == 0xD9:                      # EOI
                out["trailing_offset"] = i
                break
            continue
        if i + 4 > n:
            break
        seg_len = struct.unpack(">H", data[i + 2:i + 4])[0]
        seg_data = data[i + 4:i + 2 + seg_len]
        name = "0x%02X" % marker
        out["segments"].append({"marker": name, "offset": i, "length": seg_len})

        if marker == 0xE1:                          # APP1
            if seg_data.startswith(b"Exif\x00\x00"):
                out["exif"] = parse_exif(seg_data[6:])
            elif b"http://ns.adobe.com/xap/1.0/" in seg_data[:40]:
                idx = seg_data.find(b"\x00")
                xmp = seg_data[idx + 1:].decode("utf-8", "replace")
                out["xmp"] = xmp
        elif marker == 0xED:                        # APP13 (Photoshop / IPTC)
            out["iptc"] = _extract_iptc(seg_data)
        elif marker == 0xDB:                        # DQT
            out["quant_tables"] += 1
        elif marker == 0xC4:                        # DHT
            out["huffman_tables"] += 1
        elif 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):  # SOFn
            if len(seg_data) >= 5:
                h = struct.unpack(">H", seg_data[1:3])[0]
                w = struct.unpack(">H", seg_data[3:5])[0]
                out["dimensions"] = (w, h)

        if marker == 0xDA:                          # SOS — scan follows
            scan_start = i + 2 + seg_len
            i = scan_start
            while i < n - 1:
                if data[i] == 0xFF and data[i + 1] != 0x00 and not (0xD0 <= data[i + 1] <= 0xD7):
                    break
                i += 1
            out["compressed_ranges"].append((scan_start, i))
            continue
        i = i + 2 + seg_len
    out["chunk_summary"] = _consolidate_chunks(out["segments"])
    return out


def _extract_iptc(app13: bytes) -> dict:
    """Pull IPTC IIM records out of an APP13 Photoshop IRB blob."""
    fields = {}
    idx = app13.find(b"8BIM")
    iim_names = {(2, 5): "ObjectName", (2, 25): "Keywords", (2, 80): "By-line",
                 (2, 90): "City", (2, 95): "Province/State",
                 (2, 101): "Country", (2, 105): "Headline",
                 (2, 116): "Copyright", (2, 120): "Caption",
                 (2, 55): "DateCreated"}
    p = app13.find(b"\x1c")
    while p != -1 and p + 5 <= len(app13):
        if app13[p] != 0x1C:
            p = app13.find(b"\x1c", p + 1)
            continue
        rec = app13[p + 1]
        ds = app13[p + 2]
        ln = struct.unpack(">H", app13[p + 3:p + 5])[0]
        val = app13[p + 5:p + 5 + ln]
        key = iim_names.get((rec, ds), "IIM_%d:%d" % (rec, ds))
        try:
            sval = val.decode("utf-8")
        except Exception:
            sval = val.decode("latin-1", "replace")
        fields.setdefault(key, []).append(sval)
        p = app13.find(b"\x1c", p + 5 + ln)
    return fields or {"_note": "APP13 present, no IPTC IIM records found"}


# ============================================================================
#  SECTION 4 — PNG CONTAINER
# ============================================================================

_PNG_SIG = b"\x89PNG\r\n\x1a\n"


def parse_png(data: bytes) -> dict:
    out = {"format": "PNG", "chunks": [], "text": {}, "exif": None,
           "dimensions": None, "trailing_offset": None, "crc_errors": [],
           "compressed_ranges": []}
    if data[:8] != _PNG_SIG:
        out["_error"] = "bad PNG signature"
        return out
    i = 8
    n = len(data)
    while i + 8 <= n:
        length = struct.unpack(">I", data[i:i + 4])[0]
        ctype = data[i + 4:i + 8].decode("latin-1", "replace")
        cdata = data[i + 8:i + 8 + length]
        crc_stored = data[i + 8 + length:i + 12 + length]
        crc_calc = struct.pack(">I", binascii.crc32(data[i + 4:i + 8 + length]) & 0xFFFFFFFF)
        if crc_stored != crc_calc:
            out["crc_errors"].append({"chunk": ctype, "offset": i})
        out["chunks"].append({"type": ctype, "offset": i, "length": length})

        if ctype == "IHDR" and length >= 8:
            w, h = struct.unpack(">II", cdata[:8])
            out["dimensions"] = (w, h)
            out["bit_depth"] = cdata[8]
            out["color_type"] = cdata[9]
        elif ctype == "IDAT":
            out["compressed_ranges"].append((i + 8, i + 8 + length))
        elif ctype == "tEXt":
            k, _, v = cdata.partition(b"\x00")
            out["text"][k.decode("latin-1", "replace")] = v.decode("latin-1", "replace")
        elif ctype == "zTXt":
            k, _, rest = cdata.partition(b"\x00")
            try:
                v = zlib.decompress(rest[1:]).decode("latin-1", "replace")
            except Exception:
                v = "<zlib decompress failed>"
            out["text"][k.decode("latin-1", "replace")] = v
        elif ctype == "iTXt":
            try:
                k, rest = cdata.split(b"\x00", 1)
                comp_flag = rest[0]
                rest = rest[2:]
                _lang, rest = rest.split(b"\x00", 1)
                _trans, textb = rest.split(b"\x00", 1)
                if comp_flag == 1:
                    textb = zlib.decompress(textb)
                out["text"][k.decode("utf-8", "replace")] = textb.decode("utf-8", "replace")
            except Exception:
                pass
        elif ctype == "eXIf":
            out["exif"] = parse_exif(cdata)
        elif ctype == "tIME" and length >= 7:
            y, = struct.unpack(">H", cdata[:2])
            out["text"]["tIME"] = "%04d-%02d-%02d %02d:%02d:%02d" % (
                y, cdata[2], cdata[3], cdata[4], cdata[5], cdata[6])

        i += 12 + length
        if ctype == "IEND":
            out["trailing_offset"] = i
            break
    out["chunk_summary"] = _consolidate_chunks(out["chunks"])
    return out


def _consolidate_chunks(chunks):
    """Collapse repeated chunk/segment types (e.g. 28x IDAT) into one
    count + total-bytes line so the structure is readable at a glance."""
    summary = {}
    for c in chunks:
        key = c.get("type") or c.get("marker")
        s = summary.setdefault(key, {"count": 0, "total_bytes": 0,
                                     "first_offset": c["offset"]})
        s["count"] += 1
        s["total_bytes"] += c.get("length", 0)
    # drop noise fields when a type appears once
    for k, v in summary.items():
        if v["count"] == 1:
            v.pop("total_bytes", None)
    return summary


# ============================================================================
#  SECTION 5 — STRINGS
# ============================================================================

def extract_strings(data: bytes, minlen=4, limit=None):
    """ASCII and UTF-16LE printable runs with file offsets. limit=None means
    no cap — every run is returned."""
    def capped(n):
        return limit is not None and n >= limit
    ascii_hits = []
    cur = bytearray()
    start = 0
    for idx, b in enumerate(data):
        if 0x20 <= b < 0x7F:
            if not cur:
                start = idx
            cur.append(b)
        else:
            if len(cur) >= minlen:
                ascii_hits.append({"offset": start, "text": cur.decode("ascii")})
                if capped(len(ascii_hits)):
                    break
            cur = bytearray()
    if len(cur) >= minlen and not capped(len(ascii_hits)):
        ascii_hits.append({"offset": start, "text": cur.decode("ascii")})

    utf16_hits = []
    i = 0
    while i < len(data) - 1 and not capped(len(utf16_hits)):
        run = bytearray()
        start = i
        while i < len(data) - 1 and 0x20 <= data[i] < 0x7F and data[i + 1] == 0x00:
            run.append(data[i])
            i += 2
        if len(run) >= minlen:
            utf16_hits.append({"offset": start, "text": run.decode("ascii")})
        else:
            i += 1
    return {"ascii": ascii_hits, "utf16le": utf16_hits}


# ============================================================================
#  SECTION 6 — CARVER  (trailing data + embedded files)
# ============================================================================

_SIGNATURES = [
    (b"PK\x03\x04", "zip/office/jar", ".zip"),
    (b"PK\x05\x06", "zip-empty", ".zip"),
    (b"%PDF", "pdf", ".pdf"),
    (b"\x1f\x8b\x08", "gzip", ".gz"),
    (b"Rar!\x1a\x07", "rar", ".rar"),
    (b"7z\xbc\xaf\x27\x1c", "7zip", ".7z"),
    (b"\x7fELF", "elf-binary", ".elf"),
    (b"MZ", "pe/dos-binary", ".bin"),
    (b"\xff\xd8\xff", "jpeg", ".jpg"),
    (_PNG_SIG, "png", ".png"),
    (b"GIF87a", "gif", ".gif"),
    (b"GIF89a", "gif", ".gif"),
    (b"SQLite format 3\x00", "sqlite-db", ".sqlite"),
    (b"BZh", "bzip2", ".bz2"),
    (b"ID3", "mp3", ".mp3"),
    (b"OggS", "ogg", ".ogg"),
    (b"\x00\x00\x00\x18ftyp", "mp4/mov", ".mp4"),
    (b"-----BEGIN", "pem/key/cert", ".pem"),
]


_WEAK_SIGS = {"pe/dos-binary", "bzip2"}  # short sigs that need structural validation


def _validate_signature(label, data, pos):
    """Weak (short) signatures generate constant false positives inside
    compressed data. Validate the structure behind them before believing it."""
    if label == "pe/dos-binary":                 # "MZ" — 2 bytes, very noisy
        if pos + 0x40 > len(data):
            return False
        e_lfanew = struct.unpack_from("<I", data, pos + 0x3C)[0]
        pe = pos + e_lfanew
        return 0 < e_lfanew < len(data) and pe + 4 <= len(data) \
            and data[pe:pe + 4] == b"PE\x00\x00"
    if label == "bzip2":                          # "BZh" + block-size digit
        return pos + 4 <= len(data) and 0x31 <= data[pos + 3] <= 0x39
    return True                                   # 4+ byte sigs are specific enough


def carve(data: bytes, primary_end: int, compressed_ranges=None, outdir=None):
    """Find appended data past the real end-of-image, plus EVERY embedded
    file signature. Nothing is dropped. Each hit is annotated so you can
    judge it: `in_compressed_stream` (sig sits inside IDAT / JPEG scan, so
    almost certainly DEFLATE noise) and, for the noisy short signatures,
    a `*_validated` field telling you whether the structure behind it checks
    out (e.g. an 'MZ' that actually has a valid PE header)."""
    findings = {"trailing": None, "embedded": []}
    compressed_ranges = compressed_ranges or []

    def in_compressed(p):
        return any(a <= p < b for a, b in compressed_ranges)

    if primary_end and primary_end < len(data):
        trailing = data[primary_end:]
        info = {"offset": primary_end, "size": len(trailing),
                "preview_hex": binascii.hexlify(trailing[:32]).decode()}
        if outdir:
            path = os.path.join(outdir, "trailing_%d.bin" % primary_end)
            with open(path, "wb") as f:
                f.write(trailing)
            info["saved"] = path
        findings["trailing"] = info

    for sig, label, ext in _SIGNATURES:
        start = 0
        while True:
            pos = data.find(sig, start)
            if pos == -1:
                break
            start = pos + 1
            if pos == 0:                          # host file's own header
                continue
            hit = {"offset": pos, "type": label,
                   "sig_hex": binascii.hexlify(sig).decode(),
                   "in_compressed_stream": in_compressed(pos)}
            if label in _WEAK_SIGS:               # annotate, do not suppress
                hit["validated"] = _validate_signature(label, data, pos)
            if outdir and not hit["in_compressed_stream"] and \
                    hit.get("validated", True) and label in (
                    "zip/office/jar", "pdf", "gzip", "rar", "7zip", "sqlite-db"):
                path = os.path.join(outdir, "embedded_%d%s" % (pos, ext))
                with open(path, "wb") as f:
                    f.write(data[pos:])
                hit["saved_from_offset"] = path
            findings["embedded"].append(hit)
    return findings


# ============================================================================
#  SECTION 7 — STEGANOGRAPHY (naive LSB) + ELA  (needs Pillow)
# ============================================================================

def lsb_extract(path: str, max_bytes=65536):
    """Pull least-significant-bit planes out of a lossless image and look for
    readable text or embedded file signatures. Catches naive LSB stego only;
    DCT-domain (JPEG jsteg/F5) is a different problem and is NOT covered."""
    if not HAVE_PIL:
        return {"_note": "Pillow not installed; LSB extraction skipped."}
    try:
        img = Image.open(path).convert("RGB")
    except Exception as e:
        return {"_error": str(e)}

    flat = img.tobytes()
    pixels = [(flat[i], flat[i + 1], flat[i + 2]) for i in range(0, len(flat) - 2, 3)]
    results = {}

    def bits_to_bytes(bits):
        out = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for b in bits[i:i + 8]:
                byte = (byte << 1) | b
            out.append(byte)
        return bytes(out)

    # Combined RGB, and each channel independently
    plans = {
        "rgb_interleaved": lambda p: [c & 1 for px in p for c in px],
        "channel_R": lambda p: [px[0] & 1 for px in p],
        "channel_G": lambda p: [px[1] & 1 for px in p],
        "channel_B": lambda p: [px[2] & 1 for px in p],
    }
    for name, fn in plans.items():
        bits = fn(pixels)[: max_bytes * 8]
        raw = bits_to_bytes(bits)
        interesting = _looks_meaningful(raw)
        if interesting:
            results[name] = interesting
    return results or {"_note": "No obvious LSB payload found "
                                "(naive LSB only; absence is not proof)."}


def _looks_meaningful(raw: bytes):
    """Surface what the LSB plane actually contains. Nothing is judged away.
    NOTE: a clean image's LSB plane is ~random, so short printable runs here
    are usually coincidence — the `entropy` and `printable_ratio` fields and
    the run lengths let you tell signal from noise yourself."""
    out = {}
    # file signatures anywhere in the first stretch
    for sig, label, _ in _SIGNATURES:
        idx = raw[:8192].find(sig)
        if idx != -1:
            out.setdefault("signatures", []).append({"type": label, "offset": idx})
    # printable runs (low threshold — raw view)
    runs = extract_strings(raw, minlen=5, limit=25)["ascii"]
    if runs:
        out["strings"] = [r["text"] for r in runs]
        out["longest_run"] = max(len(r["text"]) for r in runs)
    # cheap randomness signal: clean LSB ~ uniform; real payload skews it
    if raw:
        import collections
        counts = collections.Counter(raw[:65536])
        n = sum(counts.values())
        ent = -sum((c / n) * math.log2(c / n) for c in counts.values())
        out["byte_entropy_bits"] = round(ent, 3)   # ~8.0 = random/clean
        printable = sum(1 for b in raw[:65536] if 0x20 <= b < 0x7F)
        out["printable_ratio"] = round(printable / min(len(raw), 65536), 3)
    return out or None


def error_level_analysis(path: str, outdir: str, quality=90):
    """Re-save as JPEG at fixed quality, diff against original, amplify.
    Edited regions tend to light up. Writes an image you eyeball."""
    if not HAVE_PIL:
        return {"_note": "Pillow not installed; ELA skipped."}
    try:
        orig = Image.open(path).convert("RGB")
        buf = io.BytesIO()
        orig.save(buf, "JPEG", quality=quality)
        buf.seek(0)
        resaved = Image.open(buf)
        diff = ImageChops.difference(orig, resaved)
        extrema = diff.getextrema()
        max_diff = max(e[1] for e in extrema) or 1
        scale = 255.0 / max_diff
        ela = diff.point(lambda x: min(int(x * scale), 255))
        out_path = os.path.join(outdir, "ela.png")
        ela.save(out_path)
        return {"saved": out_path, "max_diff": max_diff,
                "_note": "Bright regions = higher recompression error "
                         "(possible edits). Interpret visually."}
    except Exception as e:
        return {"_error": str(e)}


# ============================================================================
#  SECTION 8 — ORCHESTRATION + REPORT
# ============================================================================

def analyze(path, strings_min=4, do_stego=False, do_ela=False, outdir=None,
            max_strings=None):
    with open(path, "rb") as f:
        data = f.read()

    report = {"file": {"path": os.path.abspath(path),
                       "size_bytes": len(data),
                       "magic_hex": binascii.hexlify(data[:8]).decode()}}
    report["hashes"] = crypto_hashes(data)
    report["perceptual_hashes"] = perceptual_hashes(path)

    if data[:3] == b"\xff\xd8\xff":
        container = parse_jpeg(data)
    elif data[:8] == _PNG_SIG:
        container = parse_png(data)
    else:
        container = {"format": "UNKNOWN",
                     "_error": "not a JPEG or PNG by magic bytes"}
    report["container"] = container

    # surface EXIF cleanly + save thumbnail
    exif = container.get("exif")
    if exif and exif.get("_present"):
        thumb = exif.pop("_thumbnail", None)
        if thumb and outdir:
            tp = os.path.join(outdir, "embedded_thumbnail.jpg")
            with open(tp, "wb") as f:
                f.write(thumb)
            exif["thumbnail_saved"] = tp
        elif thumb:
            exif["thumbnail_present_bytes"] = len(thumb)

    comp_ranges = container.get("compressed_ranges", [])

    def _in_comp(off):
        return any(a <= off < b for a, b in comp_ranges)

    # Keep EVERY string. Annotate which ones fall inside compressed image
    # data (DEFLATE noise) so you can filter if you want — but never drop.
    allstr = extract_strings(data, minlen=strings_min, limit=max_strings)
    for s in allstr["ascii"]:
        s["in_compressed_stream"] = _in_comp(s["offset"])
    for s in allstr["utf16le"]:
        s["in_compressed_stream"] = _in_comp(s["offset"])
    report["strings"] = allstr
    primary_end = container.get("trailing_offset")
    report["carving"] = carve(data, primary_end,
                              compressed_ranges=comp_ranges, outdir=outdir)

    if do_stego:
        report["stego_lsb"] = lsb_extract(path)
    if do_ela and outdir:
        report["ela"] = error_level_analysis(path, outdir)

    report["INTEL_SUMMARY"] = build_summary(report)
    return report


def build_summary(r):
    """The analyst's at-a-glance: the handful of fields that actually matter."""
    s = {}
    c = r.get("container", {})
    exif = c.get("exif") or {}
    tags = exif.get("tags", {})

    s["sha256"] = r["hashes"]["sha256"]
    s["format"] = c.get("format")
    s["dimensions"] = c.get("dimensions")

    gps = exif.get("gps_decimal")
    if gps:
        s["gps"] = {"lat": gps[0], "lon": gps[1],
                    "google_maps": "https://www.google.com/maps?q=%f,%f" % gps,
                    "osm": "https://www.openstreetmap.org/?mlat=%f&mlon=%f#map=17/%f/%f"
                           % (gps[0], gps[1], gps[0], gps[1])}
        if "GPS.GPSImgDirection" in tags:
            s["gps"]["camera_bearing_deg"] = tags["GPS.GPSImgDirection"]

    device = {}
    for k_src, k_dst in (("Make", "make"), ("Model", "model"),
                         ("Exif.LensModel", "lens"),
                         ("Exif.BodySerialNumber", "body_serial"),
                         ("Exif.LensSerialNumber", "lens_serial"),
                         ("Exif.CameraOwnerName", "owner"),
                         ("Software", "software"), ("Artist", "artist")):
        if k_src in tags and tags[k_src] not in ("", None):
            device[k_dst] = tags[k_src]
    if device:
        s["device"] = device

    times = {}
    for k in ("DateTime", "Exif.DateTimeOriginal", "Exif.DateTimeDigitized",
              "Exif.OffsetTimeOriginal", "GPS.GPSDateStamp"):
        if k in tags:
            times[k] = tags[k]
    if times:
        s["timestamps"] = times

    flags = []
    if r.get("carving", {}).get("trailing"):
        flags.append("APPENDED DATA past end-of-image")
    embedded = r.get("carving", {}).get("embedded", [])
    real_embedded = [e for e in embedded
                     if not e.get("in_compressed_stream")
                     and e.get("validated", True)]
    if real_embedded:
        flags.append("%d embedded file signature(s) outside image data" % len(real_embedded))
    if c.get("crc_errors"):
        flags.append("PNG CRC mismatch (possible tampering)")
    if _lsb_is_suspicious(r.get("stego_lsb")):
        flags.append("LSB plane looks non-random (possible payload — verify)")
    if exif.get("thumbnail_saved") or exif.get("thumbnail_present_bytes"):
        flags.append("Embedded thumbnail recovered (check vs full frame)")
    if c.get("xmp"):
        flags.append("XMP metadata present")
    if flags:
        s["FLAGS"] = flags
    return s


def _lsb_is_suspicious(st):
    """Triage heuristic only — the full LSB extraction is always kept in the
    report regardless. Flags a plane whose stats deviate from the ~random
    profile of a clean image: low entropy, high printable ratio, a long
    contiguous run, or a validated file signature."""
    if not isinstance(st, dict):
        return False
    for plane, v in st.items():
        if not isinstance(v, dict):
            continue
        if v.get("byte_entropy_bits", 8.0) < 7.5:
            return True
        if v.get("printable_ratio", 0) > 0.55:
            return True
        if v.get("longest_run", 0) >= 16:
            return True
        for sig in v.get("signatures", []):
            if sig.get("offset") == 0:
                return True
    return False


def build_brief(r):
    """Terser VIEW of the full report. It summarizes and counts rather than
    dumping every string / chunk / LSB run — but it never decides something
    is 'garbage' and hides it. Counts point you back to the full report
    (run without --brief, or with --json) when you want the raw rows."""
    c = r.get("container", {})
    exif = c.get("exif") or {}
    brief = {
        "file": r["file"],
        "hashes": r["hashes"],
        "perceptual_hashes": r["perceptual_hashes"],
        "format": c.get("format"),
        "dimensions": c.get("dimensions"),
        "chunk_summary": c.get("chunk_summary"),
    }
    if exif.get("tags"):
        brief["exif"] = exif["tags"]
    if exif.get("gps_decimal"):
        brief["gps_decimal"] = exif["gps_decimal"]
    if c.get("text"):
        brief["png_text"] = c["text"]
    if c.get("xmp"):
        brief["xmp_present"] = True
    if c.get("iptc"):
        brief["iptc"] = c["iptc"]
    if exif.get("thumbnail_saved") or exif.get("thumbnail_present_bytes"):
        brief["embedded_thumbnail"] = exif.get("thumbnail_saved") or \
            ("%d bytes (use --outdir to save)" % exif["thumbnail_present_bytes"])

    # carving: show every hit, just grouped + counted (nothing dropped)
    carv = r.get("carving", {})
    embedded = carv.get("embedded", [])
    findings = {}
    if carv.get("trailing"):
        findings["trailing_data"] = carv["trailing"]
    if embedded:
        outside = [e for e in embedded if not e.get("in_compressed_stream")]
        inside = [e for e in embedded if e.get("in_compressed_stream")]
        findings["embedded_signatures"] = {
            "outside_image_data": outside,           # the actionable ones, in full
            "inside_compressed_data_count": len(inside),  # likely noise, counted not dumped
        }
    if c.get("crc_errors"):
        findings["png_crc_errors"] = c["crc_errors"]
    if findings:
        brief["findings"] = findings

    # LSB: per-plane stats summary; full string lists stay in the full report
    st = r.get("stego_lsb")
    if isinstance(st, dict) and not st.get("_note") and not st.get("_error"):
        brief["lsb_summary"] = {
            plane: {k: v[k] for k in ("byte_entropy_bits", "printable_ratio",
                                      "longest_run") if isinstance(v, dict) and k in v}
            for plane, v in st.items() if isinstance(v, dict)
        }
        brief["lsb_suspicious"] = _lsb_is_suspicious(st)

    # strings: counts + breakdown, full list lives in the full report
    allstr = r.get("strings", {})
    a = allstr.get("ascii", [])
    in_comp = sum(1 for s in a if s.get("in_compressed_stream"))
    brief["strings"] = {
        "ascii_total": len(a),
        "in_compressed_data": in_comp,
        "outside_compressed_data": len(a) - in_comp,
        "utf16le_total": len(allstr.get("utf16le", [])),
    }
    brief["FLAGS"] = r["INTEL_SUMMARY"].get("FLAGS", [])
    return brief


def _default(o):
    if isinstance(o, bytes):
        return binascii.hexlify(o[:64]).decode() + ("..." if len(o) > 64 else "")
    return str(o)


def print_report(r):
    s = r["INTEL_SUMMARY"]
    line = "=" * 70
    print(line)
    print("  ICONOMAGE — %s" % r["file"]["path"])
    print(line)
    print("Format     : %s   Dimensions: %s" % (s.get("format"), s.get("dimensions")))
    print("Size       : %d bytes" % r["file"]["size_bytes"])
    print("SHA-256    : %s" % s["sha256"])
    ph = r.get("perceptual_hashes", {})
    if "phash" in ph:
        print("pHash/dHash: %s / %s" % (ph.get("phash"), ph.get("dhash")))
    if "gps" in s:
        g = s["gps"]
        print("\n[GPS] %s, %s" % (g["lat"], g["lon"]))
        print("      %s" % g["google_maps"])
        if "camera_bearing_deg" in g:
            print("      camera bearing: %s deg" % g["camera_bearing_deg"])
    if "device" in s:
        print("\n[DEVICE]")
        for k, v in s["device"].items():
            print("      %-12s %s" % (k, v))
    if "timestamps" in s:
        print("\n[TIME]")
        for k, v in s["timestamps"].items():
            print("      %-26s %s" % (k, v))
    if "FLAGS" in s:
        print("\n[FLAGS]")
        for fl in s["FLAGS"]:
            print("      ! %s" % fl)
    na = len(r["strings"]["ascii"])
    nu = len(r["strings"]["utf16le"])
    print("\n[STRINGS] %d ascii, %d utf-16le runs (full list in JSON)" % (na, nu))
    print(line)
    print("Full structured output: use --json to write the complete report.")
    print(line)


def main():
    ap = argparse.ArgumentParser(
        description="iconomage — pure-python image intelligence extractor")
    ap.add_argument("image", help="path to a .jpg or .png")
    ap.add_argument("--json", metavar="FILE", help="write full report as JSON")
    ap.add_argument("--outdir", metavar="DIR",
                    help="directory to save carved files / thumbnail / ELA")
    ap.add_argument("--strings-min", type=int, default=4,
                    help="minimum string length (default 4)")
    ap.add_argument("--max-strings", type=int, default=0,
                    help="cap number of strings returned (0 = unlimited, default)")
    ap.add_argument("--stego", action="store_true",
                    help="run naive LSB extraction (needs Pillow, PNG/BMP)")
    ap.add_argument("--ela", action="store_true",
                    help="run Error Level Analysis (needs Pillow + --outdir)")
    ap.add_argument("--brief", "--simple", dest="brief", action="store_true",
                    help="curated, de-duplicated output (no per-IDAT spam, "
                         "no compression-noise strings/signatures)")
    args = ap.parse_args()

    if not os.path.isfile(args.image):
        sys.exit("No such file: %s" % args.image)
    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)

    report = analyze(args.image, strings_min=args.strings_min,
                     do_stego=args.stego, do_ela=args.ela, outdir=args.outdir,
                     max_strings=(args.max_strings or None))

    out_obj = build_brief(report) if args.brief else report

    if args.brief:
        print(json.dumps(out_obj, indent=2, default=_default))
    else:
        print_report(report)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(out_obj, f, indent=2, default=_default)
        print("Wrote %s" % args.json)


if __name__ == "__main__":
    main()
