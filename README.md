# iconomage

Single-image intelligence extraction for **JPEG** and **PNG**, in pure Python.

Point it at one image and it pulls everything the file is willing to admit:
cryptographic and perceptual hashes, the full container structure, EXIF /
GPS / IPTC / XMP metadata, embedded thumbnails, printable strings, appended
and embedded files, and (optionally) LSB-steganography extraction and Error
Level Analysis.

The forensic core is **zero-dependency standard library**. Only the
pixel-domain extras (`--stego`, `--ela`, and perceptual hashes) need Pillow.

---

## Requirements

| Feature | Needs |
| --- | --- |
| Metadata, EXIF/GPS, hashes, strings, carving | Python 3 only (stdlib) |
| Perceptual hashes, `--stego`, `--ela` | `pip install pillow` |

---

## Usage

```bash
python3 iconomage.py IMAGE [options]
```

### 1. Quick console summary, nothing written

```bash
python3 iconomage.py sugar_glider.png
```

Prints the at-a-glance intelligence block to the terminal — hashes, GPS (with
map link), device make/model/serial, timestamps, and any flags. Writes no
files. Start here.

### 2. Full structured report to JSON (no files carved)

```bash
python3 iconomage.py sugar_glider.png --json report.json
```

Writes the **complete** report to `report.json`: every chunk, every string
(annotated with whether it sits inside compressed image data), every signature
hit, and all metadata. Nothing is dropped. No files are carved out because
`--outdir` was not given.

### 3. Terse view to stdout (the counts-not-dumps version)

```bash
python3 iconomage.py sugar_glider.png --brief
```

A summarized view: it consolidates repeated chunks (e.g. `IDAT ×20`), reports
string and signature **counts** instead of dumping thousands of rows, and
surfaces the metadata that actually carries intelligence. It hides nothing by
judgment — only by verbosity. Counts point you back to the full report when you
want the raw rows. `--simple` is an alias for `--brief`.

### 4. Brief view written to JSON

```bash
python3 iconomage.py sugar_glider.png --brief --json report.json
```

Same terse view as #3, written to `report.json` instead of stdout. Note this
produces a **smaller** file than #2 from the same image — `--json` writes
whichever view is active.

### 5. Everything — extract stego, ELA, carve all output to a folder

```bash
python3 iconomage.py sugar_glider.png --json report.json --outdir carved/ --stego --ela
```

The full pass. `--outdir carved/` is where extracted artifacts land:

- `trailing_<offset>.bin` — data appended past the real end-of-image
- `embedded_<offset>.<ext>` — embedded files (zip/pdf/gzip/etc.)
- `embedded_thumbnail.jpg` — the EXIF thumbnail (often un-stripped after a crop)
- `ela.png` — the Error Level Analysis image

### 6. Maximal, fully explicit (the kitchen sink)

```bash
python3 iconomage.py sugar_glider.png \
    --json report.json \
    --outdir carved/ \
    --stego \
    --ela \
    --strings-min 5 \
    --max-strings 0
```

Every knob set explicitly. `--strings-min 5` raises the printable-run
threshold from the default of 4; `--max-strings 0` means no cap (the default).

---

## Options

| Option | Description |
| --- | --- |
| `image` | Path to a `.jpg` or `.png` (required, positional) |
| `--json FILE` | Write the report as JSON to `FILE` |
| `--outdir DIR` | Directory for carved files, thumbnail, and ELA image |
| `--strings-min N` | Minimum printable-string length to report (default `4`) |
| `--max-strings N` | Cap on strings returned; `0` = unlimited (default) |
| `--stego` | Run LSB extraction + entropy stats (needs Pillow) |
| `--ela` | Run Error Level Analysis (needs Pillow **and** `--outdir`) |
| `--brief`, `--simple` | Terse summary view instead of the full dump |
| `-h`, `--help` | Show usage |

---

## Gotchas

- **`--ela` does nothing without `--outdir`.** ELA's only output is an image
  file, so it needs somewhere to write it. `--stego` works fine without
  `--outdir` — its findings are returned inline in the report.
- **`--stego` and `--ela` require Pillow.** Without it, those sections are
  skipped with a note; the rest of the tool still runs on stdlib alone.
- **Default output keeps everything.** Signature hits that look like noise
  (e.g. an `MZ` with no valid PE header behind it, or a string buried in
  compressed `IDAT` data) are **annotated**, not deleted. The `validated` and
  `in_compressed_stream` fields let you filter on your own terms. Use `--brief`
  if you want the tool to summarize instead.

---

> **A note:** the running example here is `sugar_glider.png`. If you happen to
> have one nearby — or just a picture of one — take a second to enjoy the sugar
> glider.
