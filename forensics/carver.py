"""
carver.py
File carving by signature (magic-byte) detection.

When files are deleted, their data often remains on disk until overwritten.
File carving recovers files by scanning raw data for known header/footer
signatures rather than relying on the filesystem. This module scans a raw
image (or any binary blob) for embedded files and extracts them.

This is a simplified educational implementation of the technique used by tools
like Scalpel and PhotoRec.

For educational / authorised forensic use.
"""

import os

# Signature table: name -> (header bytes, optional footer bytes, max size)
SIGNATURES = {
    "jpg":  (b"\xff\xd8\xff", b"\xff\xd9", 5_000_000),
    "png":  (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", 5_000_000),
    "gif":  (b"GIF87a", b"\x00\x3b", 2_000_000),
    "gif89": (b"GIF89a", b"\x00\x3b", 2_000_000),
    "pdf":  (b"%PDF", b"%%EOF", 10_000_000),
    "zip":  (b"PK\x03\x04", None, 10_000_000),
}


def carve(image_path, output_dir="carved", signatures=None):
    """Scan a raw image for known file signatures and extract them.
    Returns a list of (filetype, offset, output_path, size)."""
    signatures = signatures or SIGNATURES
    os.makedirs(output_dir, exist_ok=True)

    with open(image_path, "rb") as fh:
        data = fh.read()

    recovered = []
    count = 0
    for ftype, (header, footer, max_size) in signatures.items():
        start = 0
        while True:
            idx = data.find(header, start)
            if idx == -1:
                break
            # Determine end of file
            if footer:
                fidx = data.find(footer, idx + len(header))
                end = (fidx + len(footer)) if fidx != -1 else min(idx + max_size, len(data))
            else:
                end = min(idx + max_size, len(data))

            chunk = data[idx:end]
            ext = "gif" if ftype == "gif89" else ftype
            out_path = os.path.join(output_dir, f"recovered_{count}.{ext}")
            with open(out_path, "wb") as out:
                out.write(chunk)
            recovered.append((ext, idx, out_path, len(chunk)))
            print(f"[+] {ext.upper():<4} carved at offset {idx} -> {out_path} ({len(chunk)} bytes)")
            count += 1
            start = end if footer else idx + len(header)

    print(f"[*] Carving complete: {len(recovered)} file(s) recovered.")
    return recovered


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Signature-based file carver")
    parser.add_argument("image", help="Raw image or binary file to carve")
    parser.add_argument("-o", "--output", default="carved")
    args = parser.parse_args()
    carve(args.image, args.output)
