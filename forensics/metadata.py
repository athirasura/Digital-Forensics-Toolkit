"""
metadata.py
File metadata extraction and timeline analysis.

Reconstructing the sequence of events on a system is a core forensic technique.
This module reads filesystem timestamps (modified / accessed / changed), size,
and type information, and can assemble a chronological timeline across a set of
files — the kind of artefact an examiner uses to establish "what happened when".

For educational / authorised forensic use.
"""

import os
import stat
from datetime import datetime, timezone


def _ts(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def file_metadata(path):
    """Return a metadata record for a single file."""
    st = os.stat(path)
    return {
        "path": path,
        "size_bytes": st.st_size,
        "modified": _ts(st.st_mtime),
        "accessed": _ts(st.st_atime),
        "changed": _ts(st.st_ctime),
        "mode": stat.filemode(st.st_mode),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "modified_epoch": st.st_mtime,
    }


def collect_metadata(directory):
    """Walk a directory and gather metadata for every file."""
    records = []
    for root, _, files in os.walk(directory):
        for name in files:
            full = os.path.join(root, name)
            try:
                records.append(file_metadata(full))
            except (OSError, PermissionError):
                continue
    return records


def build_timeline(records):
    """Sort metadata records chronologically by modification time —
    the simplest form of forensic timeline."""
    return sorted(records, key=lambda r: r["modified_epoch"])


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="File metadata & timeline")
    parser.add_argument("path", help="File or directory")
    parser.add_argument("--timeline", action="store_true",
                        help="Output a chronological timeline (directory only)")
    args = parser.parse_args()

    if os.path.isdir(args.path):
        records = collect_metadata(args.path)
        if args.timeline:
            records = build_timeline(records)
            print(f"{'MODIFIED':<24} {'SIZE':>10}  PATH")
            for r in records:
                print(f"{r['modified']:<24} {r['size_bytes']:>10}  {r['path']}")
        else:
            for r in records:
                print(r)
    else:
        for k, v in file_metadata(args.path).items():
            print(f"{k:>16}: {v}")
