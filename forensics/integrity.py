"""
integrity.py
Evidence integrity via cryptographic hashing.

In digital forensics, hashing proves that an item of evidence has not been
altered between acquisition and analysis. This module computes MD5 and SHA-256
hashes and can verify a file against a previously recorded hash.

For educational / authorised forensic use.
"""

import hashlib
import os


def hash_file(path, algorithms=("md5", "sha256"), block_size=65536):
    """Return a dict of {algorithm: hexdigest} for a file, read in chunks
    so even large disk images don't exhaust memory."""
    hashers = {name: hashlib.new(name) for name in algorithms}
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(block_size), b""):
            for h in hashers.values():
                h.update(block)
    return {name: h.hexdigest() for name, h in hashers.items()}


def verify_file(path, expected_hash, algorithm="sha256"):
    """Recompute a file's hash and compare to an expected value.
    Returns (is_match, actual_hash)."""
    actual = hash_file(path, algorithms=(algorithm,))[algorithm]
    return actual.lower() == expected_hash.lower(), actual


def hash_directory(directory, algorithm="sha256"):
    """Hash every file under a directory tree — useful for baselining an
    evidence set. Returns a list of (relative_path, size, hash)."""
    results = []
    for root, _, files in os.walk(directory):
        for name in files:
            full = os.path.join(root, name)
            try:
                digest = hash_file(full, algorithms=(algorithm,))[algorithm]
                size = os.path.getsize(full)
                results.append((os.path.relpath(full, directory), size, digest))
            except (OSError, PermissionError):
                continue
    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Evidence integrity hashing")
    parser.add_argument("path", help="File or directory to hash")
    parser.add_argument("--verify", help="Expected hash to verify against")
    parser.add_argument("--algo", default="sha256")
    args = parser.parse_args()

    if args.verify:
        match, actual = verify_file(args.path, args.verify, args.algo)
        print(f"[{'MATCH' if match else 'MISMATCH'}] {args.algo}: {actual}")
    elif os.path.isdir(args.path):
        for rel, size, digest in hash_directory(args.path, args.algo):
            print(f"{digest}  {size:>10}  {rel}")
    else:
        for algo, digest in hash_file(args.path).items():
            print(f"{algo}: {digest}")
