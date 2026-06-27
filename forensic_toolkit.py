#!/usr/bin/env python3
"""
forensic_toolkit.py
Digital Forensics Toolkit — unified entry point.

A modular toolkit for collecting and analysing evidence from systems suspected
of compromise. Implements the core forensic workflow: preserve integrity,
analyse artefacts, and document the chain of custody.

    python forensic_toolkit.py hash    evidence.img
    python forensic_toolkit.py verify  evidence.img <sha256>
    python forensic_toolkit.py timeline /path/to/evidence/
    python forensic_toolkit.py carve   disk.img -o recovered/
    python forensic_toolkit.py iocs    memory.dump
    python forensic_toolkit.py custody CASE-001 "A.Sura" "Imaged drive" --evidence disk.img

FOR EDUCATIONAL / AUTHORISED FORENSIC USE ONLY. Analyse only systems and data
you own or are authorised to examine. Mishandling real evidence or data may
have legal consequences.
"""

import argparse
import os
import sys
from forensics import integrity, metadata, carver, artifacts
from forensics.custody import ChainOfCustody


def cmd_hash(args):
    if os.path.isdir(args.target):
        for rel, size, digest in integrity.hash_directory(args.target):
            print(f"{digest}  {size:>10}  {rel}")
    else:
        for algo, digest in integrity.hash_file(args.target).items():
            print(f"{algo}: {digest}")


def cmd_verify(args):
    match, actual = integrity.verify_file(args.target, args.expected, args.algo)
    status = "MATCH — evidence intact" if match else "MISMATCH — evidence altered!"
    print(f"[{status}]\n  expected: {args.expected}\n  actual:   {actual}")
    sys.exit(0 if match else 1)


def cmd_timeline(args):
    records = metadata.collect_metadata(args.target)
    records = metadata.build_timeline(records)
    print(f"{'MODIFIED':<24} {'SIZE':>10}  PATH")
    for r in records:
        print(f"{r['modified']:<24} {r['size_bytes']:>10}  {r['path']}")


def cmd_carve(args):
    carver.carve(args.image, args.output)


def cmd_iocs(args):
    indicators = artifacts.extract_indicators(args.file)
    if not indicators:
        print("[*] No indicators found.")
    for kind, matches in indicators.items():
        print(f"\n[{kind.upper()}] {len(matches)} found:")
        for m in matches:
            print(f"  {m}")


def cmd_custody(args):
    coc = ChainOfCustody(args.case_id, args.examiner)
    coc.record(args.action, args.evidence, args.notes)
    coc.print_log()


def build_parser():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    h = sub.add_parser("hash", help="Hash a file or directory (integrity)")
    h.add_argument("target")
    h.set_defaults(func=cmd_hash)

    v = sub.add_parser("verify", help="Verify a file against an expected hash")
    v.add_argument("target")
    v.add_argument("expected")
    v.add_argument("--algo", default="sha256")
    v.set_defaults(func=cmd_verify)

    t = sub.add_parser("timeline", help="Build a filesystem timeline")
    t.add_argument("target")
    t.set_defaults(func=cmd_timeline)

    c = sub.add_parser("carve", help="Recover files by signature carving")
    c.add_argument("image")
    c.add_argument("-o", "--output", default="carved")
    c.set_defaults(func=cmd_carve)

    i = sub.add_parser("iocs", help="Extract indicators of compromise")
    i.add_argument("file")
    i.set_defaults(func=cmd_iocs)

    cu = sub.add_parser("custody", help="Record a chain-of-custody entry")
    cu.add_argument("case_id")
    cu.add_argument("examiner")
    cu.add_argument("action")
    cu.add_argument("--evidence")
    cu.add_argument("--notes", default="")
    cu.set_defaults(func=cmd_custody)

    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    args.func(args)
