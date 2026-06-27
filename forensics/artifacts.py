"""
artifacts.py
Artifact and indicator extraction (string triage).

Examiners triage files and memory dumps by pulling out human-readable strings
and indicators of compromise (IOCs) — emails, URLs, IP addresses, and other
patterns that point to activity worth investigating. This module extracts
printable strings from any binary and classifies notable indicators.

For educational / authorised forensic use.
"""

import re

# Indicator patterns
PATTERNS = {
    "ipv4": re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email": re.compile(rb"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "url": re.compile(rb"https?://[^\s\"'<>]+"),
    "btc_wallet": re.compile(rb"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
}


def extract_strings(path, min_length=4):
    """Extract printable ASCII strings of at least min_length characters."""
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    with open(path, "rb") as fh:
        data = fh.read()
    return [m.group().decode("ascii", errors="ignore") for m in pattern.finditer(data)]


def extract_indicators(path):
    """Scan a file for IOC patterns and return a dict of {type: [matches]}."""
    with open(path, "rb") as fh:
        data = fh.read()
    found = {}
    for name, pattern in PATTERNS.items():
        matches = sorted({m.decode("ascii", errors="ignore") for m in pattern.findall(data)})
        if matches:
            found[name] = matches
    return found


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Artifact / IOC extractor")
    parser.add_argument("file", help="File or memory dump to analyse")
    parser.add_argument("--strings", action="store_true", help="Dump all strings")
    parser.add_argument("--min-length", type=int, default=4)
    args = parser.parse_args()

    if args.strings:
        for s in extract_strings(args.file, args.min_length):
            print(s)
    else:
        indicators = extract_indicators(args.file)
        if not indicators:
            print("[*] No indicators found.")
        for kind, matches in indicators.items():
            print(f"\n[{kind.upper()}] {len(matches)} found:")
            for m in matches:
                print(f"  {m}")
