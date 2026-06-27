# Digital Forensics Toolkit

A modular, Python-based toolkit for collecting and analysing evidence from systems suspected of compromise. It implements the core digital-forensics workflow — **preserve integrity → analyse artefacts → document the chain of custody** — as a set of command-line modules.

Built as a CODTECH internship capstone project. It is an educational, from-scratch implementation of techniques found in professional tools such as Autopsy, The Sleuth Kit, Volatility, and Scalpel.

> **For educational / authorised forensic use only.** Analyse only systems and data you own or are explicitly authorised to examine. Mishandling real evidence or personal data may carry legal and ethical consequences. See the chain-of-custody module for defensible evidence handling.

---

## The Forensic Workflow

A defensible examination follows a consistent arc. Each module maps to a stage:

| Stage | Module | Purpose |
|-------|--------|---------|
| **Preserve** | `integrity` | Hash evidence (MD5/SHA-256) to prove it hasn't changed |
| **Analyse — when** | `metadata` | Extract timestamps and build a filesystem timeline |
| **Analyse — recover** | `carver` | Recover deleted/embedded files by signature carving |
| **Analyse — what** | `artifacts` | Extract strings and indicators of compromise (IOCs) |
| **Document** | `custody` | Maintain a tamper-evident chain-of-custody log |

## Modules

### 1. Evidence Integrity (`integrity`)
Computes MD5 and SHA-256 hashes of files, disk images, or whole directory trees, reading in chunks so large images don't exhaust memory. Can verify a file against a previously recorded hash — the foundation of proving evidence integrity.

### 2. Metadata & Timeline (`metadata`)
Reads filesystem timestamps (modified / accessed / changed), size, permissions, and ownership, then assembles a chronological timeline across an evidence set — the standard technique for reconstructing "what happened when".

### 3. File Carver (`carver`)
Scans a raw image for known file signatures (magic bytes) and extracts embedded or deleted files independently of the filesystem. Supports JPG, PNG, GIF, PDF, and ZIP. A simplified educational version of Scalpel/PhotoRec.

### 4. Artifact / IOC Extraction (`artifacts`)
Pulls printable strings from any binary and classifies indicators of compromise: IPv4 addresses, emails, URLs, and cryptocurrency wallet addresses — the kind of triage used on suspicious files and memory dumps.

### 5. Chain of Custody (`custody`)
Maintains an append-only JSON audit log recording every action taken on evidence, with timestamps, examiner name, and a SHA-256 hash of the evidence at each step — what makes a forensic process court-defensible.

## Installation

Requires Python 3.8+. The toolkit uses only the Python standard library — no external dependencies.

```bash
git clone <your-repo-url>
cd forensics_toolkit
python forensic_toolkit.py --help
```

## Usage

```bash
# Preserve: hash an evidence image
python forensic_toolkit.py hash evidence.img

# Preserve: verify integrity against a known hash
python forensic_toolkit.py verify evidence.img <sha256-hash>

# Analyse: build a timeline of a directory of evidence
python forensic_toolkit.py timeline /path/to/evidence/

# Analyse: recover files from a raw image
python forensic_toolkit.py carve disk.img -o recovered/

# Analyse: extract indicators of compromise from a file or memory dump
python forensic_toolkit.py iocs memory.dump

# Document: record a chain-of-custody entry
python forensic_toolkit.py custody CASE-001 "Examiner Name" "Imaged drive" --evidence disk.img --notes "Initial acquisition"
```

## Example Session

```
$ python forensic_toolkit.py hash evidence.img
md5: 8948f7d7ebf88ad0be0a58835c5f9bf1
sha256: 270a99086b3dfedfb145ea461b5463cefa3b0eed0811691dbd4f95129fc374b0

$ python forensic_toolkit.py carve evidence.img -o carved
[+] JPG  carved at offset 40 -> carved/recovered_0.jpg (65 bytes)
[+] PDF  carved at offset 185 -> carved/recovered_1.pdf (79 bytes)
[*] Carving complete: 2 file(s) recovered.

$ python forensic_toolkit.py iocs evidence.img
[IPV4]  192.168.13.37
[EMAIL] admin@evil.example
[URL]   http://malicious.example/payload
[BTC_WALLET] 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

## Project Structure

```
forensics_toolkit/
├── forensic_toolkit.py      # Unified CLI entry point
├── README.md
├── LAB_SETUP.md             # Demonstration walkthrough
├── forensics/
│   ├── __init__.py
│   ├── integrity.py         # Hashing & verification
│   ├── metadata.py          # Metadata & timeline
│   ├── carver.py            # Signature-based file carving
│   ├── artifacts.py         # String & IOC extraction
│   └── custody.py           # Chain-of-custody logging
├── carved/                  # Recovered files (created at runtime)
└── custody_*.json           # Case logs (created at runtime)
```

## Skills Demonstrated

Disk and file analysis, evidence integrity and hashing, timeline reconstruction, file carving / data recovery, IOC extraction, and chain-of-custody / evidence handling — mapped to the principles behind professional forensic suites.

## Limitations & Future Work

- File carving handles common signatures; fragmented files and more formats could be added.
- Timeline reads live filesystem metadata; parsing timestamps from a raw image (e.g. NTFS `$MFT`) would be a deeper extension.
- Possible additions: memory-dump process listing, registry/hive parsing, hash-set matching against known-bad databases, and an HTML case-report generator.

## Legal & Ethical Notice

This toolkit is for **education and authorised investigations only**. Forensic work on real evidence demands proper authorisation, documented procedures, and an unbroken chain of custody. You are solely responsible for ensuring you have the right to examine any data you process with this tool.
