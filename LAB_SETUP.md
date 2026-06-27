# Lab Setup & Demonstration Guide

How to demonstrate the Digital Forensics Toolkit safely and capture evidence for your deliverable's "Results" section. Because this toolkit needs no special hardware or vulnerable VM, you can run the whole demonstration on your own machine using synthetic evidence you create.

---

## Why synthetic evidence?

Forensic tools must only be run against data you're authorised to examine. The cleanest, safest way to demonstrate the toolkit is to **build a small "evidence" file yourself** with known content planted inside it — then show the toolkit recovering and analysing exactly what you planted. This proves the tool works without touching anyone's real data.

---

## Part 1 — Create a sample evidence image

Save this as `make_evidence.py` and run it (`python make_evidence.py`). It builds a raw image containing an embedded JPEG, an embedded PDF, and some planted indicators of compromise:

```python
data  = b"JUNK" * 10
data += b"\xff\xd8\xff" + b"fakejpegdata" * 5 + b"\xff\xd9"      # embedded JPEG
data += b"MOREJUNK" * 10
data += b"%PDF" + b"fakepdfcontent" * 5 + b"%%EOF"               # embedded PDF
data += b"Contact admin@evil.example or visit http://malicious.example/payload "
data += b"C2 server at 192.168.13.37 wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
open("evidence.img", "wb").write(data)
print("Created evidence.img:", len(data), "bytes")
```

You now have `evidence.img` to analyse.

---

## Part 2 — Run the toolkit & capture evidence

Run each stage and **screenshot the output**. The narrative follows a real examination.

### 1. Preserve — hash the evidence on acquisition
```bash
python forensic_toolkit.py hash evidence.img
```
Record the SHA-256. This is your acquisition hash — proof of the evidence's state at seizure.

### 2. Preserve — verify integrity
```bash
python forensic_toolkit.py verify evidence.img <paste-the-sha256-here>
```
Shows `MATCH — evidence intact`. Demonstrate the opposite too: edit one byte of the file, re-run, and show the `MISMATCH` result — a powerful illustration of why hashing matters.

### 3. Analyse — recover hidden files
```bash
python forensic_toolkit.py carve evidence.img -o carved
```
The carver recovers the embedded JPEG and PDF into `carved/`. Screenshot the recovery output and the resulting files.

### 4. Analyse — extract indicators of compromise
```bash
python forensic_toolkit.py iocs evidence.img
```
Pulls out the planted IP, email, URL, and Bitcoin wallet — exactly what you'd triage from a compromised host.

### 5. Analyse — build a timeline
```bash
python forensic_toolkit.py timeline .
```
Produces a chronological listing of files in the current directory by modification time.

### 6. Document — record the chain of custody
```bash
python forensic_toolkit.py custody CASE-001 "Your Name" "Imaged drive and computed acquisition hash" --evidence evidence.img --notes "Initial acquisition"
python forensic_toolkit.py custody CASE-001 "Your Name" "Carved deleted files" --evidence evidence.img
```
Each entry is timestamped, attributed, and hash-stamped. Open the generated `custody_CASE-001.json` to show the audit trail.

---

## Part 3 — Write up the results

Add a **Demonstration / Results** section to your documentation containing:

1. A line explaining the synthetic evidence (what you planted and why).
2. Screenshots in workflow order: hash → verify (match and mismatch) → carve → IOCs → custody log.
3. The recovered files from `carved/` and the `custody_CASE-001.json` as evidence artefacts.
4. A short "Findings" paragraph framing it as an examination: evidence acquired and hashed → integrity verified → two deleted files recovered → IOCs identified (C2 IP, malicious URL, attacker email, ransom wallet) → all actions logged to an unbroken chain of custody.

That acquire → preserve → analyse → document narrative is exactly what a reviewer wants to see, and it draws directly on your forensic science and criminology background — making this capstone the most authentic project on the list for your profile.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `carve` recovers nothing | Confirm you're pointing at `evidence.img` created in Part 1. |
| `iocs` finds nothing | Same — the indicators live in the synthetic image. |
| Hashes differ between runs | Expected if you edited the file; that's the integrity check working. |
| Permission errors on `timeline` of a system dir | Point it at a folder you own, like the project directory. |
