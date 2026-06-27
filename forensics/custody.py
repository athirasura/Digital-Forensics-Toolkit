"""
custody.py
Chain-of-custody evidence logging.

A defensible forensic process requires a documented chain of custody: a
tamper-evident record of every item of evidence and every action taken on it,
with timestamps, the examiner's name, and a hash of the evidence at each step.
This module maintains that audit log and can export it for a case file.

For educational / authorised forensic use.
"""

import json
import os
from datetime import datetime, timezone

from .integrity import hash_file


class ChainOfCustody:
    def __init__(self, case_id, examiner, logfile=None):
        self.case_id = case_id
        self.examiner = examiner
        self.logfile = logfile or f"custody_{case_id}.json"
        self.entries = []
        if os.path.exists(self.logfile):
            self._load()

    def _load(self):
        with open(self.logfile) as fh:
            saved = json.load(fh)
            self.entries = saved.get("entries", [])

    def _now(self):
        return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def record(self, action, evidence_path=None, notes=""):
        """Append an entry to the chain of custody. If an evidence path is
        given, its SHA-256 hash is recorded to prove integrity at this step."""
        entry = {
            "sequence": len(self.entries) + 1,
            "timestamp": self._now(),
            "examiner": self.examiner,
            "action": action,
            "evidence": evidence_path,
            "notes": notes,
        }
        if evidence_path and os.path.isfile(evidence_path):
            entry["sha256"] = hash_file(evidence_path, algorithms=("sha256",))["sha256"]
        self.entries.append(entry)
        self._save()
        print(f"[custody] #{entry['sequence']} {action}"
              + (f" — {evidence_path}" if evidence_path else ""))
        return entry

    def _save(self):
        with open(self.logfile, "w") as fh:
            json.dump({
                "case_id": self.case_id,
                "examiner": self.examiner,
                "entries": self.entries,
            }, fh, indent=2)

    def print_log(self):
        print(f"\n=== Chain of Custody — Case {self.case_id} ===")
        print(f"Examiner: {self.examiner}\n")
        for e in self.entries:
            print(f"#{e['sequence']}  {e['timestamp']}")
            print(f"    Action:   {e['action']}")
            if e.get("evidence"):
                print(f"    Evidence: {e['evidence']}")
            if e.get("sha256"):
                print(f"    SHA-256:  {e['sha256']}")
            if e.get("notes"):
                print(f"    Notes:    {e['notes']}")
        print("=" * 45)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Chain-of-custody logger")
    parser.add_argument("case_id")
    parser.add_argument("examiner")
    parser.add_argument("action")
    parser.add_argument("--evidence")
    parser.add_argument("--notes", default="")
    args = parser.parse_args()

    coc = ChainOfCustody(args.case_id, args.examiner)
    coc.record(args.action, args.evidence, args.notes)
    coc.print_log()
