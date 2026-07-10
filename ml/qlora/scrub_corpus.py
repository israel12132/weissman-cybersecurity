#!/usr/bin/env python3
"""
Scrub the exported corpus BEFORE training: redact secrets/PII, de-duplicate, and drop
too-short examples. Training on raw client findings/payloads risks memorising and later
regurgitating a customer secret, so this step is mandatory in the pipeline:

    export_corpus.py  ->  scrub_corpus.py  ->  train_qlora.py

Usage:
    python scrub_corpus.py --in corpus.jsonl --out corpus.clean.jsonl
"""
import argparse
import hashlib
import json
import re

# Order matters: more specific patterns first. Each replaces the match with a typed tag so
# the model still learns the *shape* of a finding without the live secret.
REDACTIONS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{36,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token|authorization)\b\s*[:=]\s*\S+"), r"\1=[REDACTED]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
]


def scrub_text(s: str) -> str:
    for pat, repl in REDACTIONS:
        s = pat.sub(repl, s)
    return s


def scrub_row(row: dict) -> dict:
    return {k: (scrub_text(v) if isinstance(v, str) else v) for k, v in row.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="corpus.jsonl")
    ap.add_argument("--out", dest="out", default="corpus.clean.jsonl")
    ap.add_argument("--min-output-chars", type=int, default=20)
    args = ap.parse_args()

    seen = set()
    kept = dropped_short = dropped_dupe = redacted = 0
    with open(args.inp, encoding="utf-8") as fh, open(args.out, "w", encoding="utf-8") as out:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            cleaned = scrub_row(row)
            if cleaned != row:
                redacted += 1
            if len((cleaned.get("output") or "").strip()) < args.min_output_chars:
                dropped_short += 1
                continue
            key = hashlib.sha256(
                (cleaned.get("instruction", "") + "\x00" + cleaned.get("output", "")).encode()
            ).hexdigest()
            if key in seen:
                dropped_dupe += 1
                continue
            seen.add(key)
            out.write(json.dumps(cleaned, ensure_ascii=False) + "\n")
            kept += 1

    print(
        f"scrub: kept={kept} redacted={redacted} dropped_short={dropped_short} "
        f"dropped_dupe={dropped_dupe} -> {args.out}"
    )
    if kept == 0:
        raise SystemExit("no examples survived scrubbing — check the input corpus")


if __name__ == "__main__":
    main()
