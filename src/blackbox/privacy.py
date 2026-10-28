"""Pseudonymise personal data before it reaches the immutable ledger.

An append-only log and the GDPR right to erasure (Art. 17) pull in opposite
directions: you cannot delete a line from a hash chain without breaking it.
The way out is to never write the personal data into the chain at all:

* detected values are replaced by a stable token, ``<EMAIL:9f2c1a7b3e>``,
  computed as an HMAC of the value, so the same customer gets the same token
  across runs and analysis still works;
* the token-to-value mapping lives in a separate vault file;
* erasing a person means deleting their vault entries. The ledger stays
  byte-for-byte identical and still verifies, but the tokens no longer
  resolve to anyone.

Detection is deliberately conservative regex plus checksums (Luhn for cards,
ISO 7064 mod 97 for IBANs). It does not find names or free-text addresses;
see the README for measured precision and recall.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def _card_ok(digits: str) -> bool:
    # Card networks issue 15/16-digit numbers starting with 3 (Amex), 4 (Visa),
    # 5 (Mastercard) or 6 (Discover/UnionPay). Requiring that, plus Luhn,
    # removes most epoch timestamps and random ids that pass Luhn by chance.
    return len(digits) in (15, 16) and digits[0] in "3456" and _luhn_ok(digits)


def _iban_ok(raw: str) -> bool:
    s = raw.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in rearranged)
    return int(num) % 97 == 1


DETECTORS: list[tuple[str, re.Pattern, object]] = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b"), _iban_ok),
    (
        "CARD",
        re.compile(r"\b(?:\d[ -]?){13,19}\b"),
        lambda m: _card_ok(re.sub(r"\D", "", m)),
    ),
    ("PHONE", re.compile(r"(?<![\w+])\+\d{1,3}[ \-]?(?:\(?\d{1,5}\)?[ \-]?){2,5}\d{2,6}\b"), None),
]


class Pseudonymiser:
    def __init__(self, key: bytes, vault: str | Path | None = None):
        self.key = key
        self.vault_path = Path(vault) if vault else None
        self.vault: dict[str, str] = {}
        if self.vault_path and self.vault_path.exists():
            self.vault = json.loads(self.vault_path.read_text())

    def token(self, kind: str, value: str) -> str:
        norm = re.sub(r"\s+", "", value).lower()
        h = hmac.new(self.key, f"{kind}:{norm}".encode(), hashlib.sha256).hexdigest()[:10]
        return f"<{kind}:{h}>"

    def scrub_text(self, text: str) -> tuple[str, list[str]]:
        found: list[str] = []
        for kind, pattern, check in DETECTORS:

            def repl(m: re.Match, kind=kind, check=check) -> str:
                value = m.group(0)
                if check is not None and not check(value):
                    return value
                tok = self.token(kind, value)
                self.vault[tok] = value
                found.append(kind)
                return tok

            text = pattern.sub(repl, text)
        return text, found

    def scrub(self, obj):
        """Recursively scrub strings in dicts, lists and tuples."""
        if isinstance(obj, str):
            return self.scrub_text(obj)[0]
        if isinstance(obj, dict):
            return {k: self.scrub(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.scrub(v) for v in obj]
        return obj

    def reveal(self, text: str) -> str:
        return re.sub(r"<[A-Z]+:[0-9a-f]{10}>", lambda m: self.vault.get(m.group(0), m.group(0)), text)

    def erase(self, value: str) -> int:
        """Forget every token that maps to ``value``. Returns how many were removed."""
        norm = re.sub(r"\s+", "", value).lower()
        doomed = [t for t, v in self.vault.items() if re.sub(r"\s+", "", v).lower() == norm]
        for t in doomed:
            del self.vault[t]
        self.save()
        return len(doomed)

    def save(self) -> None:
        if self.vault_path:
            self.vault_path.parent.mkdir(parents=True, exist_ok=True)
            self.vault_path.write_text(json.dumps(self.vault, indent=1, sort_keys=True))
