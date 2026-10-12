from __future__ import annotations

import re

from .config import panel_settings
from .models import Rule, SafetyCheck
from portfw.policy import render_nft


def generate_nft(rules: list[Rule]) -> str:
    return render_nft([rule.model_dump() for rule in rules], panel_settings())


def safety_checks(nft_text: str) -> list[SafetyCheck]:
    tables = re.findall(r"(?m)^\s*table\s+\S+\s+\S+", nft_text)
    return [
        SafetyCheck(label="no flush ruleset", ok=not bool(re.search(r"\bflush\s+ruleset\b", nft_text, re.I))),
        SafetyCheck(label="no input hook", ok=not bool(re.search(r"\bhook\s+input\b", nft_text, re.I))),
        SafetyCheck(label="no output hook", ok=not bool(re.search(r"\bhook\s+output\b", nft_text, re.I))),
        SafetyCheck(label="no policy drop", ok=not bool(re.search(r"\bpolicy\s+drop\b", nft_text, re.I))),
        SafetyCheck(label="only table ip pve_portfw", ok=len(tables) == 1 and bool(re.search(r"(?m)^\s*table ip pve_portfw\s*\{", nft_text))),
    ]


def assert_safe_nft(nft_text: str) -> None:
    failures = [check.label for check in safety_checks(nft_text) if not check.ok]
    if failures:
        raise ValueError(f"unsafe generated nft: {', '.join(failures)}")
