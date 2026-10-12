from __future__ import annotations

from .config import panel_settings
from .models import Rule
from portfw.policy import port_ranges, validate_rules


class RuleValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def is_forbidden_external_port(port: int) -> bool:
    return any(start <= port <= end for start, end in port_ranges(panel_settings().protectedPorts))


def validate_rule_list(raw_rules: list[dict | Rule]) -> list[Rule]:
    if not isinstance(raw_rules, list):
        raise RuleValidationError(["rules must be a JSON array"])
    raw = [rule.model_dump() if isinstance(rule, Rule) else rule for rule in raw_rules]
    try:
        return [Rule.model_validate(rule) for rule in validate_rules(raw, panel_settings())]
    except ValueError as exc:
        raise RuleValidationError([str(exc)]) from exc
