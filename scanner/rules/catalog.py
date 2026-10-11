"""Central rule catalog for OWASP Sentinel."""

from typing import List, Dict, Optional
from ..models import Rule, OWASPCategory
from . import (
    a01_broken_access,
    a02_crypto_failures,
    a03_injection,
    a04_insecure_design,
    a05_misconfiguration,
    a06_vulnerable_components,
    a07_auth_failures,
    a08_integrity_failures,
    a09_logging_failures,
    a10_ssrf,
    iac_rules,
    api_security,
    cis_container_rules,
    cwe_core_rules,
    cicd_supply_chain_rules,
)


class RuleCatalog:
    def __init__(self):
        self._rules: List[Rule] = []
        self._rules_by_id: Dict[str, Rule] = {}
        self._load_all_rules()

    def _load_all_rules(self):
        modules = [
            a01_broken_access,
            a02_crypto_failures,
            a03_injection,
            a04_insecure_design,
            a05_misconfiguration,
            a06_vulnerable_components,
            a07_auth_failures,
            a08_integrity_failures,
            a09_logging_failures,
            a10_ssrf,
            iac_rules,
            api_security,
            cis_container_rules,
            cwe_core_rules,
            cicd_supply_chain_rules,
        ]
        for mod in modules:
            if hasattr(mod, "RULES"):
                for rule in mod.RULES:
                    self._rules.append(rule)
                    self._rules_by_id[rule.id] = rule

    def get_all_rules(self) -> List[Rule]:
        return self._rules

    def get_rule_by_id(self, rule_id: str) -> Optional[Rule]:
        return self._rules_by_id.get(rule_id)

    def get_rules_by_category(self, category: OWASPCategory) -> List[Rule]:
        return [r for r in self._rules if r.category == category]

    def get_rules_by_framework(self, framework: str) -> List[Rule]:
        return [
            r for r in self._rules
            if framework in getattr(r, "frameworks", []) or getattr(r, "standard", "") == framework
        ]

    def get_rules_for_language(self, ext: str) -> List[Rule]:
        """Return rules that apply to a given file extension without leading dot."""
        clean_ext = ext.lstrip(".").lower()
        return [
            r for r in self._rules
            if "*" in r.languages or clean_ext in r.languages
        ]

    def register_rule(self, rule: Rule):
        """Add or override a rule dynamically."""
        self._rules = [r for r in self._rules if r.id != rule.id]
        self._rules.append(rule)
        self._rules_by_id[rule.id] = rule

    def unregister_rule(self, rule_id: str):
        """Remove a rule by ID."""
        self._rules = [r for r in self._rules if r.id != rule_id]
        self._rules_by_id.pop(rule_id, None)

    def load_custom_rules(self, custom_rules: List[Rule]):
        """Load a batch of user custom rules."""
        for r in custom_rules:
            self.register_rule(r)


# Singleton catalog instance
catalog = RuleCatalog()
