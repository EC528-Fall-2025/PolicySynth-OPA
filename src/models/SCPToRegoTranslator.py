import json
import os
from pathlib import Path
from typing import Dict, List, Any, Set
from datetime import datetime


class SCPToRegoTranslator:
    """Translates AWS SCP JSON policies to OPA Rego format with correct semantics"""
    
    # Fixed package name for all policies
    PACKAGE_NAME = "aws.scp"
    
    def __init__(self, input_dir: str = "src/policies/json", 
                 output_dir: str = "src/policies/aws/scp"):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def translate_all_policies(self) -> Dict[str, str]:
        """
        Translate all SCP JSON files and merge them into a single policy.rego
        This ensures consistent package naming and unified result interface
        """
        if not self.input_dir.exists():
            raise FileNotFoundError(f"Input directory not found: {self.input_dir}")
        
        json_files = list(self.input_dir.glob("*.json"))
        
        if not json_files:
            print(f"No JSON files found in {self.input_dir}")
            return {}
        
        # Collect all policies
        all_policies = []
        for json_file in json_files:
            try:
                with open(json_file, 'r') as f:
                    raw_data = json.load(f)
                    # Unwrap describe-policy format if present
                    policy = self._unwrap_policy(raw_data)
                    all_policies.append({
                        "name": json_file.stem,
                        "policy": policy
                    })
                print(f"Loaded {json_file.name}")
            except Exception as e:
                print(f"Error loading {json_file.name}: {e}")
        
        # Generate unified Rego file
        output_path = self.output_dir / "policy.rego"
        rego_code = self._generate_unified_rego(all_policies)
        
        with open(output_path, 'w') as f:
            f.write(rego_code)
        
        print(f"\n✓ Generated unified policy: {output_path}")
        return {"policy.rego": str(output_path)}
    
    def _generate_unified_rego(self, policies: List[Dict]) -> str:
        """Generate a unified Rego file from all SCP policies"""
        
        rego_lines = [
            "# AWS Service Control Policy (SCP) Translation",
            f"# Generated at: {datetime.now().isoformat()}",
            f"# Source policies: {', '.join([p['name'] for p in policies])}",
            "#",
            "# SCP Semantics:",
            "# - Effective permission = (IAM Allow) ∧ (SCP Allow boundary) ∧ (No explicit Deny)",
            "# - If Allow statements exist: only allowed actions are permitted (allowlist)",
            "# - If no Allow statements: everything allowed by default (except Deny)",
            "# - Deny always takes precedence",
            "",
            f"package {self.PACKAGE_NAME}",
            "",
            "import rego.v1",
            "",
        ]
        
        # Track if ANY policy has Allow statements (determines allowlist mode)
        has_allow_statements = False
        
        # Generate rules for each policy
        all_deny_rules = []
        all_allow_rules = []
        
        for policy_info in policies:
            policy_name = policy_info["name"]
            policy = policy_info["policy"]
            statements = policy.get("Statement", [])
            
            rego_lines.append(f"# Policy: {policy_name}")
            rego_lines.append(f"# Version: {policy.get('Version', '2012-10-17')}")
            rego_lines.append("")
            
            for idx, statement in enumerate(statements):
                effect = statement.get("Effect", "Allow")
                sid = statement.get("Sid", f"{policy_name}_Statement{idx}")
                
                if effect == "Deny":
                    deny_rule = self._generate_deny_rule(statement, sid, policy_name)
                    all_deny_rules.append(deny_rule)
                elif effect == "Allow":
                    has_allow_statements = True
                    allow_rule = self._generate_allow_rule(statement, sid, policy_name)
                    all_allow_rules.append(allow_rule)
        
        # Add all deny rules
        if all_deny_rules:
            rego_lines.append("# ===== DENY RULES =====")
            rego_lines.append("# Deny takes precedence over everything")
            rego_lines.append("")
            rego_lines.extend(all_deny_rules)
        
        # Add all allow rules
        if all_allow_rules:
            rego_lines.append("# ===== ALLOW RULES (Allowlist Mode) =====")
            rego_lines.append("# Only explicitly allowed actions are permitted")
            rego_lines.append("")
            rego_lines.extend(all_allow_rules)
        
        # Add decision logic
        rego_lines.extend(self._generate_decision_logic(has_allow_statements))
        
        # Add helper functions
        rego_lines.extend(self._generate_helper_functions())
        
        return "\n".join(rego_lines)
    
    def _generate_deny_rule(self, statement: Dict, sid: str, policy_name: str) -> str:
        """Generate a deny rule that adds to the denied_by set"""
        actions = self._normalize_list(statement.get("Action", []))
        not_actions = self._normalize_list(statement.get("NotAction", []))
        resources = self._normalize_list(statement.get("Resource", ["*"]))
        not_resources = self._normalize_list(statement.get("NotResource", []))
        conditions = statement.get("Condition", {})
        
        rule_lines = [
            f"# Deny: {sid} (from {policy_name})",
            "denied_by contains reason if {",
        ]
        
        rule_lines.append("    input_action := input.action")
        rule_lines.append("    input_resource := input.resource")
        rule_lines.append("")
        
        # Action matching
        if actions:
            rule_lines.append("    # Match Action")
            action_checks = [f'action_matches(input_action, "{act}")' for act in actions]
            if len(action_checks) == 1:
                rule_lines.append(f"    {action_checks[0]}")
            else:
                rule_lines.append("    (")
                rule_lines.extend([f"        {check}" for check in action_checks[:-1]])
                rule_lines.append(f"        or {action_checks[-1]}")
                rule_lines.append("    )")
        
        if not_actions:
            rule_lines.append("    # Match NotAction (deny everything except these)")
            for act in not_actions:
                rule_lines.append(f'    not action_matches(input_action, "{act}")')
        
        # Resource matching
        if resources and resources != ["*"]:
            rule_lines.append("")
            rule_lines.append("    # Match Resource")
            resource_checks = [f'resource_matches(input_resource, "{res}")' for res in resources]
            if len(resource_checks) == 1:
                rule_lines.append(f"    {resource_checks[0]}")
            else:
                rule_lines.append("    (")
                rule_lines.extend([f"        {check}" for check in resource_checks[:-1]])
                rule_lines.append(f"        or {resource_checks[-1]}")
                rule_lines.append("    )")
        
        if not_resources:
            rule_lines.append("")
            rule_lines.append("    # Match NotResource (deny everything except these)")
            for res in not_resources:
                rule_lines.append(f'    not resource_matches(input_resource, "{res}")')
        
        # Conditions
        if conditions:
            rule_lines.append("")
            rule_lines.append("    # Match Conditions")
            condition_checks = self._generate_condition_checks(conditions)
            rule_lines.extend([f"    {check}" for check in condition_checks])
        
        rule_lines.append("")
        rule_lines.append(f'    reason := "{policy_name}:{sid}"')
        rule_lines.append("}")
        rule_lines.append("")
        
        return "\n".join(rule_lines)
    
    def _generate_allow_rule(self, statement: Dict, sid: str, policy_name: str) -> str:
        """Generate an allow rule that adds to the allowed_by set"""
        actions = self._normalize_list(statement.get("Action", []))
        not_actions = self._normalize_list(statement.get("NotAction", []))
        resources = self._normalize_list(statement.get("Resource", ["*"]))
        not_resources = self._normalize_list(statement.get("NotResource", []))
        conditions = statement.get("Condition", {})
        
        rule_lines = [
            f"# Allow: {sid} (from {policy_name})",
            "allowed_by contains reason if {",
        ]
        
        rule_lines.append("    input_action := input.action")
        rule_lines.append("    input_resource := input.resource")
        rule_lines.append("")
        
        # Action matching
        if actions:
            rule_lines.append("    # Match Action")
            action_checks = [f'action_matches(input_action, "{act}")' for act in actions]
            if len(action_checks) == 1:
                rule_lines.append(f"    {action_checks[0]}")
            else:
                rule_lines.append("    (")
                rule_lines.extend([f"        {check}" for check in action_checks[:-1]])
                rule_lines.append(f"        or {action_checks[-1]}")
                rule_lines.append("    )")
        
        if not_actions:
            rule_lines.append("    # Match NotAction (allow everything except these)")
            for act in not_actions:
                rule_lines.append(f'    not action_matches(input_action, "{act}")')
        
        # Resource matching
        if resources and resources != ["*"]:
            rule_lines.append("")
            rule_lines.append("    # Match Resource")
            resource_checks = [f'resource_matches(input_resource, "{res}")' for res in resources]
            if len(resource_checks) == 1:
                rule_lines.append(f"    {resource_checks[0]}")
            else:
                rule_lines.append("    (")
                rule_lines.extend([f"        {check}" for check in resource_checks[:-1]])
                rule_lines.append(f"        or {resource_checks[-1]}")
                rule_lines.append("    )")
        
        if not_resources:
            rule_lines.append("")
            rule_lines.append("    # Match NotResource")
            for res in not_resources:
                rule_lines.append(f'    not resource_matches(input_resource, "{res}")')
        
        # Conditions
        if conditions:
            rule_lines.append("")
            rule_lines.append("    # Match Conditions")
            condition_checks = self._generate_condition_checks(conditions)
            rule_lines.extend([f"    {check}" for check in condition_checks])
        
        rule_lines.append("")
        rule_lines.append(f'    reason := "{policy_name}:{sid}"')
        rule_lines.append("}")
        rule_lines.append("")
        
        return "\n".join(rule_lines)
    
    def _generate_decision_logic(self, has_allow_statements: bool) -> List[str]:
        """Generate the unified decision logic with correct SCP semantics"""
        lines = [
            "# ===== DECISION LOGIC =====",
            "# Implements correct SCP semantics:",
            "# 1. If denied_by is not empty → DENY (deny takes precedence)",
            "# 2. If has Allow statements:",
            "#    - If allowed_by is not empty → ALLOW",
            "#    - If allowed_by is empty → DENY (allowlist mode)",
            "# 3. If no Allow statements → ALLOW (default allow)",
            "",
        ]
        
        if has_allow_statements:
            lines.extend([
                "# This policy has Allow statements (Allowlist Mode)",
                "default allow := false",
                "",
                "# Allow if explicitly allowed AND not denied",
                "allow if {",
                "    count(allowed_by) > 0",
                "    count(denied_by) == 0",
                "}",
                "",
                "# Deny if explicitly denied OR not in allowlist",
                "deny contains msg if {",
                "    count(denied_by) > 0",
                "    reason := denied_by[_]",
                '    msg := sprintf("Denied by SCP: %s", [reason])',
                "}",
                "",
                "deny contains msg if {",
                "    count(allowed_by) == 0",
                "    count(denied_by) == 0",
                '    msg := "Not in SCP allowlist"',
                "}",
            ])
        else:
            lines.extend([
                "# This policy has NO Allow statements (Default Allow Mode)",
                "default allow := true",
                "",
                "# Allow unless explicitly denied",
                "allow if {",
                "    count(denied_by) == 0",
                "}",
                "",
                "# Deny only if explicitly denied",
                "deny contains msg if {",
                "    count(denied_by) > 0",
                "    reason := denied_by[_]",
                '    msg := sprintf("Denied by SCP: %s", [reason])',
                "}",
            ])
        
        lines.extend([
            "",
            "# ===== UNIFIED RESULT INTERFACE =====",
            "# External systems should consume this standardized result",
            "result := {",
            '    "allow": allow,',
            '    "deny": deny,',
            '    "final": final,',
            '    "allowed_by": allowed_by,',
            '    "denied_by": denied_by,',
            "}",
            "",
            "# Final decision (boolean)",
            "final := allow if {",
            "    count(deny) == 0",
            "}",
            "",
            "final := false if {",
            "    count(deny) > 0",
            "}",
            "",
        ])
        
        return lines
    
    def _generate_helper_functions(self) -> List[str]:
        """Generate helper functions for matching"""
        return [
            "# ===== HELPER FUNCTIONS =====",
            "",
            "# Match action with wildcards (e.g., s3:*, ec2:Describe*)",
            "action_matches(action, pattern) if {",
            '    pattern == "*"',
            "}",
            "",
            "action_matches(action, pattern) if {",
            '    pattern != "*"',
            '    glob.match(pattern, [":"], action)',
            "}",
            "",
            "# Match resource ARN with wildcards",
            "resource_matches(resource, pattern) if {",
            '    pattern == "*"',
            "}",
            "",
            "resource_matches(resource, pattern) if {",
            '    pattern != "*"',
            '    glob.match(pattern, [":"], resource)',
            "}",
            "",
        ]
    
    def _generate_condition_checks(self, conditions: Dict) -> List[str]:
        """Generate Rego code for SCP Condition blocks"""
        checks = []
        
        for condition_op, condition_block in conditions.items():
            for key, values in condition_block.items():
                values_list = self._normalize_list(values)
                
                if condition_op == "StringEquals":
                    value_checks = " or ".join([f'input.context["{key}"] == "{val}"' for val in values_list])
                    checks.append(f"({value_checks})")
                
                elif condition_op == "StringLike":
                    value_checks = " or ".join([f'glob.match("{val}", [], input.context["{key}"])' for val in values_list])
                    checks.append(f"({value_checks})")
                
                elif condition_op == "StringNotEquals":
                    for val in values_list:
                        checks.append(f'input.context["{key}"] != "{val}"')
                
                elif condition_op == "ArnEquals":
                    value_checks = " or ".join([f'input.context["{key}"] == "{val}"' for val in values_list])
                    checks.append(f"({value_checks})")
                
                elif condition_op == "ArnLike":
                    value_checks = " or ".join([f'glob.match("{val}", [":"], input.context["{key}"])' for val in values_list])
                    checks.append(f"({value_checks})")
                
                elif condition_op == "Bool":
                    for val in values_list:
                        bool_val = str(val).lower()
                        checks.append(f'input.context["{key}"] == {bool_val}')
                
                else:
                    checks.append(f'# TODO: Implement condition operator {condition_op}')
        
        return checks
    
    def _normalize_list(self, value: Any) -> List[str]:
        """Convert single value or list to list of strings"""
        if isinstance(value, list):
            return value
        return [value] if value else []


def main():
    """Main function to run the translator"""
    translator = SCPToRegoTranslator()
    
    print("=" * 70)
    print("SCP to Rego Policy Translator (Correct SCP Semantics)")
    print("=" * 70)
    print(f"Input directory:  {translator.input_dir}")
    print(f"Output directory: {translator.output_dir}")
    print(f"Package name:     {translator.PACKAGE_NAME}")
    print()
    
    results = translator.translate_all_policies()
    
    print()
    print("=" * 70)
    print("Translation complete!")
    print(f"Generated unified policy with fixed package: {translator.PACKAGE_NAME}")
    print("Access result via: data.aws.scp.result")
    print("=" * 70)


if __name__ == "__main__":
    main()