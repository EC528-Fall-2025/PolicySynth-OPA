"""
SCP Validation Module

Validates that translated Rego policies behave consistently with their 
original SCP JSON policies.

Features:
- SCP default semantics (implicit Deny as permission boundary)
- Deny priority (explicit Deny takes precedence)
- Action/NotAction and Resource/NotResource mutual exclusivity
- Configurable Rego query and result type interpretation

Process:
1. Syntax validation using 'opa check'
2. Behavioral comparison between SCP and Rego
3. Test execution using 'opa eval'
4. Comprehensive test case generation
"""

import json
import subprocess
import os
import tempfile
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import glob
from pathlib import Path
import re


class Effect(Enum):
    """Policy effect types."""
    ALLOW = "Allow"
    DENY = "Deny"


class Decision(Enum):
    """Policy decision results."""
    ALLOW = "Allow"
    DENY = "Deny"
    ERROR = "Error"


class RegoResultType(Enum):
    """How to interpret Rego evaluation results."""
    DENY_SET = "deny_set"      # Non-empty set/list = Deny
    ALLOW_BOOL = "allow_bool"  # true = Allow, false = Deny
    DENY_BOOL = "deny_bool"    # true = Deny, false = Allow


@dataclass
class TestCase:
    """Represents a single test case for policy validation."""
    action: str
    resource: str
    principal: str = "*"
    context: Dict[str, Any] = field(default_factory=dict)
    expected_effect: Effect = Effect.DENY
    description: str = ""

    def to_opa_input(self) -> Dict[str, Any]:
        """
        Convert test case to OPA input format.
        
        Returns:
            Dictionary suitable for OPA evaluation
        """
        return {
            "action": self.action,
            "resource": self.resource,
            "principal": self.principal,
            "context": self.context
        }


@dataclass
class SyntaxCheckResult:
    """Result of Rego syntax validation."""
    valid: bool
    error_message: str = ""
    warnings: List[str] = field(default_factory=list)


@dataclass
class ComparisonResult:
    """Result of comparing SCP and Rego behavior."""
    test_case: TestCase
    scp_decision: Decision
    rego_decision: Decision
    match: bool
    details: str = ""


@dataclass
class ValidationReport:
    """Complete validation report for a policy."""
    policy_name: str
    syntax_check: SyntaxCheckResult = field(default_factory=lambda: SyntaxCheckResult(valid=False))
    comparison_results: List[ComparisonResult] = field(default_factory=list)
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    match_rate: float = 0.0
    
    def generate_summary(self) -> str:
        """Generate a human-readable summary."""
        summary = []
        summary.append(f"\n{'='*60}")
        summary.append(f"Validation Report: {self.policy_name}")
        summary.append(f"{'='*60}")
        
        summary.append(f"\n[Syntax Check]")
        summary.append(f"Valid: {'✓' if self.syntax_check.valid else '✗'}")
        if not self.syntax_check.valid:
            summary.append(f"Error: {self.syntax_check.error_message}")
        
        summary.append(f"\n[Behavioral Comparison]")
        summary.append(f"Total Tests: {self.total_tests}")
        summary.append(f"Passed: {self.passed_tests} ✓")
        summary.append(f"Failed: {self.failed_tests} ✗")
        summary.append(f"Match Rate: {self.match_rate:.1%}")
        
        if self.failed_tests > 0:
            summary.append(f"\n[Failed Tests]")
            for result in self.comparison_results:
                if not result.match:
                    summary.append(f"\n  Test: {result.test_case.description}")
                    summary.append(f"    Action: {result.test_case.action}")
                    summary.append(f"    Resource: {result.test_case.resource}")
                    summary.append(f"    SCP Decision: {result.scp_decision.value}")
                    summary.append(f"    Rego Decision: {result.rego_decision.value}")
                    summary.append(f"    Details: {result.details}")
        
        summary.append(f"\n{'='*60}\n")
        return "\n".join(summary)


class TestCaseGenerator:
    """Generates test cases from SCP policies."""
    
    @staticmethod
    def normalize_to_list(value: Any) -> List[str]:
        """Normalize a value to a list of strings."""
        if isinstance(value, str):
            return [value]
        elif isinstance(value, list):
            return value
        return []
    
    def generate_from_scp(self, scp_json: Dict[str, Any]) -> List[TestCase]:
        """
        Generate comprehensive test cases from an SCP policy.
        
        Args:
            scp_json: SCP policy document
            
        Returns:
            List of test cases
        """
        test_cases = []
        
        statements = scp_json.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for idx, statement in enumerate(statements):
            effect = Effect(statement.get('Effect', 'Deny'))
            
            has_action = 'Action' in statement
            has_not_action = 'NotAction' in statement
            
            if has_action:
                actions = self.normalize_to_list(statement['Action'])
            elif has_not_action:
                not_actions = self.normalize_to_list(statement['NotAction'])
                actions = []
            else:
                actions = ['*']
            
            has_resource = 'Resource' in statement
            has_not_resource = 'NotResource' in statement
            
            if has_resource:
                resources = self.normalize_to_list(statement['Resource'])
            elif has_not_resource:
                not_resources = self.normalize_to_list(statement['NotResource'])
                resources = []
            else:
                resources = ['*']
            
            conditions = statement.get('Condition', {})
            
            if has_action or (not has_action and not has_not_action):
                test_cases.extend(self._generate_positive_cases(
                    idx, effect, actions, resources, conditions
                ))
            
            if has_not_action:
                test_cases.extend(self._generate_not_action_cases(
                    idx, effect, not_actions, resources, conditions
                ))
            
            if has_not_resource:
                test_cases.extend(self._generate_not_resource_cases(
                    idx, effect, actions if has_action else ['*'], not_resources, conditions
                ))
            
            test_cases.extend(self._generate_negative_cases(
                idx, effect, actions, resources, has_action, has_resource
            ))
            
            if conditions:
                test_cases.extend(self._generate_condition_cases(
                    idx, effect, actions if has_action else ['*'], resources, conditions
                ))
        
        return test_cases
    
    def _generate_positive_cases(
        self, 
        stmt_idx: int,
        effect: Effect,
        actions: List[str],
        resources: List[str],
        conditions: Dict[str, Any]
    ) -> List[TestCase]:
        """Generate test cases that should match the policy."""
        cases = []
        
        if actions and resources:
            action = actions[0] if not actions[0].endswith('*') else self._expand_wildcard_action(actions[0])
            resource = resources[0] if not resources[0].endswith('*') else self._expand_wildcard_resource(resources[0])
            
            cases.append(TestCase(
                action=action,
                resource=resource,
                expected_effect=effect,
                description=f"Statement {stmt_idx}: Positive case - should match policy"
            ))
        
        if '*' in actions:
            cases.append(TestCase(
                action="s3:GetObject",
                resource=resources[0] if resources else "*",
                expected_effect=effect,
                description=f"Statement {stmt_idx}: Wildcard action test"
            ))
        
        if '*' in resources:
            cases.append(TestCase(
                action=actions[0] if actions else "s3:GetObject",
                resource="arn:aws:s3:::example-bucket/*",
                expected_effect=effect,
                description=f"Statement {stmt_idx}: Wildcard resource test"
            ))
        
        return cases
    
    def _generate_not_action_cases(
        self,
        stmt_idx: int,
        effect: Effect,
        not_actions: List[str],
        resources: List[str],
        conditions: Dict[str, Any]
    ) -> List[TestCase]:
        """
        Generate test cases for NotAction.
        
        NotAction means the statement applies to actions NOT in the list.
        """
        cases = []
        
        test_action = "ec2:DescribeInstances"
        if test_action not in not_actions and not any(self._matches_pattern(test_action, na) for na in not_actions):
            cases.append(TestCase(
                action=test_action,
                resource=resources[0] if resources else "*",
                expected_effect=effect,
                description=f"Statement {stmt_idx}: NotAction case - action not in exclusion list"
            ))
        
        if not_actions:
            cases.append(TestCase(
                action=not_actions[0],
                resource=resources[0] if resources else "*",
                expected_effect=Effect.DENY,
                description=f"Statement {stmt_idx}: NotAction case - action in exclusion list"
            ))
        
        return cases
    
    def _generate_not_resource_cases(
        self,
        stmt_idx: int,
        effect: Effect,
        actions: List[str],
        not_resources: List[str],
        conditions: Dict[str, Any]
    ) -> List[TestCase]:
        """
        Generate test cases for NotResource.
        
        NotResource means the statement applies to resources NOT in the list.
        """
        cases = []
        
        test_resource = "arn:aws:s3:::test-bucket/*"
        if test_resource not in not_resources and not any(self._matches_pattern(test_resource, nr) for nr in not_resources):
            cases.append(TestCase(
                action=actions[0] if actions and actions[0] != '*' else "s3:GetObject",
                resource=test_resource,
                expected_effect=effect,
                description=f"Statement {stmt_idx}: NotResource case - resource not in exclusion list"
            ))
        
        if not_resources:
            cases.append(TestCase(
                action=actions[0] if actions and actions[0] != '*' else "s3:GetObject",
                resource=not_resources[0],
                expected_effect=Effect.DENY,
                description=f"Statement {stmt_idx}: NotResource case - resource in exclusion list"
            ))
        
        return cases
    
    def _generate_negative_cases(
        self,
        stmt_idx: int,
        effect: Effect,
        actions: List[str],
        resources: List[str],
        has_action: bool,
        has_resource: bool
    ) -> List[TestCase]:
        """Generate test cases that should NOT match the policy."""
        cases = []
        expected_effect = Effect.DENY
        
        if has_action and actions and '*' not in actions:
            test_action = "ec2:TerminateInstances"
            if not any(self._matches_pattern(test_action, a) for a in actions):
                cases.append(TestCase(
                    action=test_action,
                    resource=resources[0] if resources else "*",
                    expected_effect=expected_effect,
                    description=f"Statement {stmt_idx}: Negative case - different action"
                ))
        
        if has_resource and resources and '*' not in resources:
            test_resource = "arn:aws:s3:::unrelated-bucket/*"
            if not any(self._matches_pattern(test_resource, r) for r in resources):
                cases.append(TestCase(
                    action=actions[0] if actions else "s3:GetObject",
                    resource=test_resource,
                    expected_effect=expected_effect,
                    description=f"Statement {stmt_idx}: Negative case - different resource"
                ))
        
        return cases
    
    def _generate_condition_cases(
        self,
        stmt_idx: int,
        effect: Effect,
        actions: List[str],
        resources: List[str],
        conditions: Dict[str, Any]
    ) -> List[TestCase]:
        """Generate test cases for condition evaluation."""
        cases = []
        
        for condition_type, condition_block in conditions.items():
            for condition_key, condition_values in condition_block.items():
                if isinstance(condition_values, list):
                    context = {condition_key: condition_values[0]}
                else:
                    context = {condition_key: condition_values}
                
                cases.append(TestCase(
                    action=actions[0] if actions and actions[0] != '*' else "s3:GetObject",
                    resource=resources[0] if resources else "*",
                    context=context,
                    expected_effect=effect,
                    description=f"Statement {stmt_idx}: Condition satisfied - {condition_type}:{condition_key}"
                ))
                
                cases.append(TestCase(
                    action=actions[0] if actions and actions[0] != '*' else "s3:GetObject",
                    resource=resources[0] if resources else "*",
                    context={condition_key: "wrong-value-12345"},
                    expected_effect=Effect.DENY,
                    description=f"Statement {stmt_idx}: Condition not satisfied - {condition_type}:{condition_key}"
                ))
        
        return cases
    
    def _expand_wildcard_action(self, action: str) -> str:
        """Convert wildcard action to a concrete example."""
        if action == "*":
            return "s3:GetObject"
        
        if action.endswith('*'):
            prefix = action[:-1]
            if prefix == "s3:":
                return "s3:GetObject"
            elif prefix == "ec2:":
                return "ec2:DescribeInstances"
            elif prefix == "iam:":
                return "iam:GetUser"
            elif prefix == "dynamodb:":
                return "dynamodb:GetItem"
            else:
                return f"{prefix}List"
        
        return action
    
    def _expand_wildcard_resource(self, resource: str) -> str:
        """Convert wildcard resource to a concrete example."""
        if resource == "*":
            return "arn:aws:s3:::example-bucket/example.txt"
        
        if resource.endswith("/*"):
            return resource[:-1] + "example.txt"
        
        return resource
    
    def _matches_pattern(self, value: str, pattern: str) -> bool:
        """
        Check if value matches pattern (supports wildcards).
        
        AWS wildcard matching: * matches any characters including /.
        
        Args:
            value: Value to check
            pattern: Pattern with optional wildcards
            
        Returns:
            True if value matches pattern
        """
        if pattern == '*':
            return True
        
        regex_pattern = re.escape(pattern).replace(r'\*', r'.*')
        return re.match(f'^{regex_pattern}$', value) is not None


class OPARunner:
    """Handles OPA CLI interactions."""
    
    def __init__(self, 
                 opa_path: str = "opa",
                 default_query: str = "data.aws.scp.deny",
                 result_type: RegoResultType = RegoResultType.DENY_SET):
        """
        Initialize OPA runner.
        
        Args:
            opa_path: Path to OPA executable
            default_query: Default OPA query to execute
            result_type: How to interpret Rego results
        """
        self.opa_path = opa_path
        self.default_query = default_query
        self.result_type = result_type
        self._check_opa_available()
    
    def _check_opa_available(self):
        """Check if OPA is available."""
        try:
            result = subprocess.run(
                [self.opa_path, "version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError(f"OPA not available at {self.opa_path}")
        except FileNotFoundError:
            raise RuntimeError(f"OPA executable not found at {self.opa_path}")
        except Exception as e:
            raise RuntimeError(f"Error checking OPA availability: {e}")
    
    def check_syntax(self, rego_code: str) -> SyntaxCheckResult:
        """
        Validate Rego syntax using 'opa check'.
        
        Args:
            rego_code: Rego policy code to validate
            
        Returns:
            Syntax check result
        """
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rego', delete=False) as f:
                temp_file = f.name
                f.write(rego_code)
            
            result = subprocess.run(
                [self.opa_path, "check", temp_file],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return SyntaxCheckResult(valid=True)
            else:
                return SyntaxCheckResult(
                    valid=False,
                    error_message=result.stderr or result.stdout
                )
        
        except Exception as e:
            return SyntaxCheckResult(
                valid=False,
                error_message=f"Syntax check failed: {str(e)}"
            )
        
        finally:
            if temp_file and os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception:
                    pass
    
    def evaluate(self, 
                 rego_code: str, 
                 input_data: Dict[str, Any],
                 query: str = None,
                 result_type: RegoResultType = None) -> Decision:
        """
        Evaluate Rego policy with given input using 'opa eval'.
        
        Args:
            rego_code: Rego policy code
            input_data: Input data for evaluation
            query: OPA query (uses default if None)
            result_type: How to interpret result (uses default if None)
        
        Returns:
            Decision based on Rego evaluation
        """
        if query is None:
            query = self.default_query
        if result_type is None:
            result_type = self.result_type
        
        temp_policy = None
        temp_input = None
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rego', delete=False) as f:
                temp_policy = f.name
                f.write(rego_code)
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                temp_input = f.name
                json.dump(input_data, f)
            
            result = subprocess.run(
                [self.opa_path, "eval",
                 "-d", temp_policy,
                 "-i", temp_input,
                 "--format", "json",
                 query],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                return Decision.ERROR
            
            output = json.loads(result.stdout)
            
            value = None
            if output.get("result"):
                expressions = output["result"][0].get("expressions", [])
                if expressions:
                    value = expressions[0].get("value")
            
            return self._interpret_result(value, result_type)
        
        except Exception as e:
            print(f"Error evaluating Rego: {e}")
            return Decision.ERROR
        
        finally:
            for temp_file in [temp_policy, temp_input]:
                if temp_file and os.path.exists(temp_file):
                    try:
                        os.remove(temp_file)
                    except Exception:
                        pass
    
    def _interpret_result(self, value: Any, result_type: RegoResultType) -> Decision:
        """
        Interpret OPA result based on result type.
        
        Args:
            value: Value from OPA evaluation
            result_type: How to interpret the value
        
        Returns:
            Decision based on interpretation
        """
        if result_type == RegoResultType.DENY_SET:
            if value is None:
                return Decision.ALLOW
            
            if isinstance(value, (list, dict)):
                return Decision.DENY if len(value) > 0 else Decision.ALLOW
            
            print(f"WARNING: DENY_SET mode expects list/dict, got {type(value).__name__}: {value}")
            return Decision.ERROR
        
        elif result_type == RegoResultType.ALLOW_BOOL:
            return Decision.ALLOW if value is True else Decision.DENY
        
        elif result_type == RegoResultType.DENY_BOOL:
            return Decision.DENY if value is True else Decision.ALLOW
        
        else:
            raise ValueError(f"Unknown result_type: {result_type}")


class SCPEvaluator:
    """
    Evaluates SCP policies to determine their decision.
    
    SCP acts as a permission boundary with implicit Deny by default.
    Explicit Deny has highest priority over Allow.
    """
    
    @staticmethod
    def normalize_to_list(value: Any) -> List[str]:
        """Normalize a value to a list of strings."""
        if isinstance(value, str):
            return [value]
        elif isinstance(value, list):
            return value
        return []
    
    def evaluate(self, scp_json: Dict[str, Any], test_case: TestCase) -> Decision:
        """
        Evaluate an SCP policy for a given test case.
        
        SCP Evaluation Logic:
        1. Check for explicit Deny - any match returns Deny immediately
        2. Check for explicit Allow - any match returns Allow
        3. No explicit Allow = implicit Deny (SCP as boundary)
        
        Args:
            scp_json: SCP policy document
            test_case: Test case to evaluate
        
        Returns:
            Decision (ALLOW or DENY)
        """
        statements = scp_json.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        # Pass 1: Check for explicit Deny (highest priority)
        for statement in statements:
            try:
                if self._statement_matches(statement, test_case):
                    effect = statement.get('Effect', 'Deny')
                    if effect == 'Deny':
                        return Decision.DENY
            except ValueError as e:
                print(f"ERROR: Invalid statement in policy: {e}")
                print(f"  Statement: {json.dumps(statement, indent=2)}")
                continue
        
        # Pass 2: Check for explicit Allow
        has_explicit_allow = False
        for statement in statements:
            try:
                if self._statement_matches(statement, test_case):
                    effect = statement.get('Effect')
                    if effect == 'Allow':
                        has_explicit_allow = True
                        break
            except ValueError as e:
                continue
        
        return Decision.ALLOW if has_explicit_allow else Decision.DENY
    
    def _statement_matches(self, statement: Dict[str, Any], test_case: TestCase) -> bool:
        """
        Check if a statement matches the test case.
        
        Args:
            statement: SCP statement
            test_case: Test case to match against
        
        Returns:
            True if statement matches
        
        Raises:
            ValueError: If statement has both Action and NotAction, 
                       or both Resource and NotResource
        """
        # Action/NotAction validation and matching
        has_action = 'Action' in statement
        has_not_action = 'NotAction' in statement
        
        if has_action and has_not_action:
            raise ValueError("Statement cannot have both Action and NotAction")
        
        if has_action:
            actions = self.normalize_to_list(statement['Action'])
            action_matches = any(
                self._matches_pattern(test_case.action, action)
                for action in actions
            )
            if not action_matches:
                return False
        
        elif has_not_action:
            not_actions = self.normalize_to_list(statement['NotAction'])
            if any(self._matches_pattern(test_case.action, action) for action in not_actions):
                return False
        
        # Resource/NotResource validation and matching
        has_resource = 'Resource' in statement
        has_not_resource = 'NotResource' in statement
        
        if has_resource and has_not_resource:
            raise ValueError("Statement cannot have both Resource and NotResource")
        
        if has_resource:
            resources = self.normalize_to_list(statement['Resource'])
            resource_matches = any(
                self._matches_pattern(test_case.resource, resource)
                for resource in resources
            )
            if not resource_matches:
                return False
        
        elif has_not_resource:
            not_resources = self.normalize_to_list(statement['NotResource'])
            if any(self._matches_pattern(test_case.resource, resource) for resource in not_resources):
                return False
        
        # Condition evaluation
        conditions = statement.get('Condition', {})
        if conditions:
            if not self._evaluate_conditions(conditions, test_case.context):
                return False
        
        return True
    
    def _matches_pattern(self, value: str, pattern: str) -> bool:
        """
        Check if value matches pattern (supports wildcards).
        
        AWS wildcard matching: * matches any characters including /.
        
        Args:
            value: Value to check
            pattern: Pattern with optional wildcards
        
        Returns:
            True if value matches pattern
        """
        if pattern == '*':
            return True
        
        regex_pattern = re.escape(pattern).replace(r'\*', r'.*')
        return re.match(f'^{regex_pattern}$', value) is not None
    
    def _evaluate_conditions(self, conditions: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """
        Evaluate condition block.
        
        Args:
            conditions: Condition block from SCP statement
            context: Context from test case
        
        Returns:
            True if all conditions are satisfied
        """
        for condition_type, condition_block in conditions.items():
            for condition_key, condition_values in condition_block.items():
                context_value = context.get(condition_key)
                
                # Normalize condition values to list
                if not isinstance(condition_values, list):
                    condition_values = [condition_values]
                
                # Evaluate based on condition type
                if condition_type == "StringEquals":
                    if context_value not in condition_values:
                        return False
                
                elif condition_type == "StringNotEquals":
                    if context_value in condition_values:
                        return False
                
                elif condition_type == "StringLike":
                    if not any(self._matches_pattern(str(context_value), str(cv)) for cv in condition_values):
                        return False
                
                elif condition_type == "StringNotLike":
                    if any(self._matches_pattern(str(context_value), str(cv)) for cv in condition_values):
                        return False
                
                elif condition_type.startswith("Numeric"):
                    try:
                        ctx_num = float(context_value) if context_value is not None else None
                        cond_nums = [float(cv) for cv in condition_values]
                        
                        if condition_type == "NumericEquals":
                            if ctx_num not in cond_nums:
                                return False
                        elif condition_type == "NumericLessThan":
                            if not (ctx_num is not None and ctx_num < min(cond_nums)):
                                return False
                        elif condition_type == "NumericGreaterThan":
                            if not (ctx_num is not None and ctx_num > max(cond_nums)):
                                return False
                    except (ValueError, TypeError):
                        return False
                
                elif condition_type == "Bool":
                    bool_value = str(context_value).lower() == "true"
                    expected = str(condition_values[0]).lower() == "true"
                    if bool_value != expected:
                        return False
        
        return True


class SCPValidator:
    """Main validator class for SCP to Rego validation."""
    
    def __init__(self, 
                 scp_dir: str = "src/policies/json",
                 rego_dir: str = "src/policies/aws/scp",
                 opa_path: str = "opa",
                 rego_query: str = "data.aws.scp.deny",
                 rego_result_type: RegoResultType = RegoResultType.DENY_SET):
        """
        Initialize the validator.
        
        Args:
            scp_dir: Directory containing original SCP JSON files
            rego_dir: Directory containing translated Rego policies
            opa_path: Path to OPA executable
            rego_query: OPA query to execute
            rego_result_type: How to interpret Rego results
        """
        self.scp_dir = Path(scp_dir)
        self.rego_dir = Path(rego_dir)
        self.opa_runner = OPARunner(opa_path, rego_query, rego_result_type)
        self.scp_evaluator = SCPEvaluator()
        self.test_generator = TestCaseGenerator()
    
    def validate_policy(self, policy_name: str) -> ValidationReport:
        """
        Validate a single policy by comparing SCP JSON and Rego.
        
        Args:
            policy_name: Name of the policy (without extension)
        
        Returns:
            ValidationReport with results
        """
        # Load SCP JSON
        scp_path = self.scp_dir / f"{policy_name}.json"
        if not scp_path.exists():
            raise FileNotFoundError(f"SCP policy not found: {scp_path}")
        
        with open(scp_path, 'r') as f:
            scp_json = json.load(f)
            
        try:
            if isinstance(scp_json, dict):
                if "Policy" in scp_json and isinstance(scp_json["Policy"], dict):
                    content = scp_json["Policy"].get("Content")
                    if isinstance(content, str):
                        scp_json = json.loads(content)
                elif "Content" in scp_json and isinstance(scp_json["Content"], str):
                    scp_json = json.loads(scp_json["Content"])
        except Exception as e:
            print(f"Warning: Error unwrapping policy content: {e}")
        
        # Load Rego policy
        rego_path = self.rego_dir / f"{policy_name}.rego"
        if not rego_path.exists():
            raise FileNotFoundError(f"Rego policy not found: {rego_path}")
        
        with open(rego_path, 'r') as f:
            rego_code = f.read()
        
        report = ValidationReport(policy_name=policy_name)
        
        # Syntax check
        print(f"[1/3] Checking Rego syntax for {policy_name}...")
        report.syntax_check = self.opa_runner.check_syntax(rego_code)
        
        if not report.syntax_check.valid:
            print(f"  ✗ Syntax check failed!")
            return report
        print(f"  ✓ Syntax check passed")
        
        # Generate test cases
        print(f"[2/3] Generating test cases from SCP...")
        test_cases = self.test_generator.generate_from_scp(scp_json)
        report.total_tests = len(test_cases)
        print(f"  Generated {len(test_cases)} test cases")
        
        # Compare behaviors
        print(f"[3/3] Comparing SCP and Rego behaviors...")
        for test_case in test_cases:
            scp_decision = self.scp_evaluator.evaluate(scp_json, test_case)
            rego_decision = self.opa_runner.evaluate(
                rego_code, 
                test_case.to_opa_input()
            )
            
            match = (scp_decision == rego_decision)
            
            result = ComparisonResult(
                test_case=test_case,
                scp_decision=scp_decision,
                rego_decision=rego_decision,
                match=match,
                details="" if match else f"Expected {scp_decision.value}, got {rego_decision.value}"
            )
            
            report.comparison_results.append(result)
            
            if match:
                report.passed_tests += 1
            else:
                report.failed_tests += 1
        
        if report.total_tests > 0:
            report.match_rate = report.passed_tests / report.total_tests
        
        print(f"  Completed: {report.passed_tests}/{report.total_tests} tests passed")
        
        return report
    
    def validate_all_policies(self) -> List[ValidationReport]:
        """Validate all policies in the directories."""
        reports = []
        
        scp_files = list(self.scp_dir.glob("*.json"))
        
        print(f"\nFound {len(scp_files)} SCP policies to validate")
        print(f"{'='*60}\n")
        
        for scp_file in scp_files:
            policy_name = scp_file.stem
            
            try:
                report = self.validate_policy(policy_name)
                reports.append(report)
                print(report.generate_summary())
            
            except FileNotFoundError as e:
                print(f"Warning: {e}")
                continue
            except Exception as e:
                print(f"Error validating {policy_name}: {e}")
                import traceback
                traceback.print_exc()
                continue
        
        return reports
    
    def generate_summary_report(self, reports: List[ValidationReport]) -> str:
        """Generate an overall summary of all validation reports."""
        summary = []
        summary.append("\n" + "="*60)
        summary.append("OVERALL VALIDATION SUMMARY")
        summary.append("="*60)
        
        total_policies = len(reports)
        total_tests = sum(r.total_tests for r in reports)
        total_passed = sum(r.passed_tests for r in reports)
        total_failed = sum(r.failed_tests for r in reports)
        
        policies_with_issues = [r for r in reports if r.failed_tests > 0 or not r.syntax_check.valid]
        
        summary.append(f"\nTotal Policies Validated: {total_policies}")
        summary.append(f"Total Tests Executed: {total_tests}")
        summary.append(f"Total Passed: {total_passed} ✓")
        summary.append(f"Total Failed: {total_failed} ✗")
        summary.append(f"Policies with Issues: {len(policies_with_issues)}")
        
        if total_tests > 0:
            overall_match_rate = total_passed / total_tests
            summary.append(f"Overall Match Rate: {overall_match_rate:.1%}")
        
        if policies_with_issues:
            summary.append(f"\nPolicies requiring attention:")
            for report in policies_with_issues:
                summary.append(f"  - {report.policy_name}: "
                             f"{report.failed_tests}/{report.total_tests} tests failed "
                             f"({report.match_rate:.1%} match rate)")
        
        summary.append("\n" + "="*60 + "\n")
        return "\n".join(summary)


def main():
    """Main entry point for validation."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate SCP to Rego translations")
    parser.add_argument(
        "--policy", 
        type=str, 
        help="Validate a specific policy by name (without extension)"
    )
    parser.add_argument(
        "--scp-dir",
        type=str,
        default="src/policies/json",
        help="Directory containing SCP JSON files"
    )
    parser.add_argument(
        "--rego-dir",
        type=str,
        default="src/policies/aws/scp",
        help="Directory containing Rego policy files"
    )
    parser.add_argument(
        "--opa-path",
        type=str,
        default="opa",
        help="Path to OPA executable"
    )
    parser.add_argument(
        "--rego-query",
        type=str,
        default="data.aws.scp.deny",
        help="OPA query to evaluate (default: data.aws.scp.deny)"
    )
    parser.add_argument(
        "--rego-result-type",
        type=str,
        choices=["deny_set", "allow_bool", "deny_bool"],
        default="deny_set",
        help="How to interpret Rego result: deny_set (non-empty=Deny), allow_bool (true=Allow), deny_bool (true=Deny)"
    )
    parser.add_argument(
        "--fail-on-mismatch",
        action="store_true",
        help="Exit with non-zero code if any tests fail (useful for CI)"
    )
    
    args = parser.parse_args()
    
    result_type_map = {
        "deny_set": RegoResultType.DENY_SET,
        "allow_bool": RegoResultType.ALLOW_BOOL,
        "deny_bool": RegoResultType.DENY_BOOL
    }
    result_type = result_type_map[args.rego_result_type]
    
    try:
        validator = SCPValidator(
            scp_dir=args.scp_dir,
            rego_dir=args.rego_dir,
            opa_path=args.opa_path,
            rego_query=args.rego_query,
            rego_result_type=result_type
        )
        
        has_failures = False
        
        if args.policy:
            report = validator.validate_policy(args.policy)
            print(report.generate_summary())
            
            if not report.syntax_check.valid or report.failed_tests > 0:
                has_failures = True
        else:
            reports = validator.validate_all_policies()
            print(validator.generate_summary_report(reports))
            
            for report in reports:
                if not report.syntax_check.valid or report.failed_tests > 0:
                    has_failures = True
                    break
        
        if has_failures:
            if args.fail_on_mismatch:
                print("\n⚠ Validation failures detected - exiting with code 1")
                return 1
            else:
                print("\n⚠ Validation failures detected (use --fail-on-mismatch to fail CI)")
                return 0
        else:
            print("\n✓ All validations passed!")
            return 0
    
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())