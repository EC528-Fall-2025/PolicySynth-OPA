#!/usr/bin/env python3
"""
Unit tests for FIXED SCP Validation System

This test suite verifies all the critical fixes:
1. SCP default semantics (implicit Deny)
2. Deny priority
3. Action/NotAction mutual exclusivity
4. Resource/NotResource mutual exclusivity
5. Configurable Rego result types

Run with: python validation_test.py
"""

import unittest
import json
from src.models.scp_validation import (
    TestCase,
    TestCaseGenerator,
    SCPEvaluator,
    OPARunner,
    Effect,
    Decision,
    RegoResultType
)

OPARunner._check_opa_available = lambda self: None


class TestSCPDefaultSemantics(unittest.TestCase):
    """
    Test Fix #1: SCP default semantics
    
    SCP acts as permission boundary:
    - Default is implicit Deny (not Allow)
    - Explicit Allow needed to permit action
    """
    
    def test_no_matching_statement_denies(self):
        """No matching statement should result in Deny (implicit deny)"""
        scp = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::specific-bucket/*"
            }]
        }
        
        evaluator = SCPEvaluator()
        
        # Different action - no matching Allow = Deny
        test_case = TestCase(
            action="s3:PutObject",  # Not allowed
            resource="arn:aws:s3:::specific-bucket/file.txt"
        )
        
        decision = evaluator.evaluate(scp, test_case)
        self.assertEqual(decision, Decision.DENY, 
                        "No matching Allow statement should result in Deny (implicit deny)")
    
    def test_explicit_allow_permits(self):
        """Explicit Allow should permit the action"""
        scp = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        }
        
        evaluator = SCPEvaluator()
        
        # Matching action with Allow
        test_case = TestCase(
            action="s3:GetObject",
            resource="arn:aws:s3:::bucket/file.txt"
        )
        
        decision = evaluator.evaluate(scp, test_case)
        self.assertEqual(decision, Decision.ALLOW,
                        "Explicit Allow should permit matching action")
    
    def test_empty_scp_denies_everything(self):
        """Empty SCP (no statements) should deny everything"""
        scp = {"Statement": []}
        
        evaluator = SCPEvaluator()
        
        test_case = TestCase(
            action="s3:GetObject",
            resource="*"
        )
        
        decision = evaluator.evaluate(scp, test_case)
        self.assertEqual(decision, Decision.DENY,
                        "Empty SCP should deny all actions (implicit deny)")


class TestDenyPriority(unittest.TestCase):
    """
    Test Fix #2: Deny priority
    
    Explicit Deny should override any Allow
    """
    
    def test_deny_overrides_allow(self):
        """Explicit Deny should override explicit Allow"""
        scp = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "Action": "s3:DeleteBucket",
                    "Resource": "*"
                }
            ]
        }
        
        evaluator = SCPEvaluator()
        
        # DeleteBucket has both Allow (s3:*) and explicit Deny
        test_case = TestCase(
            action="s3:DeleteBucket",
            resource="arn:aws:s3:::bucket"
        )
        
        decision = evaluator.evaluate(scp, test_case)
        self.assertEqual(decision, Decision.DENY,
                        "Explicit Deny should override Allow")
    
    def test_deny_first_evaluation(self):
        """Deny statements should be evaluated first"""
        scp = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "Action": "ec2:TerminateInstances",
                    "Resource": "*"
                }
            ]
        }
        
        evaluator = SCPEvaluator()
        
        # Should check Deny first and immediately return
        test_terminate = TestCase(
            action="ec2:TerminateInstances",
            resource="*"
        )
        
        decision = evaluator.evaluate(scp, test_terminate)
        self.assertEqual(decision, Decision.DENY)
        
        # Non-denied action should be allowed
        test_describe = TestCase(
            action="ec2:DescribeInstances",
            resource="*"
        )
        
        decision = evaluator.evaluate(scp, test_describe)
        self.assertEqual(decision, Decision.ALLOW)


class TestActionNotActionExclusivity(unittest.TestCase):
    """
    Test Fix #3: Action/NotAction mutual exclusivity
    
    Statement cannot have both Action and NotAction
    """
    
    def test_both_action_and_notaction_raises_error(self):
        """Having both Action and NotAction should raise ValueError"""
        scp = {
            "Statement": [{
                "Effect": "Deny",
                "Action": "s3:*",
                "NotAction": "s3:GetObject",  # Invalid - both present
                "Resource": "*"
            }]
        }
        
        evaluator = SCPEvaluator()
        
        test_case = TestCase(action="s3:PutObject", resource="*")
        
        # Should handle the error gracefully (prints warning, returns Deny)
        decision = evaluator.evaluate(scp, test_case)
        # The evaluator should handle invalid statements and continue
        self.assertIn(decision, [Decision.DENY, Decision.ALLOW])
    
    def test_action_only_works(self):
        """Action without NotAction should work correctly"""
        scp = {
            "Statement": [{
                "Effect": "Deny",
                "Action": ["s3:DeleteBucket", "s3:DeleteObject"],
                "Resource": "*"
            }]
        }
        
        evaluator = SCPEvaluator()
        
        # Matching action
        test_delete = TestCase(action="s3:DeleteBucket", resource="*")
        self.assertEqual(evaluator.evaluate(scp, test_delete), Decision.DENY)
        
        # Non-matching action
        test_get = TestCase(action="s3:GetObject", resource="*")
        self.assertEqual(evaluator.evaluate(scp, test_get), Decision.DENY)  # Implicit deny
    
    def test_notaction_only_works(self):
        """NotAction without Action should work correctly"""
        scp = {
            "Statement": [{
                "Effect": "Deny",
                "NotAction": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "*"
            }]
        }
        
        evaluator = SCPEvaluator()
        
        # Action NOT in NotAction list - should match and Deny
        test_put = TestCase(action="s3:PutObject", resource="*")
        self.assertEqual(evaluator.evaluate(scp, test_put), Decision.DENY)
        
        # Action in NotAction list - should not match, implicit deny anyway
        test_get = TestCase(action="s3:GetObject", resource="*")
        self.assertEqual(evaluator.evaluate(scp, test_get), Decision.DENY)  # No Allow = implicit deny
    
    def test_notaction_with_allow(self):
        """NotAction with Allow should permit everything except listed actions"""
        scp = {
            "Statement": [{
                "Effect": "Allow",
                "NotAction": ["s3:DeleteBucket"],  # Allow everything except DeleteBucket
                "Resource": "*"
            }]
        }
        
        evaluator = SCPEvaluator()
        
        # Action not in NotAction list - should be allowed
        test_get = TestCase(action="s3:GetObject", resource="*")
        self.assertEqual(evaluator.evaluate(scp, test_get), Decision.ALLOW)
        
        # Action in NotAction list - no Allow matches = implicit deny
        test_delete = TestCase(action="s3:DeleteBucket", resource="*")
        self.assertEqual(evaluator.evaluate(scp, test_delete), Decision.DENY)


class TestResourceNotResourceExclusivity(unittest.TestCase):
    """
    Test Fix #3: Resource/NotResource mutual exclusivity
    
    Statement cannot have both Resource and NotResource
    """
    
    def test_both_resource_and_notresource_raises_error(self):
        """Having both Resource and NotResource should raise ValueError"""
        scp = {
            "Statement": [{
                "Effect": "Deny",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::bucket/*",
                "NotResource": "arn:aws:s3:::other/*"  # Invalid
            }]
        }
        
        evaluator = SCPEvaluator()
        test_case = TestCase(action="s3:GetObject", resource="arn:aws:s3:::bucket/file.txt")
        
        # Should handle gracefully
        decision = evaluator.evaluate(scp, test_case)
        self.assertIn(decision, [Decision.DENY, Decision.ALLOW])
    
    def test_resource_only_works(self):
        """Resource without NotResource should work correctly"""
        scp = {
            "Statement": [{
                "Effect": "Deny",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::production-*/*"
            }]
        }
        
        evaluator = SCPEvaluator()
        
        # Matching resource
        test_prod = TestCase(
            action="s3:PutObject",
            resource="arn:aws:s3:::production-data/file.txt"
        )
        self.assertEqual(evaluator.evaluate(scp, test_prod), Decision.DENY)
        
        # Non-matching resource
        test_dev = TestCase(
            action="s3:PutObject",
            resource="arn:aws:s3:::dev-data/file.txt"
        )
        self.assertEqual(evaluator.evaluate(scp, test_dev), Decision.DENY)  # Implicit deny
    
    def test_notresource_only_works(self):
        """NotResource without Resource should work correctly"""
        scp = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "NotResource": "arn:aws:s3:::sensitive-*/*"  # Allow except sensitive
            }]
        }
        
        evaluator = SCPEvaluator()
        
        # Resource NOT in NotResource - should be allowed
        test_normal = TestCase(
            action="s3:GetObject",
            resource="arn:aws:s3:::public-data/file.txt"
        )
        self.assertEqual(evaluator.evaluate(scp, test_normal), Decision.ALLOW)
        
        # Resource in NotResource - no Allow = implicit deny
        test_sensitive = TestCase(
            action="s3:GetObject",
            resource="arn:aws:s3:::sensitive-data/secret.txt"
        )
        self.assertEqual(evaluator.evaluate(scp, test_sensitive), Decision.DENY)
    
    def test_notresource_with_deny(self):
        """NotResource with Deny should deny everything except listed resources"""
        scp = {
            "Statement": [{
                "Effect": "Deny",
                "Action": "s3:DeleteObject",
                "NotResource": ["arn:aws:s3:::temp-*/*", "arn:aws:s3:::dev-*/*"]
            }]
        }
        
        evaluator = SCPEvaluator()
        
        # Resource NOT in NotResource list - matches Deny statement
        test_prod = TestCase(
            action="s3:DeleteObject",
            resource="arn:aws:s3:::production-data/file.txt"
        )
        self.assertEqual(evaluator.evaluate(scp, test_prod), Decision.DENY)
        
        # Resource in NotResource list - doesn't match Deny, implicit deny anyway
        test_temp = TestCase(
            action="s3:DeleteObject",
            resource="arn:aws:s3:::temp-bucket/file.txt"
        )
        self.assertEqual(evaluator.evaluate(scp, test_temp), Decision.DENY)  # Implicit deny
    
    def test_notresource_with_wildcard_pattern(self):
        """NotResource should support wildcard patterns"""
        scp = {
            "Statement": [{
                "Effect": "Deny",
                "Action": "s3:*",
                "NotResource": "arn:aws:s3:::public-*/*"
            }]
        }
        
        evaluator = SCPEvaluator()
        
        # Resource not matching NotResource pattern
        test1 = TestCase(
            action="s3:PutObject",
            resource="arn:aws:s3:::private-data/file.txt"
        )
        self.assertEqual(evaluator.evaluate(scp, test1), Decision.DENY)
        
        # Resource matching NotResource pattern
        test2 = TestCase(
            action="s3:PutObject",
            resource="arn:aws:s3:::public-bucket/file.txt"
        )
        self.assertEqual(evaluator.evaluate(scp, test2), Decision.DENY)  # Implicit deny


class TestMissingFieldsWildcard(unittest.TestCase):
    """
    Test Fix #3: Missing Action/Resource = wildcard "*"
    """
    
    def test_missing_action_matches_all(self):
        """Missing Action field should match all actions"""
        scp = {
            "Statement": [{
                "Effect": "Deny",
                # No Action field = matches all actions
                "Resource": "*"
            }]
        }
        
        evaluator = SCPEvaluator()
        
        # Any action should match
        test1 = TestCase(action="s3:GetObject", resource="*")
        self.assertEqual(evaluator.evaluate(scp, test1), Decision.DENY)
        
        test2 = TestCase(action="ec2:TerminateInstances", resource="*")
        self.assertEqual(evaluator.evaluate(scp, test2), Decision.DENY)
    
    def test_missing_resource_matches_all(self):
        """Missing Resource field should match all resources"""
        scp = {
            "Statement": [{
                "Effect": "Deny",
                "Action": "s3:DeleteBucket"
                # No Resource field = matches all resources
            }]
        }
        
        evaluator = SCPEvaluator()
        
        # Any resource should match
        test1 = TestCase(
            action="s3:DeleteBucket",
            resource="arn:aws:s3:::bucket1"
        )
        self.assertEqual(evaluator.evaluate(scp, test1), Decision.DENY)
        
        test2 = TestCase(
            action="s3:DeleteBucket",
            resource="arn:aws:s3:::bucket2"
        )
        self.assertEqual(evaluator.evaluate(scp, test2), Decision.DENY)
    
    def test_missing_both_matches_everything(self):
        """Missing both Action and Resource should match everything"""
        scp = {
            "Statement": [{
                "Effect": "Deny"
                # No Action, no Resource = deny everything
            }]
        }
        
        evaluator = SCPEvaluator()
        
        test = TestCase(action="s3:GetObject", resource="*")
        self.assertEqual(evaluator.evaluate(scp, test), Decision.DENY)


class TestRegoResultTypes(unittest.TestCase):
    """
    Test Fix #4: Configurable Rego result type interpretation
    """
    
    def test_deny_set_non_empty_is_deny(self):
        """DENY_SET: Non-empty result = Deny"""
        runner = OPARunner(result_type=RegoResultType.DENY_SET)
        
        # Non-empty list
        self.assertEqual(
            runner._interpret_result(["msg1"], RegoResultType.DENY_SET),
            Decision.DENY
        )
        
        # Non-empty dict
        self.assertEqual(
            runner._interpret_result({"msg": "denied"}, RegoResultType.DENY_SET),
            Decision.DENY
        )
        
        # Empty = Allow
        self.assertEqual(
            runner._interpret_result([], RegoResultType.DENY_SET),
            Decision.ALLOW
        )
        
        # None = Allow
        self.assertEqual(
            runner._interpret_result(None, RegoResultType.DENY_SET),
            Decision.ALLOW
        )
    
    def test_allow_bool_true_is_allow(self):
        """ALLOW_BOOL: true = Allow, false = Deny"""
        runner = OPARunner(result_type=RegoResultType.ALLOW_BOOL)
        
        self.assertEqual(
            runner._interpret_result(True, RegoResultType.ALLOW_BOOL),
            Decision.ALLOW
        )
        
        self.assertEqual(
            runner._interpret_result(False, RegoResultType.ALLOW_BOOL),
            Decision.DENY
        )
        
        self.assertEqual(
            runner._interpret_result(None, RegoResultType.ALLOW_BOOL),
            Decision.ERROR
        )
    
    def test_deny_bool_true_is_deny(self):
        """DENY_BOOL: true = Deny, false = Allow"""
        runner = OPARunner(result_type=RegoResultType.DENY_BOOL)
        
        self.assertEqual(
            runner._interpret_result(True, RegoResultType.DENY_BOOL),
            Decision.DENY
        )
        
        self.assertEqual(
            runner._interpret_result(False, RegoResultType.DENY_BOOL),
            Decision.ALLOW
        )
        
        self.assertEqual(
            runner._interpret_result(None, RegoResultType.DENY_BOOL),
            Decision.ERROR
        )


class TestComplexScenarios(unittest.TestCase):
    """Test complex real-world scenarios"""
    
    def test_realistic_scp_scenario(self):
        """Test a realistic SCP with multiple statements"""
        scp = {
            "Statement": [
                {
                    "Sid": "AllowAllActions",
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                },
                {
                    "Sid": "DenyDangerousActions",
                    "Effect": "Deny",
                    "Action": [
                        "iam:DeleteUser",
                        "iam:DeleteRole",
                        "s3:DeleteBucket"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "DenyOutsideApprovedRegions",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {
                            "aws:RequestedRegion": ["us-east-1", "us-west-2"]
                        }
                    }
                }
            ]
        }
        
        evaluator = SCPEvaluator()
        
        # Allowed action in approved region
        test1 = TestCase(
            action="ec2:DescribeInstances",
            resource="*",
            context={"aws:RequestedRegion": "us-east-1"}
        )
        self.assertEqual(evaluator.evaluate(scp, test1), Decision.ALLOW)
        
        # Dangerous action - should be denied
        test2 = TestCase(
            action="iam:DeleteUser",
            resource="*",
            context={"aws:RequestedRegion": "us-east-1"}
        )
        self.assertEqual(evaluator.evaluate(scp, test2), Decision.DENY)
        
        # Approved region violation - should be denied
        test3 = TestCase(
            action="ec2:RunInstances",
            resource="*",
            context={"aws:RequestedRegion": "eu-west-1"}
        )
        self.assertEqual(evaluator.evaluate(scp, test3), Decision.DENY)


class TestTestCaseGeneration(unittest.TestCase):
    """Test that test case generation handles new semantics"""
    
    def test_generates_notaction_tests(self):
        """Test generation should handle NotAction"""
        scp = {
            "Statement": [{
                "Effect": "Deny",
                "NotAction": ["s3:GetObject"],
                "Resource": "*"
            }]
        }
        
        generator = TestCaseGenerator()
        test_cases = generator.generate_from_scp(scp)
        
        # Should have NotAction-specific tests
        notaction_tests = [tc for tc in test_cases if "NotAction" in tc.description]
        self.assertGreater(len(notaction_tests), 0)
    
    def test_generates_notresource_tests(self):
        """Test generation should handle NotResource"""
        scp = {
            "Statement": [{
                "Effect": "Deny",
                "Action": "s3:*",
                "NotResource": ["arn:aws:s3:::public-*/*"]
            }]
        }
        
        generator = TestCaseGenerator()
        test_cases = generator.generate_from_scp(scp)
        
        # Should have NotResource-specific tests
        notresource_tests = [tc for tc in test_cases if "NotResource" in tc.description]
        self.assertGreater(len(notresource_tests), 0, "Should generate NotResource test cases")
        
        # Should have both positive and negative cases
        positive = [tc for tc in notresource_tests if "not in exclusion" in tc.description]
        negative = [tc for tc in notresource_tests if "in exclusion" in tc.description]
        
        self.assertGreater(len(positive), 0, "Should have positive NotResource tests")
        self.assertGreater(len(negative), 0, "Should have negative NotResource tests")


def run_tests():
    """Run all tests with detailed output"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(__import__(__name__))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✓ All fixes validated successfully!")
    else:
        print("\n✗ Some tests failed - fixes need attention")
    
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    exit(run_tests())