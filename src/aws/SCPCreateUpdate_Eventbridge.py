import boto3
import json
from typing import Dict, Any
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError


class SCPEventBridgeHandler:
    def __init__(self, config: Dict[str, Any]=None, eventbridge_client=None):
        self.config = config or {}
        try:
            sts_client = boto3.client('sts')
            identity = sts_client.get_caller_identity()
            print(f"Using AWS credentials for account: {identity['Account']}")
        except (NoCredentialsError, PartialCredentialsError) as e:
            raise Exception(f"AWS credentials not found or incomplete: {str(e)}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidSignatureException':
                raise Exception("Invalid AWS credentials or signature."
                                "Please check your AWS Secret Access Key.")
            raise Exception(f"Error verifying AWS credentials: {str(e)}")

        self.events_client = boto3.client(
            'events',
            region_name=self.config.get('region', 'us-east-1')
        )
        # this will be replaced with step functions
        self.lambda_client = boto3.client(
            'lambda',
            region_name=self.config.get('region', 'us-east-1')
        )
        self.iam_client = boto3.client(
            'iam',
            region_name=self.config.get('region', 'us-east-1')
        )

    def create_event_rule(self, rule_name: str = "SCPCreateUpdateRule") -> dict | None:
        '''Creates an EventBridge rule to capture SCP create and update events.'''
        if rule_name == "SCPDeleteRule":
            event_pattern = {
                "source": ["aws.organizations"],
                "detail-type": ["AWS API Call via CloudTrail"],
                "detail": {
                    "eventName": ["DeletePolicy"],
                }
            }
        else:
            event_pattern = {
                "source": ["aws.organizations"],
                "detail-type": ["AWS API Call via CloudTrail"],
                "detail": {
                    "eventName": ["CreatePolicy", "UpdatePolicy"],
                }
            }

        try:
            if rule_name == "SCPDeleteRule":
                response = self.events_client.put_rule(
                    Name=rule_name,
                    EventPattern=json.dumps(event_pattern),
                    State='ENABLED',
                    Description='Trigger when SCP policies are deleted'
                )
            else:
                response = self.events_client.put_rule(
                    Name=rule_name,
                    EventPattern=json.dumps(event_pattern),
                    State='ENABLED',
                    Description='Trigger when SCP policies are created or updated'
                )
            return response

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidSignatureException':
                print("Invalid AWS credentials or signature. "
                      "Please check your AWS Secret Access Key.")

            elif error_code == 'UnrecognizedClientException':
                print("The security token included in the request is invalid" 
                      "Please check your AWS credentials.")

            else:
                print(f"AWS error creating EventBridge rule: "
                      f"{error_code} - {e.response['Error']['Message']}")
            return None
        except Exception as e:
            print(f"Unexpected error creating EventBridge rule: {str(e)}")
            return None

    def test_create_update_event_pattern(self, rule_name: str = "SCPCreateUpdateRule") -> bool:
        '''Tests if the EventBridge create/update rule is working'''

        test_create_event = {
            "version": "0",
            "id": "12345678-1234-1234-1234-123456789012",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.organizations",
            "account": "123456789012",
            "time": "2025-11-20T10:00:00Z",
            "region": "us-east-1",
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                    "arn": "arn:aws:iam::123456789012:user/test-user",
                    "accountId": "123456789012",
                    "userName": "test-user"
                },
                "eventTime": "2025-11-20T10:00:00Z",
                "eventSource": "organizations.amazonaws.com",
                "eventName": "CreatePolicy",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.0.2.1",
                "requestParameters": {
                    "name": "TestSCPPolicy",
                    "description": "Test SCP for validation",
                    "type": "SERVICE_CONTROL_POLICY",
                    "content": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
                }
            }
        }

        test_update_event = {
            "version": "0",
            "id": "87654321-4321-4321-4321-210987654321",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.organizations",
            "account": "123456789012",
            "time": "2025-11-20T11:00:00Z",
            "region": "us-east-1",
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                    "arn": "arn:aws:iam::123456789012:user/test-user",
                    "accountId": "123456789012",
                    "userName": "test-user"
                },
                "eventTime": "2025-11-20T11:00:00Z",
                "eventSource": "organizations.amazonaws.com",
                "eventName": "UpdatePolicy",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.0.2.1",
                "requestParameters": {
                    "policyId": "p-12345678",
                    "name": "UpdatedSCPPolicy",
                    "description": "Updated SCP for validation",
                    "content": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}]}"
                }
            }
        }

        # get rule pattern and test
        try:
            rule_response = self.events_client.describe_rule(Name=rule_name)
            event_pattern = rule_response['EventPattern']

            create_test = self.events_client.test_event_pattern(
                EventPattern=event_pattern,
                Event=json.dumps(test_create_event)
            )

            update_test = self.events_client.test_event_pattern(
                EventPattern=event_pattern,
                Event=json.dumps(test_update_event)
            )

            create_match = create_test['Result']
            update_match = update_test['Result']

            print(f"Create event test result: {'✓ MATCH' if create_match else '✗ NO MATCH'}")
            print(f"Update event test result: {'✓ MATCH' if update_match else '✗ NO MATCH'}")

            return create_match and update_match
        except Exception as e:
            if isinstance(e, ClientError):
                error_code = e.response['Error']['Code']
                if error_code == 'UnrecognizedClientException':
                    print("The security token included in the request is invalid. "
                          "Please check your AWS credentials.")
                    return False
            print(f"Error testing event pattern: {str(e)}")
            return False

    def test_delete_event_pattern(self, rule_name: str = "SCPDeleteRule") -> bool:
        '''Tests if the EventBridge delete rule is working'''

        test_delete_event = {
            "version": "0",
            "id": "11111111-2222-3333-4444-555555555555",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.organizations",
            "account": "123456789012",
            "time": "2025-11-20T12:00:00Z",
            "region": "us-east-1",
            "detail": {
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                    "arn": "arn:aws:iam::123456789012:user/test-user",
                    "accountId": "123456789012",
                    "userName": "test-user"
                },
                "eventTime": "2025-11-20T12:00:00Z",
                "eventSource": "organizations.amazonaws.com",
                "eventName": "DeletePolicy",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.0.2.1",
                "requestParameters": {
                    "policyId": "p-12345678"
                },
                "responseElements": {
                    "policy": {
                        "policySummary": {
                            "id": "p-12345678",
                            "arn": "arn:aws:organizations::123456789012:policy/o-example123456/service_control_policy/p-12345678",
                            "name": "DeletedSCPPolicy",
                            "description": "SCP policy being deleted",
                            "type": "SERVICE_CONTROL_POLICY"
                        }
                    }
                }
            }
        }

        # Get rule pattern and test
        try:
            rule_response = self.events_client.describe_rule(Name=rule_name)
            event_pattern = rule_response['EventPattern']

            delete_test = self.events_client.test_event_pattern(
                EventPattern=event_pattern,
                Event=json.dumps(test_delete_event)
            )

            delete_match = delete_test['Result']

            print(f"Delete event test result: {'✓ MATCH' if delete_match else '✗ NO MATCH'}")

            return delete_match

        except Exception as e:
            if isinstance(e, ClientError):
                error_code = e.response['Error']['Code']
                if error_code == 'ResourceNotFoundException':
                    print(f"EventBridge rule '{rule_name}' not found. Create the rule first.")
                    return False
                elif error_code == 'UnrecognizedClientException':
                    print("The security token included in the request is invalid. "
                          "Please check your AWS credentials.")
                    return False
            print(f"Error testing delete event pattern: {str(e)}")
            return False


test = SCPEventBridgeHandler()
test.create_event_rule("SCPCreateUpdateRule")
test.create_event_rule("SCPDeleteRule")
test.test_create_update_event_pattern("SCPCreateUpdateRule")
test.test_delete_event_pattern("SCPDeleteRule")