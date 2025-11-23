import boto3
import json
from typing import Dict, Any
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError


class SCPEventBridgeHandler:
    '''
    Class that sets up eventbridge rules as well as the skeleton for
    the step function that we'll be using for scp validation
    '''
    def __init__(self, config: Dict[str, Any]=None):
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

        self.stepfunctions_client = boto3.client(
            'stepfunctions',
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

    def create_step_function_target(self,
                                    rule_name: str,
                                    state_machine_name: str,
                                    role_arn: str) -> dict | None:
        '''
        Creates a Step Functions state machine and
        adds it as an EventBridge target.
        '''
        try:
            # resources will need to be changed to actual ARNs
            state_machine_defintition = {
                "Comment": "SCP Event Processing State Machine",
                "StartAt": "Check Event Type",
                "States": {
                    "Check Event Type": {
                        "Type": "Choice",
                        "Choices": [
                            {
                                "Variable": "$.eventName",
                                "StringEquals": "DeletePolicy",
                                "Next": "Delete Policy from S3"
                            },
                            {
                                "Variable": "$.eventName",
                                "StringEquals": "CreatePolicy",
                                "Next": "Fetch and Translate SCP"
                            },
                            {
                                "Variable": "$.eventName",
                                "StringEquals": "UpdatePolicy",
                                "Next": "Fetch and Translate SCP"
                            }
                        ],
                    },
                    "Delete Policy from S3": {
                        "Type": "Task",
                        "Resource": "arn:aws:lambda:us-east-1:973646735135:function:delete_lambda_test_for_step",
                        "End": True
                    },
                    "Fetch and Translate SCP": {
                        "Type": "Task",
                        "Resource": "arn:aws:lambda:us-east-1:973646735135:function:delete_lambda_test_for_step",
                        "ResultPath": "$.translationResult",
                        "Next": "Validate Policy"
                    },
                    "Validate Policy": {
                        "Type": "Task",
                        "Resource": "arn:aws:lambda:us-east-1:973646735135:function:delete_lambda_test_for_step",
                        "ResultPath": "$.validationResult",
                        "Next": "Store Policy in S3"
                    },
                    "Store Policy in S3": {
                        "Type": "Task",
                        "Resource": "arn:aws:lambda:us-east-1:973646735135:function:delete_lambda_test_for_step",
                        "ResultPath": "$.storeResult",
                        "End": True
                    }
                }
            }

            response = self.stepfunctions_client.create_state_machine(
                name=state_machine_name,
                definition=json.dumps(state_machine_defintition),
                roleArn=role_arn,
                type='STANDARD'
            )

            state_machine_arn = response['stateMachineArn']
            print(f"Created Step Functions state machine: {state_machine_arn}")

            # input transformer is how we pass data onto our
            # step function
            target_response = self.events_client.put_targets(
                Rule=rule_name,
                Targets=[
                    {
                        'Id': '1',
                        'Arn': state_machine_arn,
                        'RoleArn': role_arn,
                        'InputTransformer': {
                            'InputPathsMap': {
                                'eventName': '$.detail.eventName',
                                'policyContent': '$.detail.requestParameters.content',
                                'policyId': '$.detail.requestParameters.policyId',
                                'policyName': '$.detail.requestParameters.name',
                                'ingestionTime': '$.time'
                            },
                            'InputTemplate': '{"eventName": <eventName>, "policyContent": <policyContent>, "policyId": <policyId>, "policyName": <policyName>, "timestamp": <ingestionTime>}'
                        }
                    }
                ]
            )

            return {
                'stateMachineArn': state_machine_arn,
                'targetResponse': target_response
            }

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'StateMachineAlreadyExists':
                print(f"State machine {state_machine_name} already exists")
                # Get existing state machine ARN
                try:
                    existing_sm = self.stepfunctions_client.describe_state_machine(
                        stateMachineArn=f"arn:aws:states:{self.config.get('region', 'us-east-1')}:{boto3.client('sts').get_caller_identity()['Account']}:stateMachine:{state_machine_name}"
                    )
                    return {'stateMachineArn': existing_sm['stateMachineArn']}
                except:
                    pass
            print(f"Error creating Step Functions target: {error_code} - {e.response['Error']['Message']}")
            return None
        except Exception as e:
            print(f"Unexpected error creating Step Functions target: {str(e)}")
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

    def verify_setup(self) -> bool:
        """Verify that all components were created successfully"""
        print("\n=== Verifying Setup ===")

        # Check EventBridge rule
        # can also check via `aws events describe-rule --name SCPCreateUpdateRule`
        try:
            rule_response = self.events_client.describe_rule(Name="SCPCreateUpdateRule")
            print(f"✓ EventBridge Rule: {rule_response['Name']} - {rule_response['State']}")
            print(f"  Description: {rule_response.get('Description', 'N/A')}")
        except ClientError as e:
            print(f"✗ EventBridge Rule not found: {e}")
            return False

        # Check Step Function state machine
        # `aws stepfunctions describe-state-machine --state-machine-arn arn:aws:states:us-east-1:<account_id>:stateMachine:SCPProcessingStateMachine`
        # `aws stepfunctions list-state-machines`
        try:
            sts_client = boto3.client('sts')
            account_id = sts_client.get_caller_identity()['Account']
            sm_arn = f"arn:aws:states:us-east-1:{account_id}:stateMachine:SCPProcessingStateMachine"

            sm_response = self.stepfunctions_client.describe_state_machine(stateMachineArn=sm_arn)
            print(f"✓ Step Function: {sm_response['name']} - {sm_response['status']}")
            print(f"  ARN: {sm_response['stateMachineArn']}")
        except ClientError as e:
            print(f"✗ Step Function not found: {e}")
            return False

        # Check EventBridge targets
        # `aws events list-targets-by-rule --rule SCPCreateUpdateRule`
        try:
            targets_response = self.events_client.list_targets_by_rule(Rule="SCPCreateUpdateRule")
            if targets_response['Targets']:
                print(f"✓ EventBridge Targets: {len(targets_response['Targets'])} target(s)")
                for target in targets_response['Targets']:
                    print(f"  Target ID: {target['Id']}, ARN: {target['Arn']}")
            else:
                print("⚠️  No targets found for EventBridge rule")
        except ClientError as e:
            print(f"✗ Error checking targets: {e}")

        # Test event pattern
        print("\n=== Testing Event Patterns ===")
        create_update_test = self.test_create_update_event_pattern("SCPCreateUpdateRule")
        if create_update_test:
            print("✓ Create/Update event pattern works correctly")
        else:
            print("✗ Create/Update event pattern failed")

        return True

    def setup_step_function(self):
        """Test the Step Function creation + eventbridge creaiton"""
        handler = SCPEventBridgeHandler()

        # Get current account ID
        sts_client = boto3.client('sts')
        account_id = sts_client.get_caller_identity()['Account']

        # eventbridge rule
        print("Creating EventBridge rule...")
        rule_result = handler.create_event_rule("SCPCreateUpdateRule")
        if rule_result:
            print("✓ EventBridge create/update rule created successfully")
        else:
            print("✗ Failed to create create/update EventBridge rule")
            return False

        rule_result = handler.create_event_rule("SCPDeleteRule")
        if rule_result:
            print("✓ EventBridge delete rule created successfully")
        else:
            print("✗ Failed to create delete EventBridge rule")
            return False

        # step function
        role_arn = f"arn:aws:iam::{account_id}:role/StepFunction-SCPProcessing"
        print(f"Using role for account {account_id}: {role_arn}")
        print("Creating Step Function state machine...")
        sf_result = handler.create_step_function_target(
            rule_name="SCPCreateUpdateRule",
            state_machine_name="SCPProcessingStateMachine", 
            role_arn=role_arn
        )

        if sf_result:
            print("✓ Step Function created successfully")
            print(f"State Machine ARN: {sf_result['stateMachineArn']}")
        else:
            print("✗ Failed to create Step Function")
            return False

        print("Adding Step Function target for delete rule...")
        delete_target_result = handler.create_step_function_target(
            rule_name="SCPDeleteRule",
            state_machine_name="SCPProcessingStateMachine",
            role_arn=role_arn
        )

        if delete_target_result:
            print("✓ Delete rule target added successfully")
        else:
            print("✗ Failed to add target for delete rule")
            return False

        self.verify_setup()

        print("\n🎉 Setup complete! Now test in AWS Console:")
        print("1. Go to Organizations console")
        print("2. Create or update an SCP policy") 
        print("3. Check Step Functions console to see execution")
        print("4. Check CloudWatch logs for Lambda execution")

        return True

if __name__ == "__main__":
    handler = SCPEventBridgeHandler()

    handler.setup_step_function()
