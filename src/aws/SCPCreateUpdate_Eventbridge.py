import boto3
import json
from typing import Dict, Any
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError


class SCPEventBridgeHandler:
    '''
    If you're cross testing this, you need to make sure that CloudTrail
    is enabled since eventbridge relies on it to capture AWS API calls.
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
        self.lambda_client = boto3.client(
            'lambda',
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
                                "Variable": "$.detail.eventName",
                                "StringEquals": "DeletePolicy",
                                "Next": "Delete Policy from S3"
                            },
                            {
                                "Variable": "$.detail.eventName",
                                "StringMatches": ["CreatePolicy", "UpdatePolicy"],
                                "Next": "Fetch and Translate SCP"
                            }
                        ],
                        "Default": "FailState"
                    },
                    "Delete Policy from S3": {
                        "Type": "Task",
                        "Resource": "arn:aws:lambda:<region>:<account-id>:function:DeleteSCPHandler",
                        "ResultPath": "$.deleteResult",
                        "End": True
                    },
                    "Fetch and Translate SCP": {
                        "Type": "Task",
                        "Resource": "arn:aws:lambda:<region>:<account-id>:function:FetchTranslateHandler",
                        "ResultPath": "$.translationResult",
                        "Next": "Validate Policy"
                    },
                    "Validate Policy": {
                        "Type": "Task",
                        "Resource": "arn:aws:lambda:<region>:<account-id>:function:ValidationHandler",
                        "ResultPath": "$.validationResult",
                        "Next": "Store Policy in S3"
                    },
                    "Store Policy in S3": {
                        "Type": "Task",
                        "Resource": "arn:aws:lambda:<region>:<account-id>:function:StoreSCPHandler",
                        "ResultPath": "$.storeResult",
                        "End": True
                    },
                    "FailState": {
                        "Type": "Fail",
                        "Error": "UnknownEventType",
                        "Cause": "Received unsupported eventName"
                    }
                }
            }

            response = self.stepfunctions_client.create_state_machine(
                name=state_machine_name,
                definition=json.dumps(state_machine_defintition),
                roleArn=role_arn,  # can't this just be assumed from the user credentials?
                type='STANDARD'
            )

            state_machine_arn = response['stateMachineArn']
            print(f"Created Step Functions state machine: {state_machine_arn}")

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

    def add_lambda_to_step_function(self,
                                    state_machine_name: str = "SCPProcessingStateMachine",
                                    lambda_function_arn: str = None,
                                    lambda_name: str = None,
                                    insert_after: str = None) -> bool:
        '''
        Adds a Lambda function to the Step Functions state machine processing chain.
        '''
        if not lambda_function_arn or not lambda_name:
            print("Both lambda_function_arn and lambda_name are required")
            return False

        try:
            # Get current state machine definition
            account_id = boto3.client('sts').get_caller_identity()['Account']
            state_machine_arn = f"arn:aws:states:{self.config.get('region', 'us-east-1')}:{account_id}:stateMachine:{state_machine_name}"

            sm_response = self.stepfunctions_client.describe_state_machine(
                stateMachineArn=state_machine_arn
            )

            current_definition = json.loads(sm_response['definition'])

            # Lambda task state
            lambda_task = {
                "Type": "Task",
                "Resource": lambda_function_arn,
                "Retry": [
                    {
                        "ErrorEquals": ["Lambda.ServiceException", "Lambda.AWSLambdaException"],
                        "IntervalSeconds": 2,
                        "MaxAttempts": 3,
                        "BackoffRate": 2.0
                    }
                ],
                "Catch": [
                    {
                        "ErrorEquals": ["States.TaskFailed"],
                        "Next": "HandleError",
                        "ResultPath": "$.error"
                    }
                ],
                "End": True
            }

            if "HandleError" not in current_definition["States"]:
                current_definition["States"]["HandleError"] = {
                    "Type": "Pass",
                    "Result": "Error occurred in processing",
                    "End": True
                }

            # update our lambdas position (insert_after)
            for _, state_def in current_definition["States"].items():
                if state_def.get("End") == True:
                    state_def["End"] = False
                    state_def["Next"] = lambda_name
                    break

            # Add the new branch to the parallel state
            current_definition["States"][lambda_name] = lambda_task

            # Update the state machine
            update_response = self.stepfunctions_client.update_state_machine(
                stateMachineArn=state_machine_arn,
                definition=json.dumps(current_definition)
            )

            print(f"Successfully added Lambda {lambda_name} to Step Functions state machine: {update_response}")
            return True

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ResourceNotFound':
                print(f"State machine {state_machine_name} not found. Create it first using create_step_function_target()")
            else:
                print(f"Error adding Lambda to Step Functions: {error_code} - {e.response['Error']['Message']}")
            return False
        except Exception as e:
            print(f"Unexpected error adding Lambda to Step Functions: {str(e)}")
            return False

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

# TODO: Delete this when merging, just for testing purposes
def test_step_function_setup():
    """Test the Step Function creation and Lambda addition"""
    
    # Initialize the handler
    handler = SCPEventBridgeHandler()
    
    # 1. Create the EventBridge rule for create/update events
    print("Creating EventBridge rule...")
    rule_result = handler.create_event_rule("SCPCreateUpdateRule")
    if rule_result:
        print("✓ EventBridge rule created successfully")
    else:
        print("✗ Failed to create EventBridge rule")
        return False
    
    # 2. Create Step Function target (you'll need to provide a valid IAM role ARN)
    role_arn = "arn:aws:iam::135167709822:role/StepFunction-SCPProcessing" 
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
    
    # 3. Add a test Lambda function (replace with your actual Lambda ARN)
    test_lambda_arn = "arn:aws:lambda:us-east-1:135167709822:function:boto3-test"
    
    print("Adding test Lambda to Step Function...")
    lambda_result = handler.add_lambda_to_step_function(
        state_machine_name="SCPProcessingStateMachine",
        lambda_function_arn=test_lambda_arn,
        lambda_name="TestLambdaProcessor"
    )
    
    if lambda_result:
        print("✓ Test Lambda added successfully")
    else:
        print("✗ Failed to add test Lambda")
        return False
    
    print("\n🎉 Setup complete! Now test in AWS Console:")
    print("1. Go to Organizations console")
    print("2. Create or update an SCP policy") 
    print("3. Check Step Functions console to see execution")
    print("4. Check CloudWatch logs for Lambda execution")
    
    return True

if __name__ == "__main__":
    test_step_function_setup()