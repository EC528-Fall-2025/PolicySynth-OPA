import boto3
import json
from typing import Dict, Any
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from src.utils.eventbridge_validation import EventbrdigeChecker


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
                        "Resource": "arn:aws:lambda:us-east-1:973646735135:function:generateLambda",
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


if __name__ == "__main__":
    handler = EventbrdigeChecker()

    handler.setup_step_function()
