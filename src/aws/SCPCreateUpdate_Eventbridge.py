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

        self.eventbridge_checker = EventbrdigeChecker()

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
                                "Next": "Create Transform"
                            },
                            {
                                "Variable": "$.eventName",
                                "StringEquals": "UpdatePolicy",
                                "Next": "Create Transform"
                            }
                        ]
                    },
                    # we might not need this tbh
                    "Create Transform": {
                        "Type": "Pass",
                        "Parameters": {
                            "eventName.$": "$.eventName",
                            "policyId.$": "$.policyId",
                            "policyName.$": "$.policyName",
                            "timestamp.$": "$.timestamp",
                            "policyContent.$": "$.policyContent",
                            "scp.$": "States.StringToJson($.policyContent)",
                            "previous_rego": "",
                            "errors": "",
                            "input_data": "",
                            "query": "data.scp",
                            "counter.$": "$.counter"
                        },
                        "Next": "Generate Rego"
                    },
                    "Delete Policy from S3": {
                        "Type": "Task",
                        "Resource": "arn:aws:lambda:us-east-1:973646735135:function:delete-scp-policy",
                        "End": True
                    },
                    "Generate Rego": {
                        "Type": "Task",
                        "Resource": "arn:aws:lambda:us-east-1:973646735135:function:generateLambda",
                        "Next": "Validate Syntax Policy"
                    },
                    "Validate Syntax Policy": {
                        "Type": "Task",
                        "ResultPath": "$.syntaxResult",
                        "Resource": "arn:aws:lambda:us-east-1:973646735135:function:validateSyntaxLambda",
                        "Next": "Check Syntax Validation Result"
                    },
                    "Check Syntax Validation Result": {
                        "Type": "Choice",
                        "Choices": [
                            {
                                "Variable": "$.syntaxResult.errors",
                                "StringEquals": "",
                                "Next": "Validate Semantic Policy"
                            }
                        ],
                        "Default": "Check Retry Limit Syntax"
                    },
                    "Validate Semantic Policy": {
                        "Type": "Task",
                        "Resource": "arn:aws:lambda:us-east-1:973646735135:function:validateSemanticLambda",
                        "ResultPath": "$.validationResult",
                        "Next": "Check Validation Result"
                    },
                    "Check Validation Result": {
                        "Type": "Choice",
                        "Choices": [
                            {
                                "Variable": "$.validationResult.errors",
                                "StringEquals": "",
                                "Next": "Store Policy in S3"
                            }
                        ],
                        "Default": "Check Retry Limit Validation"
                    },
                    "Check Retry Limit Validation": {
                        "Type": "Choice",
                        "Choices": [
                            {
                                "Variable": "$.counter",
                                "NumericGreaterThanEquals": 5,
                                "Next": "Generation Failed"
                            }
                        ],
                        "Default": "Retry Semantic Transform"
                    },
                    "Check Retry Limit Syntax": {
                        "Type": "Choice",
                        "Choices": [
                            {
                            "Variable": "$.counter",
                            "NumericGreaterThanEquals": 5,
                            "Next": "Generation Failed"
                            }
                        ],
                        "Default": "Retry Syntax Transform"
                    },
                    "Retry Syntax Transform": {
                        "Type": "Pass",
                        "Parameters": {
                            "policyId.$": "$.policyId",
                            "scp.$": "$.scp",
                            "previous_rego.$": "$.translationResult.previous_rego",
                            "errors.$": "$.syntaxResult.errors",
                            "counter.$": "States.MathAdd($.counter, 1)"
                        },
                        "Next": "Generate Rego"
                    },
                    "Retry Semantic Transform": {
                        "Type": "Pass",
                        "Parameters": {
                            "policyId.$": "$.policyId",
                            "scp.$": "$.scp",
                            "previous_rego.$": "$.translationResult.previous_rego",
                            "errors.$": "$.validationResult.errors",
                            "counter.$": "States.MathAdd($.counter, 1)"
                        },
                        "Next": "Generate Rego"
                    },
                    "Generation Failed": {
                        "Type": "Fail",
                        "Cause": "Policy generation failed after 5 attempts",
                        "Error": "GenerationFailure"
                    },
                    "Store Policy in S3": {
                        "Type": "Task",
                        "Resource": "arn:aws:lambda:us-east-1:973646735135:function:store-scp-policy",
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
                            'InputTemplate': '{"eventName": <eventName>, "policyContent": <policyContent>, "policyId": <policyId>, "policyName": <policyName>, "timestamp": <ingestionTime>, "counter": "0"}'
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

        self.eventbridge_checker.verify_setup()

        print("\n🎉 Setup complete! Now test in AWS Console:")
        print("1. Go to Organizations console")
        print("2. Create or update an SCP policy") 
        print("3. Check Step Functions console to see execution")
        print("4. Check CloudWatch logs for Lambda execution")

        return True


if __name__ == "__main__":
    handler = SCPEventBridgeHandler()

    handler.setup_step_function()
