import boto3
import json
from typing import Dict, Any


class SCPEventBridgeHandler:
    def __init__(self, config: Dict[str, Any] = None, eventbridge_client=None):
        self.config = config or {}

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

    def create_event_rule(self, rule_name: str = "SCPCreateUpdateRule"):
        '''Creates an EventBridge rule to capture SCP create and update events.'''
        event_pattern = {
            "source": ["aws.organizations"],
            "detail-type": ["AWS API Call via CloudTrail"],
            "detail": {
                "eventName": ["CreatePolicy", "UpdatePolicy"],
            }
        }

        try:
            response = self.events_client.put_rule(
                Name=rule_name,
                EventPattern=json.dumps(event_pattern),
                State='ENABLED',
                Description='Trigger when SCP policies are created or updated'
            )
            return response
        except Exception as e:
            raise Exception(f"Error creating EventBridge rule: {str(e)}")