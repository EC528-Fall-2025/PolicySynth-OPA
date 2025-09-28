from typing import Optional, dict, Any
from datetime import datetime
# credits to cursor for helping flesh out this model

class SCP:
    policy_id: str
    arn: str
    name: str
    policy_summary: Optional[dict[str, Any]] = None
    policy_type: str
    aws_managed: bool
    json_ody: str
    creation_date: Optional[datetime] = None
    last_updated_date: Optional[datetime] = None

    # general handler of SCP json body from boto3 for storing in db
    @classmethod
    # NOTE: check this out and see if we really need this method
    # NOTE: make sure that this is good against json body

    '''
    
    [{'PolicySummary': {'Id': 'p-FullAWSAccess', 'Arn': 'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess', 'Name': 'FullAWSAccess', 'Description': 'Allows access to every operation', 'Type': 'SERVICE_CONTROL_POLICY', 'AwsManaged': True}, 'Content': '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "*",\n      "Resource": "*"\n    }\n  ]\n}'}]
    
    
    '''
    def from_aws_response(cls, policy_response: dict[str, Any]) -> 'SCPPolicy':
        """
        Create SCPPolicy data class instance from AWS
        SCP fecth for manipulate if needed
        """
        policy = policy_response.get('Policy', {})

        return cls(
            policy_id=policy.get('PolicyId', ''),
            arn=policy.get('Arn', ''),
            name=policy.get('Name', ''),
            description=policy.get('Description'),
            type=policy.get('Type', ''),
            aws_managed=policy.get('AwsManaged', False),
            content=policy.get('Content', ''),
            policy_summary=policy.get('PolicySummary'),
            creation_date=policy.get('CreationDate'),
            last_updated_date=policy.get('LastUpdatedDate')
        )
