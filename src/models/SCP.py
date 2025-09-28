from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict
import json
# credits to copilot for helping flesh out this model


@dataclass
class SCP:
    policy_id: str
    arn: str
    name: str
    description: Optional[str] = None
    policy_type: str = ''
    aws_managed: bool = False
    content: str = ''
    policy_summary: Optional[Dict[str, Any]] = None

    # general handler of SCP json body from boto3 for storing in db
    @classmethod
    # NOTE: check this out and see if we really need this method
    # NOTE: make sure that this is good against json body
    def from_aws_response(cls, policy_response: dict[str, Any]):
        """
        Create SCPPolicy data class instance from AWS
        SCP fecth for manipulate if needed
        """
        policy = policy_response.get('Policy', {})
        policy_summary = policy.get('PolicySummary', {})

        return cls(
            policy_id=policy_summary.get('Id', ''),
            arn=policy_summary.get('Arn', ''),
            name=policy_summary.get('Name', ''),
            description=policy_summary.get('Description'),
            policy_type=policy_summary.get('Type', ''),
            aws_managed=policy_summary.get('AwsManaged', False),
            content=policy.get('Content', ''),
            policy_summary=policy_summary,
        )

    def __str__(self) -> str:
        """
        Print an SCP object in nicely formatted JSON representation
        """
        return json.dumps(asdict(self), indent=2)
