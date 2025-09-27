import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from src.Keywords import Keywords

SCP_policies = [
    Keywords.AISERVICES_OPT_OUT_POLICY,
    Keywords.BACKUP_POLICY,
    Keywords.CHATBOT_POLICY,
    Keywords.DECLARATIVE_POLICY_EC2,
    Keywords.RESOURCE_CONTROL_POLICY,
    Keywords.SECURITYHUB_POLICY,
    Keywords.SERVICE_CONTROL_POLICY,
    Keywords.TAG_POLICY
]


class SCPFetcher:
    def __init__(self, config={}, organizations_client=None):
        self.config = config

        # initialize given config
        try:
            # Initialize boto3 client based on provided config
            if self.config.get('profile'):
                session = boto3.Session(profile_name=self.config['profile'])
                self.organizations_client = session.client('organizations')
            elif self.config.get('aws_access_key_id') and self.config.get('aws_secret_access_key'):
                self.organizations_client = boto3.client(
                    'organizations',
                    aws_access_key_id=self.config['aws_access_key_id'],
                    aws_secret_access_key=self.config['aws_secret_access_key'],
                    region_name=self.config.get('region', 'us-east-1')
                )
            else:
                # Assume user configured via aws cli and use
                # env variables
                self.organizations_client = boto3.client(
                    'organizations',
                    region_name=self.config.get('region', 'us-east-1')
                )

        except NoCredentialsError:
            raise Exception("AWS credentials not found. Please configure "
                            "via AWS CLI, environment variables, or pass "
                            "them in config.")

    def fetch_scp(self, source, destination):
        # Implement SCP fetching logic here
        try:
            scps = []
            paginator = self.organizations_client.get_paginator('list_policies')

            # FIXME: there has to be a better way of doing this
            for policy in SCP_policies:
                for page in paginator.paginate(Filter=policy):
                    for retrieved_policy in page['Policies']:
                        policy_details = self.organizations_client.describe_policy(
                            PolicyId=retrieved_policy['Id']
                        )
                        scps.append(policy_details['Policy'])
            return scps
        except ClientError as e:
            # maybe add some better logging here
            raise Exception(f"Error fetching SCPs: {e}")

test = SCPFetcher()
