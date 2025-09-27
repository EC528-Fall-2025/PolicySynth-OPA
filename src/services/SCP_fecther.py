import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from src.Keywords import Keywords


class SCPFetcher:
    def __init__(self, config=None, organizations_client=None):
        self.config = config or {}

        if organizations_client:
            self.organizations_client = organizations_client
            return

        try:
            # try to get session via input params
            if self.config.get('profile'):
                session = boto3.Session(
                    profile_name=self.config['profile'],
                    region_name=self.config.get('region', 'us-east-1')
                )
            elif self.config.get('aws_access_key_id') and self.config.get('aws_secret_access_key'):
                session = boto3.Session(
                    aws_access_key_id=self.config['aws_access_key_id'],
                    aws_secret_access_key=self.config['aws_secret_access_key'],
                    region_name=self.config.get('region', 'us-east-1'),
                )
            else:
                # default to env vars
                session = boto3.Session(
                    region_name=self.config.get('region', 'us-east-1')
                )

            if session.get_credentials() is None:
                raise NoCredentialsError

            self.organizations_client = session.client('organizations')
        except NoCredentialsError:
            raise Exception("AWS credentials not found. Please configure "
                            "via AWS CLI, environment variables, or pass "
                            "them in config.")

    def fetch_scp(self):
        try:
            scps = []
            paginator = self.organizations_client.get_paginator('list_policies')

            for page in paginator.paginate(Filter=Keywords.SERVICE_CONTROL_POLICY.value):
                for retrieved_policy in page['Policies']:
                    policy_details = self.organizations_client.describe_policy(
                        PolicyId=retrieved_policy['Id']
                    )
                    scps.append(policy_details['Policy'])
            return scps
        except ClientError as e:
            # maybe add some better logging here
            raise Exception(f"Error fetching SCPs: {e}")
