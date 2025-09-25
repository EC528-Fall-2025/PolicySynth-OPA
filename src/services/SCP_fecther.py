import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import json


class SCPFetcher:
    def __init__(self, config):
        self.config = config or {}

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
        pass
