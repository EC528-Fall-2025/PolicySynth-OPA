import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from src.Keywords import Keywords
from src.models.SCP import SCP


class SCPFetcher:
    def __init__(self, config=None, organizations_client=None):
        self.config = config or {}

        # config might look something like this as input arg

        # config = {
        #     'aws_access_key_id': 'your-access-key',
        #     'aws_secret_access_key': 'your-secret-key',
        #     'region': 'us-east-1'
        # }

        # TODO: make a session factory
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

    # NOTE: will we have to make these async at any point?
    def fetch_scp(self):
        try:
            scps = []
            paginator = self.organizations_client.get_paginator('list_policies')

            service_control_policy = Keywords.SERVICE_CONTROL_POLICY.value
            for page in paginator.paginate(Filter=service_control_policy):
                for retrieved_policy in page['Policies']:
                    policy_details = self.organizations_client.describe_policy(
                        PolicyId=retrieved_policy['Id']
                    )
                    # NOTE: do something with data handling here
                    # not using handler, should we use it or just go like this?
                    scp_policy: SCP = policy_details['Policy']
                    scps.append(scp_policy)

            # NOTE: opa only handles json/yaml, so we can serialize
            # this when translating
            return scps
        except ClientError as e:
            # maybe add some better logging here
            raise Exception(f"Error fetching SCPs: {e}")
