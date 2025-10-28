import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from src.models.IAM import IAMPolicy

# syntax of request for IAM policies
""" response = client.list_policies(
    Scope='All'|'AWS'|'Local',
    OnlyAttached=True|False,
    PathPrefix='string',
    PolicyUsageFilter='PermissionsPolicy'|'PermissionsBoundary',
    Marker='string',
    MaxItems=123
) """


class IAMFetcher:
    # sets up session and iam client
    # user needs to have iam:ListPolicies action
    def __init__(self, config=None, iam_client=None):
        self.config = config or {}

        if iam_client:  # set iam client
            self.iam_client = iam_client
            return
        try:
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
            self.iam_client = session.client('iam')
        except NoCredentialsError:
            raise Exception("AWS Credentials not configured.")

    # fetch_iam_policies fetches the existing IAM policies, can filter based 
    # on scope, etc.
    def fetch_iam_policies(self, scope="Local"):
        # scope is defaulted to local since we only want to get customer
        # policies and NOT AWS managed policies
        try:
            policies = []  # where were storing policies

            # this is where list policies is called
            paginator = self.iam_client.get_paginator('list_policies')
            for page in paginator.paginate(Scope=scope):
                for policy in page.get('Policies', []):
                    policy_information = self.iam_client.get_policy_version(
                        PolicyArn=policy['Arn'],
                        VersionId=policy['DefaultVersionId']
                    )
                    # TODO: save to db
                    iam_policy: IAMPolicy = policy_information['PolicyVersion']
                    policies.append(iam_policy)
            return policies
        except ClientError as e:
            raise Exception(f"Error retrieving policies: {e}")

import json
test = IAMFetcher()
policy = test.fetch_iam_policies()
with open('iam_policies.json', 'w') as f:
    json.dump(policy, f, indent=2, default=str)

print("policy saves to json")