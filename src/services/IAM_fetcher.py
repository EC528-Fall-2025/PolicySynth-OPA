import boto3
from botocore.exceptions import ClientError, NoCredentialsError

## syntax of request for IAM policies 
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
    def __init__(self, config=None, iam_client=None): 
        self.config = config or {}

        if iam_client:  # set iam client 
            self.iam_client = iam_client
            return
        try : 
            if self.config.get('profile'): 
                session=boto3.Session(
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

    ## fetch_iam_policies fetches the existing IAM policies, can filter based on scope, etc. 
    def fetch_iam_policies(self, scope="All", only_Attached=False):
        try: 
            policies =[] # where were storing policies 
            paginator = self.iam_client.get_paginator('list_policies') # this is where list policies is called
            for page in paginator.paginate(Scope=scope, OnlyAttached=only_Attached): # allows us to loop through all pages
                for policy in page.get('Policies', []): 
                    policies.append(policy) # have to connect to database 
            return policies
        except ClientError as e: 
            raise Exception(f"Error retrieving policies: {e}")