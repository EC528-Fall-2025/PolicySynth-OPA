import boto3
import json

class S3Handler:
    def __init__(self, bucket_name, region_name="us-east-1"):
        self.bucket_name = bucket_name
        self.s3 = boto3.client("s3", region_name=region_name)

    def put_json(self, key, data):
        print(f"Uploading to bucket: {self.bucket_name}, key: {key}")
        response = self.s3.put_object(
            Bucket=self.bucket_name,
            Key=key,
            Body=json.dumps(data)
        )
        print("Upload response:", response)
        return response
