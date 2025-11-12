import boto3
import json
import logging
from botocore.exceptions import ClientError

# Configure global logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class S3Handler:
    def __init__(self, bucket_name, region_name="us-east-1"):
        self.bucket_name = bucket_name
        self.s3 = boto3.client("s3", region_name=region_name)
        logger.info(f"S3Handler initialized for bucket: {self.bucket_name} in region: {region_name}")


    def put_json(self, key: str, data: dict):
        """Uploads a JSON object to the specified S3 bucket/key."""
        try:
            logger.info(f"Uploading object to s3://{self.bucket_name}/{key}")
            response = self.s3.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=json.dumps(data),
                ContentType="application/json",
                ServerSideEncryption="AES256"
            )
            status_code = response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
            if status_code == 200:
                logger.info(f"Successfully uploaded {key} to {self.bucket_name}")
            else:
                logger.warning(f"Upload returned status code {status_code}")
            return response

        except ClientError as e:
            logger.error(f"AWS ClientError uploading to S3: {e}", exc_info=True)
            raise RuntimeError(f"Failed to upload {key} to bucket {self.bucket_name}") from e
        except Exception as e:
            logger.error(f"Unexpected error uploading {key} to S3: {e}", exc_info=True)
            raise
    
    def get_json(self, key: str):
        """Downloads and returns a JSON object from S3."""
        try:
            logger.info(f"Downloading object from s3://{self.bucket_name}/{key}")
            response = self.s3.get_object(Bucket=self.bucket_name, Key=key)
            content = response["Body"].read().decode("utf-8")
            data = json.loads(content)
            logger.info(f"Successfully downloaded {key} from {self.bucket_name}")
            return data

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                logger.warning(f"⚠️ Object not found: s3://{self.bucket_name}/{key}")
                return None
            logger.error(f"AWS ClientError downloading from S3: {e}", exc_info=True)
            raise RuntimeError(f"Failed to retrieve {key} from bucket {self.bucket_name}") from e
        except Exception as e:
            logger.error(f"Unexpected error downloading {key} from S3: {e}", exc_info=True)
            raise

    def upload_file(self, local_path: str, key: str, content_type: str = None, sse: str = "AES256"):
        """
        Uploads any local file to S3 with optional content-type and server-side encryption.

        """
        extra = {}
        if content_type:
            extra["ContentType"] = content_type
        if sse:
            extra["ServerSideEncryption"] = sse

        try:
            self.s3.upload_file(
                Filename=str(local_path),
                Bucket=self.bucket_name,
                Key=key,
                ExtraArgs=extra,
            )
            logger.info("Successfully uploaded file to %s/%s", self.bucket_name, key)
            return True
        except ClientError as e:
            logger.exception("Failed to upload file %s to %s/%s: %s", local_path, self.bucket_name, key, e)
            raise
