import os
import json
import boto3
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
BUCKET = os.environ["SCP_BUCKET"]


def lambda_handler(event, context):
    """
    Deletes scp/raw/<policyId>.json from S3 for DeletePolicy events.
    Expected event:
    {
        "eventName": "DeletePolicy",
        "policyId": "p-123456"
    }
    """

    logger.info("Received event: %s", json.dumps(event))

    if event["eventName"] != "DeletePolicy":
        raise ValueError(f"delete_scp_policy called for unsupported event: {event['eventName']}")

    policy_id = event["policyId"]
    key = f"scp/raw/{policy_id}.json"

    try:
        s3.delete_object(Bucket=BUCKET, Key=key)
        logger.info("Deleted SCP %s from s3://%s/%s", policy_id, BUCKET, key)
    except ClientError as e:
        logger.error("Error deleting from S3: %s", e)
        raise

    return {
        "status": "OK",
        "action": "DELETE",
        "policyId": policy_id,
        "s3Bucket": BUCKET,
        "s3Key": key
    }
