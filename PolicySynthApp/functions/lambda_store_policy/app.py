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
    Stores SCP JSON into S3 for CreatePolicy / UpdatePolicy events.
    Expected event:
    {
        "eventName": "CreatePolicy" / "UpdatePolicy",
        "policyId": "p-123456",
        "policyName": "MyPolicy",
        "timestamp": "...",
        "policyContent": "{...raw JSON string...}"
    }
    """

    logger.info("Received event: %s", json.dumps(event))

    # Validate event type
    if event["eventName"] not in ("CreatePolicy", "UpdatePolicy"):
        raise ValueError(f"store_scp_policy called for unsupported event: {event['eventName']}")

    policy_id = event["policyId"]
    policy_name = event.get("policyName", "unknown")
    timestamp = event.get("timestamp")

    # Parse policy content (string → JSON dict)
    try:
        policy_json = json.loads(event["policyContent"])
    except json.JSONDecodeError:
        logger.warning("policyContent is not valid JSON; storing raw string")
        policy_json = event["policyContent"]

    # Build S3 key
    key = f"scp/raw/{policy_id}.json"

    # Object to store
    payload = {
        "policyId": policy_id,
        "policyName": policy_name,
        "timestamp": timestamp,
        "scp": policy_json
    }

    try:
        s3.put_object(
            Bucket=BUCKET,
            Key=key,
            Body=json.dumps(payload, indent=2),
            ContentType="application/json"
        )
    except ClientError as e:
        logger.error("Error writing to S3: %s", e)
        raise

    logger.info("Stored SCP %s at s3://%s/%s", policy_id, BUCKET, key)

    return {
        "status": "OK",
        "action": "STORE",
        "policyId": policy_id,
        "s3Bucket": BUCKET,
        "s3Key": key
    }
