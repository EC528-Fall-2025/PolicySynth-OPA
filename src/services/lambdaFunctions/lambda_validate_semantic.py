import json
import boto3
import random
import time
from botocore.exceptions import ClientError, BotoCoreError, EndpointConnectionError
import logging
import traceback

client = boto3.client("bedrock-runtime", region_name = "us-east-1")

model_id = "global.anthropic.claude-sonnet-4-5-20250929-v1:0"

def _call_with_backoff(func, *args, max_retries=6, base_delay=0.5, **kwargs):
    logger = logging.getLogger(__name__)
    for attempt in range(1, max_retries + 1):
        try:
            logger.debug("_call_with_backoff attempt %d", attempt)
            return func(*args, **kwargs)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            logger.warning("ClientError on attempt %d: %s", attempt, code)
            if code in ("ThrottlingException", "TooManyRequestsException", "Throttling"):
                headers = e.response.get("ResponseMetadata", {}).get("HTTPHeaders", {}) or {}
                ra = headers.get("retry-after") or headers.get("Retry-After")
                if ra:
                    try:
                        sleep = float(ra)
                    except Exception:
                        sleep = random.uniform(0, base_delay * (2 ** (attempt - 1)))
                else:
                    sleep = random.uniform(0, base_delay * (2 ** (attempt - 1)))
                logger.info("Sleeping %.3fs before retry (attempt %d)", sleep, attempt)
                time.sleep(sleep)
                continue
            raise
        except (BotoCoreError, EndpointConnectionError) as e:
            sleep = random.uniform(0, base_delay * (2 ** (attempt - 1)))
            logger.warning("Transient error on attempt %d: %s. Sleeping %.3fs", attempt, str(e), sleep)
            time.sleep(sleep)
            continue
    logger.error("Max retries exceeded for API call after %d attempts", max_retries)
    raise Exception("Max retries exceeded for API call")


def build_prompt(inputscp, previous_rego="", validation_errors="", relax_corner_cases=True): 
    # Format SCP as JSON string for better readability
    scp_str = json.dumps(inputscp, indent=2) if isinstance(inputscp, dict) else str(inputscp)
    
    prompt = f"""Compare the following SCP and Rego policy for semantic equivalence.
    Identify mismatches in allowed/denied actions, resources, and condition blocks.
    Do not rewrite the policy. Only describe errors. If there are no errors, return an empty string.

    SCP:
    {scp_str}

    Rego:
    {previous_rego if previous_rego else "(No previous Rego provided)"}
"""
    # Explicit, unambiguous instruction about corner cases
    if relax_corner_cases:
        prompt += """
        Important assumptions for this comparison (DEFAULT BEHAVIOR):
        - For this analysis, assume any context keys referenced in conditions (e.g. aws:RequestedRegion) are present and non-empty.
        - Do NOT report mismatches that only arise from missing or empty request context attributes (corner cases) such as global services or absent aws:RequestedRegion.
        - Focus only on direct semantic differences in allowed/denied actions, resources, and condition values as written.
        """
    else:
        prompt += """
        Strict behavior (relax_corner_cases = false):
        - Consider and report differences that arise from missing or empty context attributes (e.g. aws:RequestedRegion absent vs present).
        - Report any semantic divergence caused by different handling of missing/empty context keys.
        """

    if validation_errors:
        prompt += f"""
        Previous validation errors (for context):
        {validation_errors}
        """
    
    prompt += "\nOutput only the errors found, or an empty string if there are no errors."
    
    return prompt

def lambda_handler(event,context): 
    try: 
        # Configure logger for the Lambda invocation
        logger = logging.getLogger(__name__)
        if not logger.handlers:
            handler = logging.StreamHandler()
            fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
            handler.setFormatter(fmt)
            logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        logger.info("lambda_handler invoked")
        logger.info("Incoming event: %s", json.dumps(event, default=str))

        if "scp" not in event:
            logger.error("Missing 'scp' in request payload")
            return {
                "statusCode": 400,
                "error": "Missing 'scp' in request"
            }
        scp = event["scp"]
        prev_rego = event.get("previous_rego","") # fetch previous rego that failed if exists
        errors = event.get("validation_errors","")
        # allow caller to override corner-case behavior (default: True = relax corner cases)
        relax_corner_cases = event.get("relax_corner_cases", True)
        logger.info("relax_corner_cases=%s", relax_corner_cases)
        # Log any provided validation errors (truncated)
        if errors:
            try:
                logger.info("Provided validation_errors: %s", str(errors)[:2000])
            except Exception:
                logger.info("Provided validation_errors present but could not be stringified")
        prompt = build_prompt(scp, prev_rego, errors, relax_corner_cases)
        # Avoid logging the full prompt if it's huge; log a truncated preview
        logger.debug("Built prompt preview: %s", prompt[:2000])

        logger.info("Calling Bedrock converse API (modelId=%s)", model_id)
        response = _call_with_backoff(
            client.converse,
            modelId=model_id,
            messages=[{
                "role": "user",
                "content": [{"text": prompt}]
            }],
            inferenceConfig={
                "maxTokens": 8192  # max length of response
            }
        )

        try:
            logger.info("Bedrock response keys: %s", list(response.keys()))
            # Log truncated JSON-safe representation of response
            logger.debug("Bedrock response (truncated): %s", json.dumps(response, default=str)[:2000])
        except Exception:
            logger.debug("Bedrock response present but could not be JSON-serialized")

        # Safely extract response content
        content = response.get("output", {}).get("message", {}).get("content", [])
        if not content or "text" not in content[0]:
            logger.info("No textual content returned by model; treating as no errors")
            errors = ""
        else:
            errors = content[0]["text"].strip()
            logger.info("Model returned content (truncated): %s", errors[:2000])
        # if there are no errors then errors is set to nothing and therefore passes 
        return {
            "statusCode": 200,
            "scp": scp,
            "previous_rego": prev_rego,
            "stopReason": response.get("stopReason"),
            "usage": response.get("usage", {}),
            "errors": errors
        }
    except Exception as e:
        # Log full stack trace to CloudWatch logs for debugging
        logger = logging.getLogger(__name__)
        logger.exception("Error in lambda function: %s", str(e))
        tb = traceback.format_exc()
        logger.debug("Stack trace: %s", tb)
        return {
            "statusCode": 500,
            "error": str(e),
            "stack_trace": tb
        }