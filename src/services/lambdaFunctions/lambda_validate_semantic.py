import json
import boto3
import random
import time
from botocore.exceptions import ClientError, BotoCoreError, EndpointConnectionError

client = boto3.client("bedrock-runtime", region_name = "us-east-1")

model_id = "global.anthropic.claude-sonnet-4-5-20250929-v1:0"

def _call_with_backoff(func, *args, max_retries=6, base_delay=0.5, **kwargs):
    for attempt in range(1, max_retries + 1):
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
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
                time.sleep(sleep)
                continue
            raise
        except (BotoCoreError, EndpointConnectionError):
            sleep = random.uniform(0, base_delay * (2 ** (attempt - 1)))
            time.sleep(sleep)
            continue
    raise Exception("Max retries exceeded for API call")


def build_prompt(inputscp, previous_rego="", validation_errors=""): 
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
    
    if validation_errors:
        prompt += f"""
Previous validation errors (for context):
{validation_errors}
"""
    
    prompt += "\nOutput only the errors found, or an empty string if there are no errors."
    
    return prompt

def lambda_handler(event,context): 
    try: 
        if "scp" not in event:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "Missing 'scp' in request"})
            }
        scp = event["scp"]
        prev_rego = event.get("previous_rego","") # fetch previous rego that failed if exists
        errors = event.get("validation_errors","")
        prompt = build_prompt(scp, prev_rego, errors)
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

        # Safely extract response content
        content = response.get("output", {}).get("message", {}).get("content", [])
        if not content or "text" not in content[0]:
            errors = ""
        else:
            errors = content[0]["text"].strip()
        # if there are no errors then errors is set to nothing and therefore passes 
        return {
            "statusCode": 200,
            "body": json.dumps({
                "scp":scp, 
                "previous_rego": prev_rego, 
                "errors": errors,
                "stopReason": response.get("stopReason"),
                "usage": response.get("usage", {})
            })
        }
    except Exception as e:
        print(f"Error in lambda function: ", str(e))
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }