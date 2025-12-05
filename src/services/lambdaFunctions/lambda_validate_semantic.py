import json
import boto3
import random
import time
from botocore.exceptions import ClientError, BotoCoreError, EndpointConnectionError
import logging
import traceback
import os
import subprocess
import tempfile

client = boto3.client("bedrock-runtime", region_name = "us-east-1")
s3 = boto3.client("s3")

model_id = "global.anthropic.claude-sonnet-4-5-20250929-v1:0"

# OPA binary path
OPA_PATH = "/opt/bin/opa"

# Terraform plan location + query
TERRAFORM_PLAN_BUCKET = os.getenv("TERRAFORM_PLAN_BUCKET", "terraform-input-data")
TERRAFORM_PLAN_KEY = os.getenv("TERRAFORM_PLAN_KEY", "plan.json")
TERRAFORM_PLAN_QUERY = os.getenv("TERRAFORM_PLAN_QUERY", "data.scp")
ENABLE_TERRAFORM_EVAL = os.getenv("ENABLE_TERRAFORM_EVAL", "true").lower() == "true"


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
    
    prompt += (
        '\nIMPORTANT:\n'
        '- If there are no errors, output exactly this: "" (just two double quotes, nothing else, no JSON object).\n'
        'Do NOT add any additional commentary, explanation, or extra formatting.\n'
    )    
    return prompt

def fetch_terraform_plan():
    """
    Fetch a Terraform plan JSON from S3.
    This is a fixed test fixture used to ensure the generated Rego can be
    evaluated against a real terraform show -json style document.
    """
    logger = logging.getLogger(__name__)
    logger.info(
        "Fetching Terraform plan from s3://%s/%s",
        TERRAFORM_PLAN_BUCKET,
        TERRAFORM_PLAN_KEY,
    )
    try:
        obj = s3.get_object(Bucket=TERRAFORM_PLAN_BUCKET, Key=TERRAFORM_PLAN_KEY)
        data = obj["Body"].read().decode("utf-8")
        logger.info("Fetched Terraform plan (%d bytes)", len(data))
        return data
    except Exception as e:
        logger.error("Failed to fetch Terraform plan from S3: %s", str(e))
        raise

def run_opa_eval_on_terraform(rego_code: str, terraform_plan_json: str, query: str):
    """
    Run `opa eval` using the generated Rego and a Terraform plan JSON as input.
    We treat any non-zero exit code or JSON parse failure as a validation error.
    """
    logger = logging.getLogger(__name__)

    if not os.path.exists(OPA_PATH):
        msg = f"OPA binary not found at {OPA_PATH}"
        logger.error(msg)
        return False, msg

    policy_file = None
    input_file = None

    try:
        # Write policy to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False) as f:
            f.write(rego_code)
            policy_file = f.name

        # Write Terraform plan JSON to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(terraform_plan_json)
            input_file = f.name

        logger.info(
            "Running OPA eval on Terraform plan: opa eval -d %s -i %s '%s'",
            policy_file,
            input_file,
            query,
        )

        result = subprocess.run(
            [OPA_PATH, "eval", "-d", policy_file, "-i", input_file, "--format", "json", query],
            capture_output=True,
            text=True,
            timeout=12,
        )

        logger.debug("OPA eval stdout: %s", result.stdout[:1000])
        logger.debug("OPA eval stderr: %s", result.stderr[:1000])

        if result.returncode != 0:
            msg = result.stderr or result.stdout or "Unknown OPA eval error"
            logger.error("OPA eval on Terraform plan failed (rc=%d): %s", result.returncode, msg)
            return False, f"OPA eval on Terraform plan failed: {msg}"

        # Try to parse JSON to ensure output is well-formed
        try:
            _ = json.loads(result.stdout)
            logger.info("OPA eval on Terraform plan succeeded and returned valid JSON.")
        except json.JSONDecodeError as e:
            logger.error("Failed to parse OPA eval JSON output: %s", str(e))
            return False, f"OPA eval returned invalid JSON: {str(e)}"

        return True, ""
    except subprocess.TimeoutExpired:
        logger.error("OPA eval on Terraform plan timed out.")
        return False, "OPA eval on Terraform plan timed out."
    except Exception as e:
        logger.exception("Error running OPA eval on Terraform plan: %s", str(e))
        return False, f"Exception during OPA eval on Terraform plan: {str(e)}"
    finally:
        for tmp in (policy_file, input_file):
            if tmp and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except Exception:
                    logger.debug("Failed to remove temp file %s", tmp)


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

        # Prefer generated rego from pipeline if present
        generate_result = event.get("generateResult") or {}
        generated_rego = generate_result.get("generated_rego") or prev_rego
        logger.info("generated_rego length: %s", len(generated_rego) if generated_rego else 0)
        logger.info("generated_rego content (truncated): %s", (generated_rego[:200] if generated_rego else "None"))

        if not generated_rego:
            logger.info("No generated_rego or previous_rego found; Terraform eval (if enabled) will be skipped.")

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

        # Normalize Claude's sentinel "\"\"" to a real empty string
        if errors == "\"\"":
            errors = ""
        logger.info("ENABLE_TERRAFORM_EVAL evaluated as: %s", ENABLE_TERRAFORM_EVAL)
        logger.info("errors value before Terraform eval: %r", errors)

        #Terrafrom OPA eval. Only run if: terraform eval is enabled, claude found no errors, we have rego code to eval
        if ENABLE_TERRAFORM_EVAL and errors == "" and generated_rego:
            logger.info("ENABLE_TERRAFORM_EVAL is true and no Claude errors; running OPA eval on Terraform plan.")
            try:
                tf_plan = fetch_terraform_plan()
                passed, tf_err = run_opa_eval_on_terraform(
                    generated_rego,
                    tf_plan,
                    TERRAFORM_PLAN_QUERY
                )
                if not passed:
                    # Treat this as a semantic validation failure so Step Functions will retry/regenerate.
                    logger.error("Terraform OPA eval failed: %s", tf_err)
                    # You can either append or replace; here we prepend to make it obvious.
                    if errors:
                        errors = f"Terraform eval error: {tf_err}\n\n{errors}"
                    else:
                        errors = f"Terraform eval error: {tf_err}"
                else:
                    logger.info("Terraform OPA eval succeeded.")
            except Exception as e:
                # If fetching or running eval throws, we treat as validation failure
                logger.exception("Exception during Terraform eval step: %s", str(e))
                if errors:
                    errors = f"Terraform eval exception: {str(e)}\n\n{errors}"
                else:
                    errors = f"Terraform eval exception: {str(e)}"
        # if there are no errors then errors is set to nothing and therefore passes 
        logger.info("ENABLE_TERRAFORM_EVAL evaluated as: %s", ENABLE_TERRAFORM_EVAL)

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