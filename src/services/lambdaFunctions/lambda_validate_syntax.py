import json 
import boto3
import os
import subprocess
import tempfile
import logging

# fetch input data for opa eval
s3 = boto3.client("s3")

# logger setup
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("lambda_validate_syntax")
logger.debug("Logger initialized with level %s", LOG_LEVEL)


def fetch_input_data(policy_id: str):
    """
    Fetch the corresponding input data for the given SCP from S3.
    Returns a JSON string.
    """
    bucket_name = "terraform-input-data"
    try:
        logger.debug("Fetching input data from S3 bucket=%s for policy_id=%s", bucket_name, policy_id)
        obj = s3.get_object(Bucket=bucket_name, Key="p-wao9ivzf_main_denied.json")
        data = obj["Body"].read().decode("utf-8")
        logger.info("Fetched input data for policy_id=%s (size=%d bytes)", policy_id, len(data))
        return data
    except s3.exceptions.NoSuchKey:
        logger.warning("No input data found in S3 for policy_id=%s", policy_id)
        raise Exception(f"No input data found for policy {policy_id} in S3 bucket {bucket_name}")
    except Exception as e:
        logger.exception("Error fetching input data for policy_id=%s: %s", policy_id, str(e))
        raise Exception(f"Error fetching input data: {str(e)}")


# validate syntax by running opa eval / check with input rego file,
# output rego file if passes
def lambda_handler(event,context):
    try:
        # Initialize default values
        logger.debug("lambda_handler invoked with event: %s", event)
        scp = event["scp"]
        rego = event["previous_rego"]
        query = "data.scp"
        policy_id = event["policyId"]

        if "previous_rego" not in event:
            logger.warning("Request missing 'previous_rego' field")
            return {
                "scp": scp,
                "previous_rego": rego,
                "errors": json.dumps({"error": "no rego in request"})
            }
        passed, errors = run_opa_check(rego)
        logger.debug("OPA check result for policy_id=%s: passed=%s, errors=%s", policy_id, passed, errors)
        if passed and len(errors) == 0:
            input_data = event.get("input_data", fetch_input_data(policy_id))
            if not input_data:
                logger.warning("No input data available for opa eval for policy_id=%s", policy_id)
                return {
                    "scp": scp,
                    "previous_rego": rego,
                    "errors": json.dumps({"error": "no input data"})
                }
            eval_passed, eval_result = run_opa_eval(rego, input_data, query)
            logger.debug("OPA eval result for policy_id=%s: eval_passed=%s", policy_id, eval_passed)
            if eval_passed:
                return {
                    "scp": scp,
                    "previous_rego": rego,
                    "errors": json.dumps(eval_result) if isinstance(eval_result, dict) else str(eval_result)
                }
            else:
                logger.error("OPA eval failed for policy_id=%s: %s", policy_id, eval_result)
                return {
                    "scp": scp,
                    "previous_rego": rego,
                    "errors": json.dumps({"error": "opa eval failed", "details": str(eval_result)})
                }
        else:
            # Serialize errors list to JSON string
            errors_str = json.dumps({"syntax_errors": errors}) if isinstance(errors, list) else json.dumps({"error": str(errors)})
            logger.error("OPA syntax check failed for policy_id=%s: %s", policy_id, errors)
            return {
                "scp": scp,
                "previous_rego": rego,
                "errors": errors_str
            }
    except Exception as e:
        logger.exception("Error in lambda_validate_syntax: %s", str(e))
        return {
            "scp": scp,
            "previous_rego": rego,
            "errors": json.dumps({"error": f"Exception in syntax validation: {str(e)}"})
        }


def run_opa_check(rego_code: str):
    # run opa check for syntax validation
    opa_path = "opt/bin/opa"
    logger.debug("Checking OPA binary at path: %s", opa_path)
    if not os.path.exists(opa_path):
        logger.error("OPA binary not found at %s", opa_path)
        return False, [f"OPA binary not found at {opa_path}"]

    temp_file = None
    # write rego file to temp file
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False) as f:
            f.write(rego_code)
            temp_file = f.name
        logger.debug("Wrote temporary rego file: %s", temp_file)

        result = subprocess.run([opa_path, "check", temp_file], capture_output=True, text=True, timeout=10)
        logger.debug("OPA check stdout: %s", result.stdout)
        logger.debug("OPA check stderr: %s", result.stderr)
        if result.returncode == 0:
            logger.info("Policy syntax passed for temp file %s", temp_file)
            return True, []
        # Filter out empty strings from error list
        errors = [line for line in result.stderr.strip().split("\n") if line.strip()]
        return False, errors if errors else ["Syntax check failed with unknown error"]
    except subprocess.TimeoutExpired:
        logger.error("OPA check timed out for temp file %s", temp_file)
        return False, ["OPA check timed out"]
    except Exception as e:
        logger.exception("Error running OPA check: %s", str(e))
        return False, [f"Error running OPA check: {str(e)}"]
    finally:
        if temp_file:
            try:
                os.remove(temp_file)
            except:
                logger.debug("Failed to remove temp file %s", temp_file)


def run_opa_eval(rego_code, input_data, query): 
    # passing returns: bool passed=True, result dict
    # failing returns: bool passed=False, error message string
    temp_policy = None
    temp_input = None
    opa_path = "opt/bin/opa"

    logger.debug("Preparing to run opa eval using binary: %s", opa_path)
    if not opa_path:
        logger.error("OPA_PATH environment variable not set or opa path empty")
        return False, "OPA_PATH environment variable not set"

    try:
        # run opa eval with input data after syntax passed
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False) as f: 
            f.write(rego_code)
            temp_policy = f.name
        logger.debug("Wrote temporary policy file: %s", temp_policy)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f: 
            f.write(input_data)
            temp_input = f.name
        logger.debug("Wrote temporary input file: %s", temp_input)

        result = subprocess.run(
            [opa_path, "eval", "-d", temp_policy, "-i", temp_input, "--format", "json", query],
            capture_output=True, text=True, timeout=10
        )

        if result.returncode != 0:
            error_msg = result.stderr if result.stderr else result.stdout
            logger.error("OPA eval failed (rc=%s): %s", result.returncode, error_msg)
            return False, f"OPA eval failed: {error_msg}"

        try:
            output = json.loads(result.stdout)
            logger.info("OPA eval succeeded, parsed JSON output")
            return True, output
        except json.JSONDecodeError as e:
            logger.exception("Failed to parse OPA eval output as JSON: %s", str(e))
            return False, f"Failed to parse OPA eval output as JSON: {str(e)}"

    except subprocess.TimeoutExpired:
        logger.error("OPA eval timed out for policy %s", temp_policy)
        return False, "OPA eval timed out"
    except Exception as e: 
        logger.exception("Error running OPA eval: %s", str(e))
        return False, f"Error running OPA eval: {str(e)}"
    finally:
        for temp_file in [temp_policy, temp_input]:
            if temp_file and os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception:
                    logger.debug("Failed to remove temp file %s in finally", temp_file)
