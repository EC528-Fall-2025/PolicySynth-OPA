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
import re

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
# Terraform test plans (pass/fail suites)
TERRAFORM_TESTS_BUCKET = os.getenv("TERRAFORM_TESTS_BUCKET", TERRAFORM_PLAN_BUCKET)
TERRAFORM_TESTS_PREFIX = os.getenv("TERRAFORM_TESTS_PREFIX", "terraform-tests")

def strip_fenced_code(text): 
    """Remove markdown code fences from LLM output"""
    if not text:
        return text
    text = text.strip()
    
    pattern = r"```(?:\w+)?\s*\n(.*?)```"
    match = re.search(pattern, text, re.DOTALL)

    if match:
        return match.group(1).strip()

    return text.strip()

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

def build_terraform_rego_from_scp(scp: dict) -> str:
    """
    For region guardrails like DenyAllExceptApprovedRegions:
      Effect: Deny
      Condition.StringNotEquals["aws:RequestedRegion"] = [approved regions]

    Generate Terraform-aware Rego using Rego v1 syntax:
      - function heads use `if`
      - partial set uses `contains` in the head
    """
    statements = scp.get("Statement", [])
    approved_regions = []

    for st in statements:
        cond = st.get("Condition", {})
        string_not_equals = cond.get("StringNotEquals", {})
        regions = string_not_equals.get("aws:RequestedRegion")
        if regions:
            approved_regions = regions
            break

    # If we can't recognize a region-based SCP, return a no-op policy
    if not approved_regions:
        return """package scp

deny := []
"""

    lines = []
    lines.append("package scp")
    lines.append("")
    lines.append("# true if region is in the approved list")

    # allowed_region(region) if { region == "us-east-1" }
    for r in approved_regions:
        lines.append(f'allowed_region(region) if {{')
        lines.append(f'  region == "{r}"')
        lines.append("}")
    lines.append("")

    # Partial-set deny rule in new syntax: deny contains reason if { ... }
    lines.append("deny contains reason if {")
    lines.append("  some provider_name")
    lines.append("  pc := input.configuration.provider_config[provider_name]")
    lines.append("  region := pc.expressions.region.constant_value")
    lines.append("  not allowed_region(region)")
    lines.append('  reason := sprintf("provider %v uses disallowed region %v", [provider_name, region])')
    lines.append("}")

    return "\n".join(lines)


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

def fetch_s3_text(bucket: str, key: str) -> str:
    logger = logging.getLogger(__name__)
    logger.info("Fetching S3 object s3://%s/%s", bucket, key)
    obj = s3.get_object(Bucket=bucket, Key=key)
    data = obj["Body"].read().decode("utf-8")
    logger.info("Fetched %d bytes from s3://%s/%s", len(data), bucket, key)
    return data


def list_terraform_test_plans():
    """
    List Terraform test plans in S3, grouped into pass and fail sets.

    Expects keys like:
      terraform-tests/pass/...
      terraform-tests/fail/...
    """
    logger = logging.getLogger(__name__)

    prefix = TERRAFORM_TESTS_PREFIX.rstrip("/") + "/"
    logger.info(
        "Listing Terraform test plans in bucket=%s prefix=%s",
        TERRAFORM_TESTS_BUCKET, prefix
    )

    pass_keys = []
    fail_keys = []

    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=TERRAFORM_TESTS_BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            # skip "folder" placeholder keys and non-json
            if not key.endswith(".json"):
                continue
            if "/pass/" in key:
                pass_keys.append(key)
            elif "/fail/" in key:
                fail_keys.append(key)

    logger.info("Found %d pass plans, %d fail plans", len(pass_keys), len(fail_keys))
    return pass_keys, fail_keys

def opa_eval_terraform_for_violations(rego_code: str, terraform_plan_json: str, query: str):
    """
    Run `opa eval` and interpret the result as a list of violations.

    Assumes the query returns either:
      - a list of violation messages (preferred), or
      - an empty list if compliant.

    Returns:
      (ok: bool, violations: list, error_message: str)
    """
    logger = logging.getLogger(__name__)

    if not os.path.exists(OPA_PATH):
        msg = f"OPA binary not found at {OPA_PATH}"
        logger.error(msg)
        return False, [], msg

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
            "Running OPA eval (semantic) on Terraform plan: opa eval -d %s -i %s '%s'",
            policy_file, input_file, query
        )

        result = subprocess.run(
            [OPA_PATH, "eval", "-d", policy_file, "-i", input_file, "--format", "json", query],
            capture_output=True,
            text=True,
            timeout=12,
        )

        logger.debug("OPA eval stdout (truncated): %s", result.stdout[:1000])
        logger.debug("OPA eval stderr (truncated): %s", result.stderr[:1000])

        if result.returncode != 0:
            msg = result.stderr or result.stdout or "Unknown OPA eval error"
            logger.error("OPA eval failed (rc=%d): %s", result.returncode, msg)
            return False, [], f"OPA eval failed: {msg}"

        # Parse JSON output and extract 'violations'
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse OPA eval JSON output: %s", str(e))
            return False, [], f"OPA eval returned invalid JSON: {str(e)}"

        violations = []
        try:
            result_list = data.get("result", [])
            if result_list:
                expressions = result_list[0].get("expressions", [])
                if expressions:
                    value = expressions[0].get("value")
                    # If value is already a list of violations, use it.
                    if isinstance(value, list):
                        violations = value
                    else:
                        # If your policy returns something different, adapt this logic.
                        logger.warning(
                            "OPA eval value is not a list; got type %s. "
                            "You may need to adjust parsing.",
                            type(value),
                        )
        except Exception as e:
            logger.warning("Error extracting violations from OPA output: %s", str(e))

        logger.info("OPA semantic eval found %d violations", len(violations))
        return True, violations, ""
    except subprocess.TimeoutExpired:
        logger.error("OPA eval on Terraform plan timed out.")
        return False, [], "OPA eval on Terraform plan timed out."
    except Exception as e:
        logger.exception("Error running OPA eval on Terraform plan: %s", str(e))
        return False, [], f"Exception during OPA eval: {str(e)}"
    finally:
        for tmp in (policy_file, input_file):
            if tmp and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except Exception:
                    logger.debug("Failed to remove temp file %s", tmp)


def run_terraform_test_suite(rego_code: str):
    """
    Run the generated Rego against all Terraform test plans in S3.

    For keys under .../pass/... we expect NO violations.
    For keys under .../fail/... we expect AT LEAST ONE violation.

    Returns:
        (all_ok: bool, error_message: str, terraform_non_compliant: bool)

    The third value is True only when OPA evaluation completes successfully
    but exposes non-compliant behavior (violations present when they should
    not be, or violations missing when they should exist).
    """
    logger = logging.getLogger(__name__)

    pass_keys, fail_keys = list_terraform_test_plans()

    # If no test plans are configured, fall back to old single-plan behavior
    if not pass_keys and not fail_keys:
        logger.info(
            "No Terraform test plans found under %s; "
            "falling back to single plan sanity check.",
            TERRAFORM_TESTS_PREFIX,
        )
        try:
            tf_plan = fetch_terraform_plan()
            ok, violations, err = opa_eval_terraform_for_violations(
                rego_code, tf_plan, TERRAFORM_PLAN_QUERY
            )
            if not ok:
                return False, err, False
            if violations:
                header = (
                    f"Fallback Terraform eval reported {len(violations)} violation(s)"
                )
                body = "\n".join(f"- {v}" for v in violations[:10])
                msg = header + "\nViolations:\n" + body
                return False, msg[:2000], True
            return True, "", False
        except Exception as e:
            logger.exception("Exception during fallback Terraform eval: %s", str(e))
            return False, f"Fallback Terraform eval failed: {str(e)}", False

    problems = []
    all_ok = True
    terraform_non_compliant = False

    # Check PASS plans: expect NO violations
    for key in pass_keys:
        plan_json = fetch_s3_text(TERRAFORM_TESTS_BUCKET, key)
        ok, violations, err = opa_eval_terraform_for_violations(
            rego_code, plan_json, TERRAFORM_PLAN_QUERY
        )
        if not ok:
            all_ok = False
            problems.append(f"{key}: eval error: {err}")
        elif violations:
            all_ok = False
            terraform_non_compliant = True

            header = f"{key}: expected NO violations, but got {len(violations)}"
            body = "\n".join(f"- {v}" for v in violations[:10])
            problems.append(header + "\nViolations:\n" + body)

    # Check FAIL plans: expect AT LEAST ONE violation
    for key in fail_keys:
        plan_json = fetch_s3_text(TERRAFORM_TESTS_BUCKET, key)
        ok, violations, err = opa_eval_terraform_for_violations(
            rego_code, plan_json, TERRAFORM_PLAN_QUERY
        )
        if not ok:
            all_ok = False
            problems.append(f"{key}: eval error: {err}")
        elif not violations:
            all_ok = False
            terraform_non_compliant = True
            problems.append(
                f"{key}: expected violations, but got none"
            )

    if all_ok:
        logger.info("All Terraform semantic tests passed.")
        return True, "", False
    else:
        # Join each plan’s block with a blank line between
        msg = "\n\n".join(problems)
        logger.error("Terraform semantic tests failed: %s", msg)
        # Truncate in case it gets huge
        return False, msg[:2000], terraform_non_compliant


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

        terraform_non_compliant = False
        terraform_non_compliance_details = ""

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

        # not using claude to generate terraform rego
        terraform_rego = build_terraform_rego_from_scp(scp)
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

        # Terraform OPA eval. Only run if: terraform eval is enabled, Claude found no semantic errors, we have Rego code to eval
        if ENABLE_TERRAFORM_EVAL and errors == "" and terraform_rego:
            logger.info(
                "ENABLE_TERRAFORM_EVAL is true and no Claude errors; "
                "running Terraform semantic test suite."
            )
            try:
                passed, tf_err, tf_non_compliant = run_terraform_test_suite(terraform_rego)
                terraform_non_compliant = bool(tf_non_compliant)
                terraform_non_compliance_details = tf_err
                if not passed:
                    # Treat this as a semantic validation failure so Step Functions will retry/regenerate.
                    logger.error("Terraform semantic tests failed: %s", tf_err)
                    if errors:
                        errors = f"Terraform eval error: {tf_err}\n\n{errors}"
                    else:
                        errors = f"Terraform eval error: {tf_err}"
                else:
                    logger.info("Terraform semantic tests passed.")
            except Exception as e:
                # If something blows up, treat as validation failure
                logger.exception("Exception during Terraform semantic tests: %s", str(e))
                if errors:
                    errors = f"Terraform eval exception: {str(e)}\n\n{errors}"
                else:
                    errors = f"Terraform eval exception: {str(e)}"
                terraform_non_compliant = False
                terraform_non_compliance_details = str(e)

        # if there are no errors then errors is set to nothing and therefore passes 
        logger.info("ENABLE_TERRAFORM_EVAL evaluated as: %s", ENABLE_TERRAFORM_EVAL)

        # terraform is compliant iff there are no errors
        # and if the terraform_non_compliant flag from the test suite is false
        terraform_non_compliant = terraform_non_compliant or (errors != "")
        return {
            "statusCode": 200,
            "scp": scp,
            "generated_rego": generated_rego,
            "previous_rego": prev_rego,
            "stopReason": response.get("stopReason"),
            "usage": response.get("usage", {}),
            "errors": errors,
            "terraform_non_compliant": terraform_non_compliant,
            "terraform_non_compliance_details": terraform_non_compliance_details
        }
    except Exception as e:
        # Log full stack trace to CloudWatch logs for debugging
        logger = logging.getLogger(__name__)
        logger.exception("Error in lambda function: %s", str(e))
        tb = traceback.format_exc()
        logger.debug("Stack trace: %s", tb)
        return {
            "statusCode": 500,
            "stopReason": response.get("stopReason"),
            "usage": response.get("usage", {}),
            "error": str(e),
            "stack_trace": tb
        }