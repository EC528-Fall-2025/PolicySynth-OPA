import json 
import boto3
import os
import subprocess
import tempfile
from typing import Dict, Any

# validate syntax by running opa eval / check with input rego file, output rego file if passes 
def lambda_handler(event,context): 
    """ Event Format: 
    { 
        "rego": <rego code as string> 
        "mode": "check" | "eval"
        "input_data": {...} # for the opa eval testing 
    }
    """ 
    try: 
        if "rego" not in event: 
            return{ 
                "statusCode": 400, 
                "body": json.dumps({"error": "no rego in request"})
            }
        # parse inputs
        rego_code = event["rego"]
        mode = event.get("mode")
        if mode == "check": 
            passed = run_opa_check(rego_code)
        if passed:
            if "input_data" not in event: # cant run opa eval without test inputs
                return{ 
                "statusCode": 400, 
                "body": json.dumps({"error": "no rego in request"})
                }
            return run_opa_eval(rego_code)
        else: 
            return { "statusCode": 400, "body": json.dumps({"error":"no rego in request"})}
    except Exception as e: 
        return{
            "statusCode": 400, 
            "body": json.dumps({"error": "no rego in request"})
        }

def run_opa_check(rego_code: str): 
# run opa check for syntax validation
    passed = False 
    opa_path = os.environ.get("OPA_PATH")
    # write rego file to temp file 
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False) as f: 
        f.write(rego_code)
        temp_file = f.name
    try: 
        result = subprocess.run([opa_path, "check", temp_file], capture_output=True, text=True, check=True, timeout=10)
        print("opa check output", result.stdout)
        if result.returncode == 0: 
            print("Policy syntax passed")
            passed = True
    except subprocess.CalledProcessError as e: 
        print(f"Error running OPA: {e}")
    return passed

def run_opa_eval(rego_code, input_data, query): 
    # passing returns: bool passed=True, scp, rego, errors 
    # failing returns: bool passed=False, scp, rego, errors and goes back to generate lambda function 
    temp_policy= None
    temp_input= None
    # run opa eval with input dataafter syntax passed
    opa_path = os.environ.get("OPA_PATH")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False) as f: 
        f.write(input_data)
        temp_policy = f.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f: 
        f.write(input_data)
        temp_input = f.name
    try: 
        result = subprocess.run(
            [opa_path, "eval", "-d", temp_policy, "-i", temp_input, "--format", "json", query],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return False, result.stderr or result.stdout
        output = json.loads(result.stdout)
        return True, output
    except Exception as e: 
        return False, None, rego_code, str(e)
    finally:
        for temp_file in [temp_policy, temp_input]:
            if temp_file and os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception:
                    pass