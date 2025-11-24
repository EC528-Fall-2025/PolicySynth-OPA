import json 
import boto3
import os
import subprocess
import tempfile
from typing import Dict, Any

# validate syntax by running opa eval / check with input rego file, output rego file if passes 
def lambda_handler(event,context): 
    # Initialize default values
    scp = event.get("scp", {})
    rego = event.get("previous_rego", "")
    input_data = event.get("input_data", "")
    query = event.get("query", "")

    try: 
        if "rego" not in event: 
            return { 
                "scp": scp,
                "previous_rego": rego,
                "errors": json.dumps({"error": "no rego in request"})
            }
        # parse inputs
        rego_code = event["rego"]
        passed, errors = run_opa_check(rego_code)
        if passed and len(errors) == 0:
            if "input_data" not in event or not input_data: # cant run opa eval without test inputs
                return { 
                    "scp": scp,
                    "previous_rego": rego,  
                    "errors": json.dumps({"error": "no input data"})
                }
            eval_passed, eval_result = run_opa_eval(rego_code, input_data, query)
            if eval_passed:
                return {
                    "scp": scp,
                    "previous_rego": rego_code,
                    "rego": rego_code,
                    "errors": "",
                    "eval_result": json.dumps(eval_result) if isinstance(eval_result, dict) else str(eval_result)
                }
            else:
                return {
                    "scp": scp,
                    "previous_rego": rego,
                    "errors": json.dumps({"error": "opa eval failed", "details": str(eval_result)})
                }
        else: 
            # Serialize errors list to JSON string
            errors_str = json.dumps({"syntax_errors": errors}) if isinstance(errors, list) else json.dumps({"error": str(errors)})
            return { 
                "scp": scp,
                "previous_rego": rego,
                "errors": errors_str
            }
    except Exception as e: 
        print(f"Error in lambda_validate_syntax: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            "scp": scp,
            "previous_rego": rego, 
            "errors": json.dumps({"error": f"Exception in syntax validation: {str(e)}"})
        }

def run_opa_check(rego_code: str): 
    # run opa check for syntax validation
    opa_path = os.environ.get("OPA_PATH")
    if not opa_path:
        return False, ["OPA_PATH environment variable not set"]
    
    temp_file = None
    # write rego file to temp file 
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False) as f: 
            f.write(rego_code)
            temp_file = f.name
        
        result = subprocess.run([opa_path, "check", temp_file], capture_output=True, text=True, timeout=10)
        print("opa check output", result.stdout)
        if result.returncode == 0: 
            print("Policy syntax passed")
            return True, []
        # Filter out empty strings from error list
        errors = [line for line in result.stderr.strip().split("\n") if line.strip()]
        return False, errors if errors else ["Syntax check failed with unknown error"]
    except subprocess.TimeoutExpired:
        return False, ["OPA check timed out"]
    except Exception as e:
        return False, [f"Error running OPA check: {str(e)}"]
    finally:
        if temp_file:
            try:
                os.remove(temp_file)
            except:
                pass

def run_opa_eval(rego_code, input_data, query): 
    # passing returns: bool passed=True, result dict
    # failing returns: bool passed=False, error message string
    temp_policy = None
    temp_input = None
    opa_path = os.environ.get("OPA_PATH")
    
    if not opa_path:
        return False, "OPA_PATH environment variable not set"
    
    try:
        # run opa eval with input data after syntax passed
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False) as f: 
            f.write(rego_code)
            temp_policy = f.name
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f: 
            f.write(input_data)
            temp_input = f.name
        
        result = subprocess.run(
            [opa_path, "eval", "-d", temp_policy, "-i", temp_input, "--format", "json", query],
            capture_output=True, text=True, timeout=10
        )
        
        if result.returncode != 0:
            error_msg = result.stderr if result.stderr else result.stdout
            return False, f"OPA eval failed: {error_msg}"
        
        try:
            output = json.loads(result.stdout)
            return True, output
        except json.JSONDecodeError as e:
            return False, f"Failed to parse OPA eval output as JSON: {str(e)}"
            
    except subprocess.TimeoutExpired:
        return False, "OPA eval timed out"
    except Exception as e: 
        return False, f"Error running OPA eval: {str(e)}"
    finally:
        for temp_file in [temp_policy, temp_input]:
            if temp_file and os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception:
                    pass