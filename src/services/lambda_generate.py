import json 
import boto3
import os
import re

# takes SCP Json as input, feeds to Claude with prompt and spits out rego policy 
# creates bedrock client to connect to claude 
client = boto3.client("bedrock-runtime", region_name = "us-east-1")

# set model id
#model_id = "anthropic.claude-sonnet-4-5-20250929-v1:0"
model_id = "global.anthropic.claude-sonnet-4-5-20250929-v1:0" # have to use the cross-region inference profile ID instead for this model

# build prompt creates general prompt for LLM with inputscp, previous rego, and validation errors if applicable. 
def build_prompt(inputSCP, previous_rego="", validation_errors=""): 
    prompt = f"""
    You are an expert in AWS IAM, Service Control Policies (SCPs), and OPA Rego.

    Your task: Convert the following AWS SCP JSON into a functionally equivalent
    OPA Rego policy. The output must enforce the exact same permission boundaries,
    conditions, and semantics.

    INPUT SCP JSON:
    {inputSCP}

    If validation errors are provided, they describe how the previous Rego output
    failed semantically or syntactically. Use them to improve/fix the next version.

    PREVIOUS REGO (if any):
    {previous_rego}

    VALIDATION ERRORS (if any):
    {validation_errors}

    REQUIREMENTS:
    1. Output ONLY raw Rego code - DO NOT wrap it in markdown code fences or backticks.
    2. The policy MUST exactly replicate the SCP’s logic.
    3. Preserve all condition logic, including:
    - StringLike, StringEquals, ArnLike
    - NotAction, NotResource, Deny overrides
    - Condition operators
    4. If previous Rego exists, refine it rather than rewriting blindly.
    5. Do NOT include explanations or comments unless formatted as Rego comments.

    Output:
    """
    return prompt 
def lambda_handler(event, context): 
    try: 
        if "scp" not in event:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "Missing 'scp' in request"})
            }
        scp = event["scp"]
        prev_rego = event.get("previous_rego","") # fetch previous rego that failed if exists
        errors = event.get("validation_errors","") ## if previous rego did not pass we need the validation errors to feed context to Claude
        # build prompt with args
        prompt = build_prompt(scp, prev_rego, errors)
        # call claude passing arguments
        response = client.converse(
            modelId=model_id,
            messages=[{
                "role": "user",
                "content": [{"text": prompt}] # pass in prompt here
            }],
            inferenceConfig={
                "maxTokens":8192 # max length of response 
            }
        )
        content = response["output"]["message"]["content"]
        rego_output = content[0]["text"]
        rego_output = strip_fenced_code(rego_output)
        return {
            "statusCode": 200,
            "body": json.dumps({
                "rego": rego_output,
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


def strip_fenced_code(text): 
    """Remove markdown code fences from LLM output"""
    if not text:
        return text
    text = text.strip()
    
    pattern = r"```(?:\w+)?\s*\n(.*?)```"
    match = re.search(pattern, text, re.DOTALL) # dotall makes it match all characters

    if match:
        return match.group(1).strip() # if its a match then remove it 

    # If no fenced block found, return raw text
    return text.strip()