import json
from datetime import datetime
from src.services.translator import translate
from src.utils.s3_handler import S3Handler

def translate_and_upload(scp_policy: dict, bucket_name: str):
    """
    Translates a given SCP policy JSON into a Rego file
    and uploads it to an S3 bucket.
    """
    # Step 1: Translate to Rego policy string using your existing translator
    rego_str = translate(scp_policy)

    # Step 2: Prepare S3 upload info
    policy_name = scp_policy.get("Name", "unnamed-policy").lower().replace(" ", "_")
    rego_key = f"rego_policies/{policy_name}.rego"
    metadata_key = f"metadata/{policy_name}.json"

    # Step 3: Initialize S3 handler
    handler = S3Handler(bucket_name=bucket_name)

    # Step 4: Upload the .rego file
    print(f"Uploading {policy_name}.rego to S3...")
    handler.s3.put_object(
        Bucket=bucket_name,
        Key=rego_key,
        Body=rego_str,
        ContentType="text/plain",
        ServerSideEncryption="AES256"
    )
    print(f"Uploaded Rego policy to s3://{bucket_name}/{rego_key}")

    # Step 5: Upload metadata JSON (optional but useful)
    metadata = {
        "policy_name": policy_name,
        "source": "scp",
        "uploaded_at": datetime.utcnow().isoformat(),
        "s3_key": rego_key
    }
    handler.put_json(metadata_key, metadata)
    print(f"Uploaded metadata to s3://{bucket_name}/{metadata_key}")

    return {"rego_key": rego_key, "metadata_key": metadata_key}


def translate_all_and_upload(json_file_path: str, bucket_name: str):
    """
    Reads a JSON file containing multiple SCPs,
    translates each one, and uploads to S3.
    """
    with open(json_file_path, "r") as f:
        scps = json.load(f)

    for scp in scps:
        try:
            translate_and_upload(scp, bucket_name)
        except Exception as e:
            print(f"Failed for {scp.get('Name', 'unknown')}: {e}")


if __name__ == "__main__":
    # Example usage:
    # python -m src.services.translate_and_upload
    bucket_name = "policy-synthesizer-test-bucket"
    json_file_path = "src/tests/mockSCP.json"  # or your actual SCP fetch output file

    translate_all_and_upload(json_file_path, bucket_name)
