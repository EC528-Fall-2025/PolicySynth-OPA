from src.utils.s3_handler import S3Handler

handler = S3Handler(bucket_name="policy-synthesizer-test-bucket", region_name="us-east-1")
handler.put_json(f"metadata/test.json", {"message": "hello from PolicySynth!"})
handler.put_json(f"policies/test.json", {"message": "hello from PolicySynth!"})

# example workflow 
def process_scp_event(event):
    # 1. Pull SCP from event
    scp_id = event["scp_id"]
    policy_data = fetch_scp(scp_id)
    
    # 2. Generate policy + metadata
    generated_policy, metadata = run_policy_generator(policy_data)

    # 3. Save outputs to S3
    s3 = S3Handler(bucket_name="policy-synthesizer-prod-bucket", region_name="us-east-1")

    s3.put_json(f"policies/{scp_id}.json", generated_policy)
    s3.put_json(f"metadata/{scp_id}.json", metadata)

    return {"status": "uploaded", "scp_id": scp_id}
