from src.utils.s3_handler import S3Handler
import logging

#handler = S3Handler(bucket_name="policy-synthesizer-test-bucket", region_name="us-east-1")
#handler.put_json(f"metadata/test.json", {"message": "hello from PolicySynth!"})
#handler.put_json(f"policies/test.json", {"message": "hello from PolicySynth!"})

# example workflow 
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)  # Only for local test

    handler = S3Handler(bucket_name="policy-synthesizer-test-bucket")
    test_data = {"message": "hello with error handling"}

    try:
        handler.put_json("test-error-handling.json", test_data)
        result = handler.get_json("test-error-handling.json")
        print("Retrieved:", result)
    except Exception as e:
        logger.exception("Operation failed")
