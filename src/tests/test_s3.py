from src.utils.s3_handler import S3Handler
import logging

# Create a module-level logger
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    # Configure logging 
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    bucket = "policy-synthesizer-test-bucket"
    key = "test-error-handling.json"
    test_data = {"message": "hello with error handling"}

    logger.info(f"Starting S3 upload test to bucket '{bucket}'...")

    handler = S3Handler(bucket_name=bucket)

    try:
        # Upload
        handler.put_json(key, test_data)
        logger.info(f"Upload complete for {key}")

        # Download
        result = handler.get_json(key)
        logger.info(f"Downloaded data: {result}")

        print("Retrieved:", result)

    except Exception as e:
        logger.exception("Operation failed during S3 test run")

    finally:
        logger.info("S3 test workflow finished.")

#handler = S3Handler(bucket_name="policy-synthesizer-test-bucket", region_name="us-east-1")
#handler.put_json(f"metadata/test.json", {"message": "hello from PolicySynth!"})
#handler.put_json(f"policies/test.json", {"message": "hello from PolicySynth!"})
