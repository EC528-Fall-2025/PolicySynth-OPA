import json
import os
import shutil
import zipfile
import logging
from datetime import datetime
from pathlib import Path
from src.utils.s3_handler import S3Handler

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Define paths
BASE_DIR = Path(__file__).resolve().parents[2]
REGO_DIR = BASE_DIR / "src" / "rego_policies"
PKG_DIR = BASE_DIR / "src" / "policy_packages"

# Initialize S3 handler
S3_BUCKET = "policy-synthesizer-test-bucket"
s3_handler = S3Handler(bucket_name=S3_BUCKET)


def prepackage_policy(policy_name: str):
    """
    Pre-packages a translated OPA policy (.rego) into a Terraform-ready bundle,
    validates structure, zips it, and uploads to S3.
    """

    policy_file = REGO_DIR / f"{policy_name}.rego"
    package_dir = PKG_DIR / f"{policy_name}-package"

    # Preconditions
    assert policy_file.exists(), f"Policy file not found: {policy_file}"

    # Reset or create output folder
    if package_dir.exists():
        shutil.rmtree(package_dir)
    os.makedirs(package_dir / "policies", exist_ok=True)
    os.makedirs(package_dir / "mock_configs", exist_ok=True)

    # 1. Copy the rego file
    shutil.copy(policy_file, package_dir / "policies" / policy_file.name)
    assert (package_dir / "policies" / policy_file.name).exists(), "Rego file copy failed"

    # 2. Create metadata.json
    metadata = {
        "policy_name": policy_name,
        "created_at": datetime.now().isoformat(),
        "source": "scp_fetch",
        "description": "Auto-translated and pre-packaged OPA policy",
        "version": "v1.0.0",
    }
    with open(package_dir / "metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)
    assert (package_dir / "metadata.json").exists(), "metadata.json missing"

    # 3. Terraform template files
    with open(package_dir / "main.tf", "w") as f:
        f.write(f"""
terraform {{
  required_providers {{
    opa = {{
      source  = "openpolicyagent/opa"
      version = ">=0.5.0"
    }}
  }}
}}

resource "opa_policy" "{policy_name}" {{
  name   = "{policy_name}"
  policy = file("${{path.module}}/policies/{policy_name}.rego")
}}
""")
    assert (package_dir / "main.tf").exists(), "main.tf missing"

    with open(package_dir / "variables.tf", "w") as f:
        f.write('variable "allowed_regions" { type = list(string) }\n')

    with open(package_dir / "terraform.tfvars", "w") as f:
        f.write('allowed_regions = ["us-east-1", "us-west-2", "eu-west-1"]\n')

    # 4. Mock configs (placeholders)
    with open(package_dir / "mock_configs/happy_path.tf", "w") as f:
        f.write('// compliant configuration placeholder\n')

    with open(package_dir / "mock_configs/sad_path.tf", "w") as f:
        f.write('// violating configuration placeholder\n')

    # 5. Zip the package
    zip_path = PKG_DIR / f"{policy_name}-package.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(package_dir):
            for file in files:
                file_path = Path(root) / file
                arcname = file_path.relative_to(package_dir)
                zipf.write(file_path, arcname)

    # Postconditions
    assert zip_path.exists(), "Failed to create package ZIP"
    assert zipfile.is_zipfile(zip_path), "Invalid ZIP file structure"

    logger.info("Pre-packaged policy created successfully: %s", zip_path)

    # 6. Upload to S3
    s3_key = f"policy_packages/{zip_path.name}"
    try:
        s3_handler.upload_file(zip_path, s3_key)
        logger.info("Uploaded package to S3 at key: %s", s3_key)
    except Exception as e:
        logger.exception("S3 upload failed: %s", e)
        raise

    return zip_path


if __name__ == "__main__":
    prepackage_policy("deny-nonapproved-regions")
