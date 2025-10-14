# translate.py
from pathlib import Path
import json
from textwrap import dedent

def _write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.strip() + "\n", encoding="utf-8")

def _rego_header(pkg: str) -> str:
    return f"package {pkg}\n\n# Input: Terraform plan JSON (terraform show -json)\n"

def _rego_sg_no_0000() -> str:
    return dedent("""
    # Deny SG ingress from 0.0.0.0/0
    deny[msg] {
      rc := input.resource_changes[_]
      rc.type == "aws_security_group"
      after := rc.change.after
      after.ingress[_].cidr_blocks[_] == "0.0.0.0/0"
      msg := sprintf("Security Group %s allows 0.0.0.0/0 ingress", [rc.name])
    }
    """)

def _rego_s3_no_public() -> str:
    return dedent("""
    # Deny public S3 bucket via ACL or missing public access block
    deny[msg] {
      rc := input.resource_changes[_]
      rc.type == "aws_s3_bucket"
      after := rc.change.after
      after.acl == "public-read"
      msg := sprintf("S3 bucket %s has public ACL", [rc.name])
    }

    deny[msg] {
      rc := input.resource_changes[_]
      rc.type == "aws_s3_bucket_public_access_block"
      after := rc.change.after
      not after.block_public_acls
      msg := sprintf("S3 public access not fully blocked for %s", [rc.name])
    }
    """)

def _rego_ebs_encrypted() -> str:
    return dedent("""
    # Require EBS encryption
    deny[msg] {
      rc := input.resource_changes[_]
      rc.type == "aws_ebs_volume"
      after := rc.change.after
      not after.encrypted
      msg := sprintf("EBS volume %s is not encrypted", [rc.name])
    }

    deny[msg] {
      rc := input.resource_changes[_]
      rc.type == "aws_launch_template"
      after := rc.change.after
      bd := after.block_device_mappings[_]
      ebs := bd.ebs
      ebs.encrypted == false
      msg := sprintf("Launch template %s has unencrypted EBS", [rc.name])
    }
    """)

def _unit_tests() -> str:
    return dedent("""
    package policy.tests
    import data.terraform.policy as p

    test_sg_open() {
      input := {"resource_changes": [{
        "type": "aws_security_group",
        "name": "web-sg",
        "change": {"after": {"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]}}
      }]}
      count(p.deny with input as input) == 1
    }

    test_s3_public_acl() {
      input := {"resource_changes": [{
        "type": "aws_s3_bucket",
        "name": "my-bucket",
        "change": {"after": {"acl": "public-read"}}
      }]}
      count(p.deny with input as input) == 1
    }

    test_ebs_unencrypted() {
      input := {"resource_changes": [{
        "type": "aws_ebs_volume",
        "name": "vol-1",
        "change": {"after": {"encrypted": false}}
      }]}
      count(p.deny with input as input) == 1
    }
    """)

def run(input_path: Path, out_dir: Path):
    if not input_path.exists():
        raise FileNotFoundError(f"Missing guardrails file: {input_path}")
    meta = json.loads(input_path.read_text(encoding="utf-8"))

    # 主策略
    pkg = "terraform.policy"
    content = [_rego_header(pkg), _rego_sg_no_0000(), _rego_s3_no_public(), _rego_ebs_encrypted()]
    _write(out_dir / "policy.rego", "\n".join(content))

    # 入口/说明/测试
    _write(out_dir / "manifest.yaml", "entrypoint: terraform/policy.rego")
    tests_dir = out_dir.parent / "tests"
    _write(tests_dir / "policy_test.rego", _unit_tests())
    _write(out_dir / "README.md",
           f"# Generated from {input_path.name}\n\nDiscovered at: {meta.get('discovered_at')}\n")
