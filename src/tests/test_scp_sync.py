import io, json, os, tarfile
from moto import mock_aws
import boto3
import types

# import modules from your new package
from src.lambdas.scp_pipeline import app, opa_validator
from src.lambdas.scp_sync import aws, policy_generator

DUMMY_SCPS = [
    {
        "id": "p-123",
        "name": "BlockPassRole",
        "content": {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DenyPassRole",
                "Effect": "Deny",
                "Action": ["iam:PassRole"],
                "Resource": "*"
            }]
        }
    }
]

@mock_aws
def test_create_happy_path(tmp_path, monkeypatch):
    # 1) make region explicit for everything
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

    # 2) S3 mock + bucket
    import boto3
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket = "test-artifacts"
    s3.create_bucket(Bucket=bucket)

    # 3) make the lambda use THIS moto client instance
    from src.lambdas.scp_sync import aws
    monkeypatch.setattr(aws, "_s3", lambda: s3)

    # 4) keep the rest the same
    monkeypatch.setattr(aws, "list_scps", lambda: DUMMY_SCPS)
    monkeypatch.setenv("ARTIFACT_BUCKET", bucket)
    monkeypatch.setenv("ARTIFACT_PREFIX", "generated/scp")

    def fake_eval(bundle_bytes: bytes):
        with tarfile.open(fileobj=io.BytesIO(bundle_bytes), mode="r:gz") as t:
            names = t.getnames()
            assert any(n.startswith("policy/") and n.endswith(".rego") for n in names)
        return {"eval_result": {"result": [{"expressions": [{"value": []}]}]}}
    monkeypatch.setattr(opa_validator, "run_validation_suite", lambda bb: fake_eval(bb))

    resp = app.handle_create({"action": "create"}, None)
    # if it still fails, print the body to see the real exception:
    if resp["statusCode"] != 200:
        print("ERROR BODY:", resp["body"])
    assert resp["statusCode"] == 200

@mock_aws
def test_update_and_delete(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

    import boto3
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket = "test-artifacts"
    s3.create_bucket(Bucket=bucket)

    from src.lambdas.scp_sync import aws
    monkeypatch.setattr(aws, "_s3", lambda: s3)

    monkeypatch.setattr(aws, "list_scps", lambda: DUMMY_SCPS)
    monkeypatch.setenv("ARTIFACT_BUCKET", bucket)
    monkeypatch.setenv("ARTIFACT_PREFIX", "generated/scp")
    monkeypatch.setattr(opa_validator, "run_validation_suite", lambda bb: {"ok": True})

    resp_c = app.handle_create({"action": "create"}, None)
    if resp_c["statusCode"] != 200:
        print("CREATE ERROR:", resp_c["body"])
    assert resp_c["statusCode"] == 200

    resp_u = app.handle_update({"action": "update"}, None)
    if resp_u["statusCode"] != 200:
        print("UPDATE ERROR:", resp_u["body"])
    assert resp_u["statusCode"] == 200

    resp_d = app.handle_delete({"action": "delete"}, None)
    if resp_d["statusCode"] != 200:
        print("DELETE ERROR:", resp_d["body"])
    assert resp_d["statusCode"] == 200

    keys = [o.get("Key") for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])]
    assert "generated/scp/bundle.tar.gz" not in (keys or [])
    assert "generated/scp/metadata.json" not in (keys or [])
