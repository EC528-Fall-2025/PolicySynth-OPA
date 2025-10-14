# test_db.py
from src.session import init_db
from src.models.db.models import SCP
from datetime import datetime

# Use SQLite in-memory for quick testing
Session = init_db("sqlite:///:memory:")

# Create a session
with Session() as session:
    #Insert test SCP policy
    scp = SCP(
        policy_id="p-123",
        arn="arn:aws:org:policy/p-123",
        name="Test SCP",
        description="Test SCP policy",
        policy_type="SERVICE_CONTROL_POLICY",
        aws_managed=False,
        content='{"Statement": []}',
        policy_summary={"allowedActions": [], "deniedActions": []}
    )
    session.add(scp)
'''
    #Insert test IAM policy
    iam = IAM(
        policy_id="AID-456",
        arn="arn:aws:iam::123456789012:policy/TestPolicy",
        name="Test IAM",
        description="Test IAM policy",
        aws_managed=True,
        content={"Statement": []},
        policy_summary={"allowedActions": [], "deniedActions": []}
    )
    session.add(iam)

    #Insert test ConfigRule
    config = ConfigRule(
        rule_name="TestConfigRule",
        rule_arn="arn:aws:config:rule/TestConfigRule",
        description="Test Config rule",
        scope={"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
        source_identifier="AWSManaged",
        input_parameters={},
        managed=True
    )
    session.add(config)

    session.commit()

    #Query back to verify
    scps = session.query(SCP).all()
    iams = session.query(IAM).all()
    configs = session.query(ConfigRule).all()

    print("SCPs:", scps)
    print("IAMs:", iams)
    print("ConfigRules:", configs)
    scps = session.query(SCP).all()
    iams = session.query(IAM).all()
    configs = session.query(ConfigRule).all()

    print("SCPs:")
    for s in scps:
        print(s.policy_id, s.name, s.arn)

    print("\nIAMs:")
    for i in iams:
        print(i.policy_id, i.name, i.arn)

    print("\nConfigRules:")
    for c in configs:
        print(c.rule_name, c.rule_arn)
'''