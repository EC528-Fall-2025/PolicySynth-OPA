import boto3
import json

def main():
    # Initialize clients
    session = boto3.Session(profile_name="policy-test-user")
    config = session.client("config", region_name="us-east-1")
    iam = session.client("iam")

    # Fetch IAM attached policies (first 10 only for test)
    iam_policies = iam.list_attached_user_policies(UserName="policy-test-user")
    with open("iam_policies_sample.json", "w") as f:
        json.dump(iam_policies, f, indent=2, default=str)  # <-- default=str fixes datetime
    print("Saved iam_policies_sample.json")

    # Fetch AWS Config rules
    config_rules = config.describe_config_rules()
    with open("config_rules_sample.json", "w") as f:
        json.dump(config_rules, f, indent=2, default=str)  # <-- same here
    print("Saved config_rules_sample.json")

if __name__ == "__main__":
    main()
