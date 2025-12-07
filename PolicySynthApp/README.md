# PolicySynthApp

**Validate your Terraform infrastructure against AWS Service Control Policies (SCPs) automatically.**

This application converts SCP policies into OPA Rego policies and validates your Terraform plans to ensure compliance with organizational policies. When an SCP is created or updated, it automatically checks if your Terraform plan would be allowed or denied.

## What This Does

1. **Monitors SCP Changes:** Automatically detects when SCP policies are created, updated, or deleted via EventBridge
2. **Converts to Rego:** Uses AWS Bedrock (Claude) to convert SCP JSON to OPA Rego policies
3. **Validates Terraform:** Checks your Terraform plan against the generated Rego policy
4. **Sends Alerts:** Emails you if your Terraform violates SCP policies

## Quick Start Guide

**You have a Terraform project and want to check if it complies with your organization's SCP policies? Follow these steps:**

### Prerequisites

- ✅ AWS CLI installed and configured (`aws configure`)
- ✅ SAM CLI installed ([Installation Guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html))
- ✅ Docker installed and running
- ✅ Access to AWS Organizations
- ✅ Bedrock model access enabled for Claude Sonnet 4.5 ([Enable in Bedrock Console](https://console.aws.amazon.com/bedrock/))

### Step 1: Deploy the Application

```bash
cd PolicySynthApp
sam build
sam deploy --guided
```

When prompted:
- **Stack Name:** `PolicySynthStateMachine` (or your preferred name)
- **Region:** Choose your AWS region (e.g., `us-east-1`)
- **Confirm changes:** `Y`
- **Allow IAM role creation:** `Y` (required)
- **Save arguments:** `Y`

⏱️ Wait 5-10 minutes for deployment. Note your stack name:
```bash
STACK_NAME="PolicySynthStateMachine"  # Or whatever you named it
```

### Step 2: Prepare and Upload Your Terraform Plan

In your Terraform project directory:

```bash
# Generate plan
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > plan.json

# Get bucket name and upload
BUCKET_NAME=$(aws cloudformation describe-stack-resources \
  --stack-name ${STACK_NAME} \
  --query "StackResources[?ResourceType=='AWS::S3::Bucket' && LogicalResourceId=='TerraformPlanBucket'].PhysicalResourceId" \
  --output text)

aws s3 cp plan.json s3://${BUCKET_NAME}/plan.json
```

**Alternative:** Find bucket in AWS Console → CloudFormation → Your Stack → Resources → `TerraformPlanBucket`

### Step 3: Set Up Email Notifications (Optional)

1. Go to [Amazon SNS Console](https://console.aws.amazon.com/sns/)
2. Find topic: `SendTerraformViolationEmail-PolicySynth`
3. Create subscription → Email → Enter your email → Confirm

### Step 4: Trigger Validation

**Automatic (Recommended):**
- Go to AWS Organizations → Policies
- Create or update an SCP
- Validation runs automatically!

**Manual Testing:**
```bash
STATE_MACHINE_ARN=$(aws stepfunctions list-state-machines \
  --query "stateMachines[?name=='StateMachine1bcdcf1e'].stateMachineArn" \
  --output text)

POLICY_ID="p-1234567890"  # Your SCP policy ID
POLICY_JSON=$(aws organizations describe-policy --policy-id ${POLICY_ID} --query 'Policy.Content' --output text)

aws stepfunctions start-execution \
  --state-machine-arn ${STATE_MACHINE_ARN} \
  --input "{
    \"eventName\": \"CreatePolicy\",
    \"policyId\": \"${POLICY_ID}\",
    \"policyName\": \"TestPolicy\",
    \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"policyContent\": ${POLICY_JSON},
    \"counter\": 0
  }"
```

### Step 5: Check Results

```bash
# View execution status
aws stepfunctions list-executions \
  --state-machine-arn ${STATE_MACHINE_ARN} \
  --max-results 5

# View logs
sam logs -n ValidateSemanticPolicy --stack-name ${STACK_NAME} --tail
```

**Expected Results:**
- ✅ **Compliant:** Terraform passes → Policy stored in S3
- ⚠️ **Non-Compliant:** Terraform violates SCP → Email sent (if subscribed)
- ❌ **Error:** Check logs for details

### Updating Your Plan

When you change your Terraform configuration:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
aws s3 cp plan.json s3://${BUCKET_NAME}/plan.json
```

The next SCP validation will use your updated plan automatically.

## How It Works

1. **EventBridge** monitors AWS Organizations for SCP changes (Create/Update/Delete)
2. **State Machine** is automatically triggered
3. **Bedrock (Claude)** converts SCP JSON to OPA Rego policy
4. **OPA** validates syntax and evaluates against your Terraform plan
5. **Results** are stored in S3; violations trigger email notifications

## Troubleshooting

**Validation not running:**
- Verify plan exists at `s3://{bucket}/plan.json`
- Check `ENABLE_TERRAFORM_EVAL` is `"true"` (default)
- Review Lambda logs: `sam logs -n ValidateSemanticPolicy --stack-name ${STACK_NAME}`

**Plan not found:**
- Verify bucket name and key are correct
- Check S3 bucket permissions
- Ensure plan file is valid JSON

**Validation always fails:**
- Check Terraform plan JSON is valid
- Review generated Rego policy in logs
- Check for specific violation details

## Additional Commands

**Build locally (need docker open):**
```bash
sam build --use-container
```
or 
```bash
sam build
```

**View logs:**
```bash
sam logs -n GenerateRego --stack-name ${STACK_NAME} --tail
```

## Cleanup

```bash
sam delete --stack-name "PolicySynthStateMachine"
```

**Warning:** This deletes all resources including S3 buckets and their contents. Backup important data first.

## Resources

- [AWS SAM Developer Guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html)
- [SAM CLI Documentation](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-logging.html)


## Go To Commands

deleting stack (wait) : aws cloudformation wait stack-delete-complete --stack-name PolicySynthStateMachine
check stack status: aws cloudformation describe-stacks --stack-name PolicySynthStateMachine --query 'Stacks[0].StackStatus' --output text
