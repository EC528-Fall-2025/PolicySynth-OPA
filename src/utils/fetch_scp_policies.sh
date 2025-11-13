#!/bin/bash
set -euo pipefail

# output
OUTPUT_DIR="src/policies/json"
mkdir -p "$OUTPUT_DIR"

echo "=== Fetching AWS Service Control Policies (SCP) ==="

# all scp
POLICY_IDS=$(aws organizations list-policies \
  --filter SERVICE_CONTROL_POLICY \
  --query 'Policies[].Id' \
  --output text)

if [ -z "$POLICY_IDS" ]; then
  echo "No SCP policies found in your AWS Organization."
  exit 0
fi

# sanitize filename: keep only [A-Za-z0-9._-], spaces -> _
sanitize() {
  local s="$1"
  s="${s// /_}"
  s="$(echo -n "$s" | tr -cd 'A-Za-z0-9._-')"
  [ -z "$s" ] && s="policy"
  echo "$s"
}

# download
for POLICY_ID in $POLICY_IDS; do
  POLICY_NAME=$(aws organizations describe-policy \
    --policy-id "$POLICY_ID" \
    --query 'Policy.PolicySummary.Name' \
    --output text)

  SAFE_NAME=$(sanitize "$POLICY_NAME")
  OUTPUT_FILE="${OUTPUT_DIR}/${SAFE_NAME}.json"

  if [ -e "$OUTPUT_FILE" ]; then
    OUTPUT_FILE="${OUTPUT_DIR}/${SAFE_NAME}_${POLICY_ID}.json"
  fi

  echo "Downloading policy: $POLICY_NAME -> $OUTPUT_FILE"

  aws organizations describe-policy \
    --policy-id "$POLICY_ID" \
    --output json > "$OUTPUT_FILE"
done

echo "All SCP policies saved to: $OUTPUT_DIR"
