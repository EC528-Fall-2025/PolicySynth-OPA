#!/bin/bash

set -e

if ! command -v psynth &> /dev/null; then
    echo "Error: psynth command not found. Make sure the package is installed."
    exit 1
fi

OUTPUT_FILE=${OUTPUT_FILE:-"service_control_policies.json"}

echo "Fetching SCP policies..."
psynth fetch-scp --output "$OUTPUT_FILE"

# check if file was created

if [ -f "$OUTPUT_FILE" ]; then
    echo "SCP policies successfully saved to $OUTPUT_FILE"
else
    echo "ERROR: Output file $OUTPUT_FILE was not successfully created"
    exit 1
fi

echo "SCP Fetch Completed"