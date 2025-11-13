#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="src/tests/opa_test/scp"

# build bundle and run golden checks
main() {  # run validation pipeline
  opa fmt -w src
  opa check src
  opa test -v src/policies/aws/scp
  opa build -b src/policies -o policy_bundle.tar.gz
  run_golden
}

# compare eval outputs with folder-based expectations
run_golden() {  # walk inputs and compare expected final from folder name
  local fail=0
  shopt -s nullglob
  for exp in allow deny; do
    local dir="$BASE_DIR/$exp"
    [[ -d "$dir" ]] || continue
    for in_f in "$dir"/*.json; do
      local name=$(basename "$in_f")
      local got
      got=$(opa eval -b policy_bundle.tar.gz -i "$in_f" 'data.aws.scp.result.final' -f raw)
      if [[ "$got" != "$exp" ]]; then
        echo "[FAIL] $exp/$name expected=$exp got=$got"
        fail=1
      else
        echo "[OK]   $exp/$name -> $got"
      fi
    done
  done
  exit $fail
}

main "$@"
