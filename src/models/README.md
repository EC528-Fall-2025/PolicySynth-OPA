# Models
## scp_validation.py
python -m src.models.scp_validation \
  --policy <POLICY_NAME> \
  --scp-dir <SCP_JSON_DIR> \
  --rego-dir <REGO_POLICY_DIR> \
  --rego-query <REGO_QUERY_PATH> \
  --rego-result-type <RESULT_TYPE> \
  [--fail-on-mismatch]

### Command-Line Arguments

| Argument             | Type   | Default                | Description                                                                                                                |
| -------------------- | ------ | ---------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `--policy`           | `str`  | *(required)*           | The policy name (without `.json` or `.rego` extension). Both files must share the same base name in the given directories. |
| `--scp-dir`          | `str`  | `src/policies/json`    | Path to the directory containing the SCP JSON files. Supports both native AWS `describe-policy` output and plain SCP JSON. |
| `--rego-dir`         | `str`  | `src/policies/aws/scp` | Path to the directory containing the translated Rego policy files.                                                         |
| `--opa-path`         | `str`  | `opa`                  | Path to the OPA executable. Change this if OPA is installed in a custom location.                                          |
| `--rego-query`       | `str`  | `data.aws.scp.deny`    | The OPA query to evaluate. For example: `data.aws.scp.allow` or `data.aws.scp.deny`.                                       |
| `--rego-result-type` | `str`  | `deny_set`             | How to interpret the Rego evaluation results. Supported values: `deny_set`, `allow_bool`, `deny_bool`. See table below.    |
| `--fail-on-mismatch` | *flag* | *(off)*                | If set, the process exits with non-zero status on syntax or behavior mismatch (useful for CI validation).                  |

### Rego Result Type Options

| Result Type  | Expected Query Output                  | Interpretation Logic                             | Use Case                                                                                      |
| ------------ | -------------------------------------- | ------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| `deny_set`   | A set, list, or dict of denial reasons | Non-empty → **Deny**, Empty → **Allow**          | Most common when using `data.aws.scp.deny` rules returning message sets.                      |
| `allow_bool` | Boolean (`true`/`false`)               | `true` → **Allow**, `false` or `null` → **Deny** | Use when Rego defines a simple boolean rule, e.g. `allow { input.action == "s3:GetObject" }`. |
| `deny_bool`  | Boolean (`true`/`false`)               | `true` → **Deny**, `false` or `null` → **Allow** | Alternative for rules such as `deny { ... }` returning a single boolean.                      |

#### Notice

The current version of the validation system only supports single-policy file validation.

When running with the --policy argument, the validator loads exactly one pair of files: 
+ <policy_name>.json (the SCP policy)
+ <policy_name>.rego (the corresponding translated Rego policy).

Other .json or .rego files in the same directory are ignored.

-------

### Examples

#### Boolean allow policy
python -m src.models.scp_validation \
  --policy example_scp_restrict_regions \
  --scp-dir src/tests/opa_test/scp/allow \
  --rego-dir src/tests/opa_test/scp/allow \
  --rego-query data.aws.scp.allow \
  --rego-result-type allow_bool

#### Boolean deny policy

python -m src.models.scp_validation \
  --policy deny_bool \
  --scp-dir src/tests/opa_test/scp/deny \
  --rego-dir src/tests/opa_test/scp/deny \
  --rego-query data.aws.scp.deny \  
  --rego-result-type deny_bool

#### Deny-set policy (messages returned as list)
python -m src.models.scp_validation \
  --policy example_scp_deny_s3_delete \
  --scp-dir src/tests/opa_test/scp/deny \
  --rego-dir src/tests/opa_test/scp/deny \
  --rego-query data.aws.scp.deny \
  --rego-result-type deny_set


### Wrong(Not match)
python -m src.models.scp_validation  \
 --policy example_scp_getobject_only   \
 --scp-dir src/tests/opa_test/scp/wrong   \
 --rego-dir src/tests/opa_test/scp/wrong   \
 --rego-query data.aws.scp.allow   \
 --rego-result-type allow_bool