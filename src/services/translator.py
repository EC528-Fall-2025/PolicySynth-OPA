import json 
import os
from pathlib import Path
from src.models.SCP import SCP

# every AWS policy has Effect, Action, Resource
# translates given SCP policy to 
def translate(scp_policy): 
    # types of conditions seen in SCPs template 
    cond_templates = {
            "StringNotEquals": 'input.{key} != "{val}"',
            "StringEqualsIfExists": '(not input.{key} or input.{key} == "{val}")',
            "StringNotEqualsIfExists": '(not input.{key} or input.{key} != "{val}")',
            "Bool": 'input.{key} == {val}',
            "BoolIfExists": '(not input.{key} or input.{key} == {val})'
        }
    
    policy_name = scp_policy.get("Name") # name of policy
    contents = scp_policy["PolicyDocument"]["Statement"] # contents of policy
    rego_rules = [] # define rego policy
    for stmt in contents: 
        effect = stmt["Effect"].lower()
        condition = stmt.get("Condition", {}) # returns empty if doesn't exist 
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])

        print("Actions: ", actions)
        print("Condition: ", condition)
        print("Resources: ", resources)

        if isinstance(actions, str):
            actions = [actions]  # wrap single action string in a list
        elif isinstance(resources, str): 
            resources = [resources]
        # convert condition to rego logic using template
        cond_str =""
        if condition: # if there are conditions 
            cond_type, cond_data = next(iter(condition.items())) if condition else (None, None) # loop through conditions, if no conditons set to None 
            template = cond_templates.get(cond_type)
            if template:
                cond_str = " and ".join(
                    template.format(key=k, val=str(v).lower() if isinstance(v, bool) else v)
                    for k, v in cond_data.items()
                )
        for action in actions:
            rule_name = f"{effect}_{action.replace(':', '_')}"
            rule = f"""
    {effect}[msg] {{
        input.action == "{action}"
        {cond_str}
        msg := "{policy_name} triggered for {action}"
    }}
"""
            rego_rules.append(rule.strip())
    
    rules_str = "\n\n".join(rego_rules)
    policy = f"""
    package aws.scp.{policy_name.replace('-','_')}
    default allow = false
    default deny = false
    {rules_str}
"""
    save_rego_files(policy_name, policy) # save generated rego policy in folder
    
    return policy 


def save_rego_files(policy_name, policy_str): 
    filename = policy_name.lower().replace(" ", "_") + ".rego"
    policy_dir = Path(__file__).parent.parent / "rego_policies"
    os.makedirs(policy_dir, exist_ok=True)
    filepath = policy_dir / filename
    with open(filepath, "w") as f:
        f.write(policy_str)
    print(f"Saved policy: {filepath}")