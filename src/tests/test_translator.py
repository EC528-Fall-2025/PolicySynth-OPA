import json
import os
from src.services.translator import translate 


def test_translate(): 
    base_dir = os.path.dirname(os.path.dirname(__file__))  # goes up from tests → src
    json_path = os.path.join(base_dir, "tests", "mockscp.json")

    with open(json_path, "r") as f:
        scps = json.load(f)

    for scp in scps: 
        print(f"\n--- Translating {scp['Name']} ---")
        rego_policy = translate(scp)
        print(rego_policy)