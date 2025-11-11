from src.services.SCP_fetcher import SCPFetcher
from src.Keywords import Keywords
import json
import argparse
import sys


# run pip install -e .
# then do your thing
def _save_to_json(data: dict, filename: str) -> bool:
    try:
        with open(filename, 'w') as f:
            # str default for datetime
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception as e:
        print(f"An error occured saving policy as json: {e}")
        return False


# NOTE: should we create a model for args?
def fetch_scp_policies(args):
    """
    fetch scp policies and save to json
    """
    try:
        fetcher = SCPFetcher()
        policies = fetcher.fetch_scp()

        output_file = args.output or 'service_control_policies.json'
        print(f"Successfuly fetched {len(policies)} SCP policies")
        _save_to_json(policies, output_file)
    except Exception as e:
        print(f"An error ocurred fetching policies: {e}")
        sys.exit(1)



def main():
    parser = argparse.ArgumentParser(
        prog='policysynth',
        description='Policy Synthesizer for AWS SCP, IAM Polcies, '
        '          and AWS Configs. Future functionality will include'
        '          ability to synthesize OPA policies based off retrieved'
        '          information'
    )

    # since we're having different functions, use subparsers for each one
    subparsers = parser.add_subparsers(
        dest='command',
        help='Available commands'
    )

    # TODO: Come up with a way to input configs?
    scp_parser = subparsers.add_parser(
        'fetch-scp',
        help='Fetch SCP policies for a given AWS account'
    )
    scp_parser.add_argument(
        '--filter',
        choices=[keyword.value for keyword in Keywords],
        default=Keywords.SERVICE_CONTROL_POLICY,  # this might be redundant
        help="Filter what SCPs you wish to retrieve"
    )
    scp_parser.add_argument(
        '--output',
        '-o',
        help='Output file name (default: service_control_policies.json)'
    )

    scp_parser.set_defaults(func=fetch_scp_policies)
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    # execute the passed function
    args.func(args)


if __name__ == '__main__':
    main()
