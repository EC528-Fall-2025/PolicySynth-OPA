from services.IAM_fetcher import IAMFetcher
from services.SCP_fetcher import SCPFetcher
import json
import argparse
import sys

# run pip install -e . 
# then do your thing

def save_to_json(data: dict, filename: str) -> bool:
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"An error occured: {e}")
        return False


# NOTE: should we create a model for args
def fetch_iam_policies(args) -> bool:
    """
    fetch iam policies and save to json
    """
    try:
        fetcher = IAMFetcher()
        policies = fetcher.fetch_iam_policies(
            scope=args.scope,
            only_Attached=args.only_Attached
        )

        output_file = args.filename or 'iam_policies.json'
        save_to_json(policies, output_file)
        return 1
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog='policysynth',
        description='Policy synthesizer for aws'
    )

    # since we're having different functions, use subparsers for each one
    subparsers = parser.add_subparsers(
        dest='command',
        help='Available commands'
    )

    iam_parser = subparsers.add_parser(
        'fetch-iam',
        help='Fetch IAM policies for a given AWS account'
    )
    iam_parser.add_argument(
        '--scope',
        choices=['All', 'AWS', 'Local'],
        default='Local',
        help='Policy scope (default: Local)'
    )
    iam_parser.add_argument(
        '--only-attached',
        action='store_true',
        help='Only fetch attached policies'
    )
    iam_parser.add_argument(
        '--output',
        '-o',
        help='Output file name (default: iam_policies.json)'
    )
    iam_parser.set_defaults(func=fetch_iam_policies)

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    # execute the passed function
    args.func(args)

if __name__ == '__main__':
    main()