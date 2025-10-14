# src/cli/list_iam_policies.py
from __future__ import annotations

import argparse
import sys

from src.services.IAM_fetcher import IAMPolicyFetcher, FetchError
from src.models.IAM import to_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="List IAM policies and emit structured JSON (minimal MVP for the issue)."
    )
    parser.add_argument("--profile", type=str, default=None, help="AWS profile name (e.g., dev)")
    parser.add_argument("--region", type=str, default=None, help="AWS region (IAM is global; optional)")
    parser.add_argument(
        "--scope",
        type=str,
        choices=["All", "AWS", "Local"],
        default="All",
        help='Policy scope: "All" (default), "AWS" (AWS managed), or "Local" (customer managed)',
    )
    parser.add_argument(
        "--only-attached",
        action="store_true",
        help="If set, return only policies that are attached to an IAM user, group, or role.",
    )
    parser.add_argument("--page-size", type=int, default=100, help="Paginator page size (default: 100)")
    parser.add_argument(
        "--max-items",
        type=int,
        default=None,
        help="Hard cap on total items to collect (useful for quick tests).",
    )
    parser.add_argument("--output", type=str, default=None, help="Write JSON to this file instead of stdout")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-JSON messages (errors still go to stderr).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Basic validation
    if args.page_size <= 0:
        print("Error: --page-size must be a positive integer.", file=sys.stderr)
        sys.exit(2)

    try:
        # instantiate the DI-friendly fetcher
        fetcher = IAMPolicyFetcher(profile=args.profile, region=args.region)

        inv = fetcher.collect_policies(
            scope=args.scope,
            only_attached=args.only_attached,
            page_size=args.page_size,
            max_items=args.max_items,
        )

        payload = to_json(inv, pretty=args.pretty)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(payload)
            if not args.quiet:
                print(f"Wrote {len(payload)} bytes to {args.output}", file=sys.stderr)
        else:
            print(payload)  # JSON to stdout

        sys.exit(0)

    except FetchError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        if not args.quiet:
            print("Aborted by user.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
