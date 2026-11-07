import argparse
import json
from .core import (
    resolve_secret_intent,
    scan_and_redact_trajectory,
    inject_secret_to_provider,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Zero-Exposure Conversational Secret Gateway (Railway & Cloud Secret Injector)"
    )
    subparsers = parser.add_subparsers(dest="subcommand")

    # resolve
    res_p = subparsers.add_parser(
        "resolve",
        help="Resolve natural language app/tool description to canonical environment variable keys",
    )
    res_p.add_argument("--describe", "-d", required=True, help="Natural language description of what needs the secret")
    res_p.add_argument("--project", "-p", help="Target Railway/cloud project name")
    res_p.add_argument("--service", "-s", help="Target service name")

    # inject
    inj_p = subparsers.add_parser(
        "inject",
        help="Conversational prompt + hidden terminal input (getpass) to inject secret into Railway",
    )
    inj_p.add_argument("--project", "-p", help="Target Railway project name")
    inj_p.add_argument("--service", "-s", help="Target Railway service name")
    inj_p.add_argument("--environment", "-e", help="Target Railway environment")
    inj_p.add_argument("--describe", "-d", default="", help="Explain what the app/tool needs")
    inj_p.add_argument("--key", "-k", help="Explicit environment variable key (optional if --describe is used)")
    inj_p.add_argument("--provider", choices=["railway", "vercel"], default="railway")
    inj_p.add_argument("--dry-run", action="store_true", help="Preview masked command without running subprocess")

    # scan
    scan_p = subparsers.add_parser(
        "scan",
        help="Scan and redact accidental API keys from chat trajectories",
    )
    scan_p.add_argument("--text", "-t", required=True, help="Text or prompt to scan for leaked secrets")

    args = parser.parse_args()

    if args.subcommand == "resolve":
        out = resolve_secret_intent(
            description=args.describe,
            project=args.project,
            service=args.service,
        )
        print(json.dumps(out, indent=2))

    elif args.subcommand == "inject":
        intent = resolve_secret_intent(
            description=args.describe or "Custom environment secret",
            explicit_key=args.key,
            project=args.project,
            service=args.service,
        )
        target_key = intent["recommended_key"]
        print(f"[*] Target Project : {intent['project']}")
        if intent.get("service"):
            print(f"[*] Target Service : {intent['service']}")
        print(f"[*] Resolved Key   : {target_key}")
        res = inject_secret_to_provider(
            key=target_key,
            project=intent["project"],
            service=intent.get("service"),
            environment=args.environment,
            provider=args.provider,
            dry_run=args.dry_run,
        )
        print(json.dumps(res, indent=2))

    elif args.subcommand == "scan":
        out = scan_and_redact_trajectory(args.text)
        print(json.dumps(out, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
