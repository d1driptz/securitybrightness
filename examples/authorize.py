"""Submit a proposal and print its decision. Does not perform the action."""
import argparse
import json
import os
from dataclasses import asdict

from core.sdk import ApplicationClient, SDKError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action")
    parser.add_argument("target")
    parser.add_argument("--purpose", default="application integration example")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    try:
        client = ApplicationClient(os.environ["SECURITYBRIGHTNESS_APP_ID"],
                                   os.environ["SECURITYBRIGHTNESS_APP_CREDENTIAL"],
                                   port=args.port, timeout=args.timeout)
        result = client.check(args.action, args.target, details={"purpose": args.purpose})
    except KeyError:
        print("Set SECURITYBRIGHTNESS_APP_ID and SECURITYBRIGHTNESS_APP_CREDENTIAL.")
        return 3
    except (TypeError, ValueError) as exc:
        print(str(exc))
        return 3
    except SDKError as exc:
        print(json.dumps({"error": exc.code, "status": exc.status, "outcome_unknown": exc.outcome_unknown}))
        return 3
    print(json.dumps(asdict(result), indent=2))
    return 0 if result.allowed else 2


if __name__ == "__main__":
    raise SystemExit(main())
