#!/usr/bin/env python3
"""HTTP client using tng.Transport for OHTTP encryption with ITA attestation.

This replaces the TNG ingress container — the Python process handles
encryption and attestation verification in-process via the tng package.
"""

import argparse
import sys
from time import sleep

import httpx
import tng


def main():
    p = argparse.ArgumentParser(description="TNG Python transport HTTP client")
    p.add_argument("--host", default="localhost", help="TNG egress host (default: localhost)")
    p.add_argument("--port", type=int, default=8011, help="TNG egress port (default: 8011)")
    p.add_argument("--no-verify", action="store_true", help="Skip attestation verification (testing only)")
    p.add_argument("--requests", type=int, default=3, help="Number of requests to send (default: 3)")
    p.add_argument("--policy-ids", nargs="*", default=["dcdc61ae-059c-4f38-841c-cc8ac91c497c"],
                   help="ITA policy IDs for verification")
    args = p.parse_args()

    if args.no_verify:
        transport = tng.Transport(verify=None)
    else:
        transport = tng.Transport(verify={
            "model": "passport",
            "as_provider": "ita",
            "policy_ids": args.policy_ids,
        })

    target = f"http://{args.host}:{args.port}"
    print(f"Using TNG Python transport)")
    print(f"Target egress: {target}")
    print(f"Attestation: {'disabled' if args.no_verify else 'ITA passport'}")
    print()

    failed_count = 0
    with httpx.Client(transport=transport) as client:
        for i in range(args.requests):
            url = f"{target}/"
            print(f"[{i+1}/{args.requests}] GET {url}")
            try:
                resp = client.get(url, timeout=10)
                print(f"  Status: {resp.status_code}")
                print(f"  Body: {resp.text.strip()}")
                if transport.attestation_token:
                    print(f"  Attestation token: {transport.attestation_token[:80]}...")
                else:
                    print(f"  Attestation token: None")
            except Exception as e:
                print(f"  Error: {e}")
                failed_count += 1
            # sleep(0.5)

    transport.close()

    print()
    print(f"Results: {args.requests - failed_count}/{args.requests} succeeded, {failed_count} failed")
    sys.exit(1 if failed_count > 0 else 0)


if __name__ == "__main__":
    main()
