from __future__ import annotations

import argparse

from .parser import parse_packet
from .scenarios import format_results, run_scenarios


def _packet(kind: int, size: int, index: int = 1) -> bytes:
    packet = bytearray(size)
    packet[0] = kind
    packet[4:8] = index.to_bytes(4, "little")
    if kind == 2:
        packet[8:12] = (index + 1).to_bytes(4, "little")
    return bytes(packet)


def main() -> int:
    parser = argparse.ArgumentParser(description="Nonprivileged WG handshake overlay reference")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("validate", help="validate framing and the 27-case model contract")
    simulate = subcommands.add_parser("simulate", help="emit in-memory contract evidence")
    simulate.add_argument("--format", choices=("json", "csv"), default="json")
    args = parser.parse_args()

    if args.command == "validate":
        for kind, size in ((1, 148), (2, 92), (3, 64), (4, 32)):
            parse_packet(_packet(kind, size, kind))
        rows = run_scenarios()
        if len(rows) != 27 or not all(row["model_ok"] for row in rows):
            print("INVALID: local model contract failed")
            return 1
        print("VALID: 27/27 model cases; WG 1/2/3 overlay, WG 4 direct bypass")
        return 0

    print(format_results(args.format), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
