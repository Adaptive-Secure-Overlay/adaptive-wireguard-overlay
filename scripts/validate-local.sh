#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
export PYTHONPATH="$project_root/src${PYTHONPATH:+:$PYTHONPATH}"

# Local files, Python stdlib and the installed OpenSSH signature verifier only.
# No sockets, WG, firewall, SSH connection or EVE-NG.
command -v ssh-keygen >/dev/null
python3 -m json.tool config/wg-overlay.example.json >/dev/null
python3 -m json.tool schemas/eve-result.schema.json >/dev/null
python3 -m json.tool schemas/trust-registry.schema.json >/dev/null
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m wg_handshake_overlay validate
python3 -m wg_handshake_overlay simulate --format json >/dev/null
