from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from wg_handshake_overlay.trust_registry import (
    SIGNATURE_ALGORITHM,
    SSHSIG_NAMESPACE,
    build_registry_payload,
    canonical_signed_bytes,
)


def wireguard_key(number: int) -> str:
    if not 1 <= number <= 255:
        raise ValueError("test key byte must be between 1 and 255")
    return base64.b64encode(bytes([number]) * 32).decode("ascii")


def node_keys(*node_ids: str) -> dict[str, str]:
    return {node_id: wireguard_key(index) for index, node_id in enumerate(node_ids, start=1)}


class EphemeralOpenSshSigner:
    """Generate a test-only root in a temporary directory and never persist it in the repository."""

    def __init__(self) -> None:
        executable = shutil.which("ssh-keygen")
        if executable is None:
            raise RuntimeError("ssh-keygen is required for trust-registry tests")
        self._executable = executable
        self._temporary = tempfile.TemporaryDirectory(prefix="wg-registry-sign-")
        self.directory = Path(self._temporary.name)
        self.private_key_path = self.directory / "root_ed25519"
        self._run(
            [
                self._executable,
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "ephemeral-test-only",
                "-f",
                str(self.private_key_path),
            ]
        )
        fields = self.private_key_path.with_suffix(".pub").read_text(encoding="ascii").split()
        self.public_key = f"{fields[0]} {fields[1]}"

    def close(self) -> None:
        self._temporary.cleanup()

    def document(
        self,
        *,
        registry_id: str,
        version: int,
        nodes: dict[str, str],
        key_id: str = "root-test-1",
    ) -> bytes:
        signed = build_registry_payload(registry_id=registry_id, version=version, nodes=nodes)
        token = uuid.uuid4().hex
        message_path = self.directory / f"registry-{token}.json"
        signature_path = Path(str(message_path) + ".sig")
        message_path.write_bytes(canonical_signed_bytes(signed))
        self._run(
            [
                self._executable,
                "-Y",
                "sign",
                "-f",
                str(self.private_key_path),
                "-n",
                SSHSIG_NAMESPACE,
                str(message_path),
            ]
        )
        signature = signature_path.read_text(encoding="ascii")
        message_path.unlink(missing_ok=True)
        signature_path.unlink(missing_ok=True)
        return (
            json.dumps(
                {
                    "signed": signed,
                    "signature": {
                        "algorithm": SIGNATURE_ALGORITHM,
                        "key_id": key_id,
                        "value": signature,
                    },
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )

    @staticmethod
    def parse(document: bytes) -> dict[str, object]:
        return json.loads(document.decode("utf-8"))

    @staticmethod
    def encode(document: dict[str, object]) -> bytes:
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"

    def _run(self, command: list[str]) -> None:
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
            creationflags=creation_flags,
        )
        if completed.returncode != 0:
            raise RuntimeError("ssh-keygen test helper failed")
