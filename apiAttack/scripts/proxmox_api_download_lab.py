#!/usr/bin/env python3
"""Offline CVE-2024-21545 comparison harness.

The script models only the vulnerable Proxmox API behavior needed for this
demo: trusting a guest-agent response that contains a "download" object.
It reads from a fake host filesystem under .lab/hostfs, never from /.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


FAKE_FILES = {
    "/etc/cve-2024-21545-proof.txt": "apiattack-vulnerable-node\n",
    "/etc/hostname": "apiattack-proxmox-node\n",
    "/etc/shadow": "root:$y$j9T$fake-lab-hash:19723:0:99999:7:::\n",
    "/etc/pve/priv/authkey.key": "FAKE-PVE-AUTHKEY-FOR-CVE-2024-21545-LAB\n",
}


@dataclass
class ApiResult:
    kind: str
    detail: str
    body: str = ""
    path: str = ""

    @property
    def downloaded(self) -> bool:
        return self.kind == "download"


def reset_hostfs(host_root: Path) -> None:
    if host_root.exists():
        shutil.rmtree(host_root)

    for guest_path, content in FAKE_FILES.items():
        target = host_root / guest_path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def resolve_fake_host_path(host_root: Path, requested_path: str) -> Path:
    if not requested_path.startswith("/"):
        raise ValueError(f"download path is not absolute: {requested_path}")

    pure_path = PurePosixPath(requested_path)
    if ".." in pure_path.parts:
        raise ValueError(f"download path contains '..': {requested_path}")

    candidate = (host_root / requested_path.lstrip("/")).resolve()
    root = host_root.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"download path escapes fake host root: {requested_path}") from exc

    return candidate


def qga_unmodified_error(command: str) -> dict[str, Any]:
    return {
        "error": {
            "class": "GenericError",
            "desc": (
                "Failed to execute child process "
                f"\u201c{command}\u201d: No such file or directory"
            ),
        }
    }


def qga_patched_response(command: str) -> dict[str, Any]:
    trigger = "NOTFOUND"
    if command.startswith(trigger) and len(command) > len(trigger):
        requested_path = command[len(trigger) :]
        if requested_path.startswith("/"):
            return {
                "return": {
                    "download": {
                        "path": requested_path,
                        "content-type": "text/plain",
                    }
                }
            }

    return qga_unmodified_error(command)


def vulnerable_proxmox_handler(
    qga_response: dict[str, Any], host_root: Path
) -> ApiResult:
    if "error" in qga_response:
        return ApiResult(
            kind="json",
            detail="guest-agent error returned as JSON; no host file read",
            body=json.dumps(qga_response, sort_keys=True),
        )

    data = qga_response.get("return")
    if isinstance(data, dict) and isinstance(data.get("download"), dict):
        download = data["download"]
        requested_path = str(download.get("path", ""))
        try:
            host_path = resolve_fake_host_path(host_root, requested_path)
            body = host_path.read_text(encoding="utf-8")
        except (OSError, ValueError) as exc:
            return ApiResult(kind="error", detail=str(exc), path=requested_path)

        return ApiResult(
            kind="download",
            detail="vulnerable handler trusted guest-agent download object",
            body=body,
            path=requested_path,
        )

    return ApiResult(
        kind="json",
        detail="normal guest-agent return value",
        body=json.dumps({"data": data}, sort_keys=True),
    )


def fixed_proxmox_handler(qga_response: dict[str, Any], host_root: Path) -> ApiResult:
    del host_root
    data = qga_response.get("return")
    if isinstance(data, dict) and isinstance(data.get("download"), dict):
        requested_path = str(data["download"].get("path", ""))
        return ApiResult(
            kind="blocked",
            detail="fixed handler rejects untrusted guest-agent download object",
            path=requested_path,
        )

    if "error" in qga_response:
        return ApiResult(
            kind="json",
            detail="guest-agent error returned as JSON; no host file read",
            body=json.dumps(qga_response, sort_keys=True),
        )

    return ApiResult(
        kind="json",
        detail="normal guest-agent return value",
        body=json.dumps({"data": data}, sort_keys=True),
    )


def print_case(title: str, result: ApiResult) -> None:
    print()
    print(f"== {title} ==")
    print(f"download:  {'yes' if result.downloaded else 'no'}")
    print(f"result:    {result.detail}")
    if result.path:
        print(f"path:      {result.path}")
    if result.body:
        first_line = result.body.splitlines()[0] if result.body.splitlines() else ""
        print(f"body:      {first_line}")


def compare(args: argparse.Namespace) -> int:
    host_root = args.lab_dir / "hostfs"
    reset_hostfs(host_root)

    command = f"NOTFOUND{args.path}"
    baseline = vulnerable_proxmox_handler(qga_unmodified_error(command), host_root)
    exploited = vulnerable_proxmox_handler(qga_patched_response(command), host_root)
    fixed = fixed_proxmox_handler(qga_patched_response(command), host_root)

    print(f"Fake host root: {host_root}")
    print(f"Guest command:  {command}")
    print_case("Baseline: unmodified guest agent against vulnerable API", baseline)
    print_case("Patched guest agent against vulnerable API", exploited)
    print_case("Patched guest agent against fixed API", fixed)

    failures = []
    if baseline.downloaded:
        failures.append("baseline unexpectedly downloaded a host file")
    if not exploited.downloaded:
        failures.append("patched agent did not trigger the vulnerable download path")
    if fixed.downloaded or fixed.kind != "blocked":
        failures.append("fixed handler did not reject the guest-agent download object")

    if failures:
        print()
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1

    print()
    print(
        "PASS: baseline has no host read, vulnerable API plus patched agent "
        "downloads from the fake host, and the fixed API blocks it."
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--lab-dir",
        type=Path,
        required=True,
        help="Local lab state directory.",
    )
    parser.add_argument(
        "--path",
        default="/etc/hostname",
        help="Absolute fake host path to request through the download object.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return compare(args)


if __name__ == "__main__":
    raise SystemExit(main())
