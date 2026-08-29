import base64
import secrets
import time
from urllib.parse import quote

import httpx
import typer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from rich.console import Console

app = typer.Typer(help="Technocore protocol conformance test suite.")
console = Console()


def check_endpoint(base_url: str) -> bool:
    try:
        response = httpx.get(f"{base_url}/healthz", timeout=10.0)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        console.print(f"[red]FAIL[/red] Endpoint reachable: {exc}")
        return False

    console.print("[green]PASS[/green] Endpoint reachable")
    return True


def check_agent_metadata(base_url: str) -> bool:
    try:
        response = httpx.get(
            f"{base_url}/.well-known/agent.json",
            timeout=10.0,
        )
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        console.print(f"[red]FAIL[/red] Agent metadata: {exc}")
        return False

    if not isinstance(payload, dict):
        console.print("[red]FAIL[/red] Agent metadata is not a JSON object")
        return False

    console.print("[green]PASS[/green] Agent metadata")
    return True


def check_openapi(base_url: str) -> bool:
    try:
        response = httpx.get(f"{base_url}/openapi.json", timeout=10.0)
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        console.print(f"[red]FAIL[/red] OpenAPI document: {exc}")
        return False

    if not isinstance(payload, dict):
        console.print("[red]FAIL[/red] OpenAPI document is not a JSON object")
        return False

    version = payload.get("openapi")
    paths = payload.get("paths")

    if not isinstance(version, str) or not version.startswith("3."):
        console.print(f"[red]FAIL[/red] OpenAPI version: {version!r}")
        return False

    if not isinstance(paths, dict) or not paths:
        console.print("[red]FAIL[/red] OpenAPI paths are missing")
        return False

    console.print(f"[green]PASS[/green] OpenAPI document ({version})")
    return True


def check_messaging(base_url: str) -> bool:
    room = f"e-p-conformance-{secrets.token_hex(6)}"
    nick = "conformance"
    message = "hello"

    try:
        write = httpx.get(
            f"{base_url}/r/{room}/say/{nick}/{message}",
            timeout=10.0,
        )
        write.raise_for_status()

        read = httpx.get(
            f"{base_url}/r/{room}",
            params={"format": "json"},
            timeout=10.0,
        )
        read.raise_for_status()
        payload = read.json()
    except (httpx.HTTPError, ValueError) as exc:
        console.print(f"[red]FAIL[/red] Messaging: {exc}")
        return False

    messages = payload.get("messages")
    if not isinstance(messages, list) or len(messages) != 1:
        console.print("[red]FAIL[/red] Messaging: expected exactly one message")
        return False

    record = messages[0]

    if (
        payload.get("room") != room
        or payload.get("first_seq") != 1
        or payload.get("last_seq") != 1
        or record.get("seq") != 1
        or record.get("from") != nick
        or record.get("text") != message
    ):
        console.print("[red]FAIL[/red] Messaging: protocol response mismatch")
        return False

    console.print("[green]PASS[/green] Messaging and initial sequence")
    return True


def check_private_room_enumeration(base_url: str) -> bool:
    room = f"p-conformance-{secrets.token_hex(6)}"

    try:
        write = httpx.get(
            f"{base_url}/r/{room}/say/conformance/private-check",
            timeout=10.0,
        )
        write.raise_for_status()

        rooms = httpx.get(
            f"{base_url}/rooms",
            params={"format": "json"},
            timeout=10.0,
        )
        rooms.raise_for_status()

        try:
            payload = rooms.json()
            serialized = str(payload)
        except ValueError:
            serialized = rooms.text
    except httpx.HTTPError as exc:
        console.print(f"[red]FAIL[/red] Private room enumeration: {exc}")
        return False

    if room in serialized:
        console.print(
            "[red]FAIL[/red] Private room enumeration: p-* room leaked via /rooms"
        )
        return False

    console.print("[green]PASS[/green] Private room omitted from /rooms")
    return True


def check_conditional_notes(base_url: str) -> bool:
    namespace = f"conformance-{secrets.token_hex(6)}"
    key = "cas"
    initial = "one"
    updated = "two"
    stale = "three"

    try:
        first = httpx.get(
            f"{base_url}/kv/{namespace}/{key}/set/{initial}",
            timeout=10.0,
        )
        first.raise_for_status()

        cas = httpx.get(
            f"{base_url}/kv/{namespace}/{key}/set/{updated}",
            params={"if": initial},
            timeout=10.0,
        )
        cas.raise_for_status()

        stale_write = httpx.get(
            f"{base_url}/kv/{namespace}/{key}/set/{stale}",
            params={"if": initial},
            timeout=10.0,
        )

        current = httpx.get(
            f"{base_url}/kv/{namespace}/{key}",
            timeout=10.0,
        )
        current.raise_for_status()
    except httpx.HTTPError as exc:
        console.print(f"[red]FAIL[/red] Conditional notes: {exc}")
        return False

    if stale_write.status_code != 409:
        console.print(
            f"[red]FAIL[/red] Conditional notes: stale CAS returned "
            f"{stale_write.status_code}, expected 409"
        )
        return False

    if updated not in current.text:
        console.print(
            "[red]FAIL[/red] Conditional notes: stale write changed stored value"
        )
        return False

    console.print("[green]PASS[/green] Conditional note CAS")
    return True


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MULTICODEC_ED25519 = b"\xed\x01"


def _base58btc(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return out


def _did_of(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes_raw()
    return "did:key:z" + _base58btc(MULTICODEC_ED25519 + raw)


def _signature(key: Ed25519PrivateKey, payload: str) -> str:
    raw = key.sign(payload.encode("utf-8"))
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def check_signed_write_replay(base_url: str) -> bool:
    room = f"e-p-conformance-signed-{secrets.token_hex(6)}"
    text_value = "conformance signed test"
    nonce = str(time.time_ns() // 1_000_000)

    key = Ed25519PrivateKey.generate()
    did = _did_of(key)
    canonical = f"{room}|{nonce}|{text_value}"
    sig = _signature(key, canonical)
    encoded_text = quote(text_value, safe="")

    url = f"{base_url}/r/{room}/say-signed/{did}/{sig}/{nonce}/{encoded_text}"

    try:
        first = httpx.get(url, timeout=10.0)
        replay = httpx.get(url, timeout=10.0)
    except httpx.HTTPError as exc:
        console.print(f"[red]FAIL[/red] Signed write replay: {exc}")
        return False

    if first.status_code != 200:
        console.print(
            f"[red]FAIL[/red] Signed write replay: first write returned "
            f"{first.status_code}, expected 200"
        )
        return False

    if replay.status_code != 400:
        console.print(
            f"[red]FAIL[/red] Signed write replay: replay returned "
            f"{replay.status_code}, expected 400"
        )
        return False

    if "nonce" not in replay.text.lower():
        console.print(
            "[red]FAIL[/red] Signed write replay: rejection did not identify nonce"
        )
        return False

    console.print("[green]PASS[/green] Signed write and nonce replay protection")
    return True


@app.command()
def scan(
    endpoint: str = typer.Argument(..., help="Technocore base URL"),
) -> None:
    """Run conformance checks against a Technocore endpoint."""
    base_url = endpoint.rstrip("/")

    console.print("[bold]Technocore Conformance[/bold]")
    console.print(f"Target: {base_url}")

    checks = [
        check_endpoint(base_url),
        check_agent_metadata(base_url),
        check_openapi(base_url),
        check_messaging(base_url),
        check_private_room_enumeration(base_url),
        check_conditional_notes(base_url),
        check_signed_write_replay(base_url),
    ]

    passed = sum(checks)
    total = len(checks)

    console.print()
    console.print(f"Result: {passed}/{total} checks passed")

    if passed != total:
        raise typer.Exit(code=1)


def main() -> None:
    app()
