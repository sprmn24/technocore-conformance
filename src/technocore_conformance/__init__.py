import base64
import secrets
import threading
import time
from urllib.parse import quote

import httpx
import typer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from rich.console import Console

app = typer.Typer(help="Technocore protocol conformance test suite.")
console = Console()


SHARED_TEST_ROOM = "p-conformance-suite"


def _request_with_rate_limit(
    method: str,
    url: str,
    *,
    timeout: float = 10.0,
    max_retries: int = 3,
    **kwargs,
):
    request = httpx.get if method == "GET" else httpx.post

    for attempt in range(max_retries + 1):
        response = request(url, timeout=timeout, **kwargs)

        if getattr(response, "status_code", None) != 429:
            return response

        if response.text.startswith("429 room-creation budget spent:"):
            return response

        if attempt == max_retries:
            return response

        retry_after = response.headers.get("Retry-After")
        try:
            wait = max(1, int(retry_after))
        except (TypeError, ValueError):
            wait = 1

        if wait > 10:
            return response

        console.print(f"[yellow]RATE LIMIT[/yellow] waiting {wait}s before retry")
        time.sleep(wait)

    raise RuntimeError("unreachable")


def check_endpoint(base_url: str) -> bool:
    try:
        response = _request_with_rate_limit("GET", f"{base_url}/healthz", timeout=10.0)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        console.print(f"[red]FAIL[/red] Endpoint reachable: {exc}")
        return False

    console.print("[green]PASS[/green] Endpoint reachable")
    return True


def check_agent_metadata(base_url: str) -> bool:
    try:
        response = _request_with_rate_limit(
            "GET",
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
        response = _request_with_rate_limit(
            "GET", f"{base_url}/openapi.json", timeout=10.0
        )
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

    required_paths = {
        "/r/{room}",
        "/r/{room}/say/{nick}/{text}",
        "/r/{room}/say-signed/{did}/{sig}/{nonce}/{text}",
        "/kv/{ns}/{key}",
        "/kv/{ns}/{key}/set/{value}",
        "/kv/{ns}",
        "/rooms",
    }

    missing = sorted(required_paths - set(paths))
    if missing:
        console.print(f"[red]FAIL[/red] OpenAPI required paths missing: {missing!r}")
        return False

    console.print(f"[green]PASS[/green] OpenAPI document ({version})")
    return True


def check_messaging(base_url: str) -> bool | None:
    global SHARED_TEST_ROOM

    room = f"e-p-conformance-{secrets.token_hex(6)}"
    nick = "conformance"
    message = "hello"

    try:
        write = _request_with_rate_limit(
            "GET",
            f"{base_url}/r/{room}/say/{nick}/{message}",
            timeout=10.0,
        )

        if getattr(write, "status_code", None) == 429 and write.text.startswith(
            "429 room-creation budget spent:"
        ):
            SHARED_TEST_ROOM = ""
            console.print(
                "[yellow]SKIP[/yellow] Messaging initial sequence: "
                "room-creation budget exhausted"
            )
            return None

        write.raise_for_status()

        read = _request_with_rate_limit(
            "GET",
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

    SHARED_TEST_ROOM = room
    console.print("[green]PASS[/green] Messaging and initial sequence")
    return True


def check_since_semantics(base_url: str) -> bool | None:
    room = SHARED_TEST_ROOM
    if not room:
        console.print(
            "[yellow]SKIP[/yellow] since semantics: no reusable room available"
        )
        return None
    marker = secrets.token_hex(4)
    values = [f"{marker}-one", f"{marker}-two", f"{marker}-three"]

    try:
        baseline_read = _request_with_rate_limit(
            "GET",
            f"{base_url}/r/{room}",
            params={"format": "json"},
            timeout=10.0,
        )
        baseline_read.raise_for_status()
        baseline = int(baseline_read.json().get("last_seq") or 0)

        for message in values:
            write = _request_with_rate_limit(
                "GET",
                f"{base_url}/r/{room}/say/conformance/{message}",
                timeout=10.0,
            )
            write.raise_for_status()

        read = _request_with_rate_limit(
            "GET",
            f"{base_url}/r/{room}",
            params={"since": baseline, "format": "json"},
            timeout=10.0,
        )
        read.raise_for_status()
        payload = read.json()
    except (httpx.HTTPError, TypeError, ValueError) as exc:
        console.print(f"[red]FAIL[/red] since semantics: {exc}")
        return False

    messages = payload.get("messages")
    if not isinstance(messages, list):
        console.print("[red]FAIL[/red] since semantics: messages is not a list")
        return False

    observed = [(record.get("seq"), record.get("text")) for record in messages]
    expected = [
        (baseline + 1, values[0]),
        (baseline + 2, values[1]),
        (baseline + 3, values[2]),
    ]

    if observed != expected:
        console.print(
            f"[red]FAIL[/red] since semantics: got {observed!r}, expected {expected!r}"
        )
        return False

    console.print("[green]PASS[/green] since returns only newer messages")
    return True


def check_limit_semantics(base_url: str) -> bool | None:
    room = SHARED_TEST_ROOM
    if not room:
        console.print(
            "[yellow]SKIP[/yellow] limit semantics: no reusable room available"
        )
        return None
    marker = secrets.token_hex(4)
    values = [f"{marker}-one", f"{marker}-two", f"{marker}-three"]

    try:
        baseline_read = _request_with_rate_limit(
            "GET",
            f"{base_url}/r/{room}",
            params={"format": "json"},
            timeout=10.0,
        )
        baseline_read.raise_for_status()
        baseline = int(baseline_read.json().get("last_seq") or 0)

        for message in values:
            write = _request_with_rate_limit(
                "GET",
                f"{base_url}/r/{room}/say/conformance/{message}",
                timeout=10.0,
            )
            write.raise_for_status()

        read = _request_with_rate_limit(
            "GET",
            f"{base_url}/r/{room}",
            params={"limit": 2, "format": "json"},
            timeout=10.0,
        )
        read.raise_for_status()
        payload = read.json()
    except (httpx.HTTPError, TypeError, ValueError) as exc:
        console.print(f"[red]FAIL[/red] limit semantics: {exc}")
        return False

    messages = payload.get("messages")
    if not isinstance(messages, list):
        console.print("[red]FAIL[/red] limit semantics: messages is not a list")
        return False

    observed = [(record.get("seq"), record.get("text")) for record in messages]
    expected = [
        (baseline + 2, values[1]),
        (baseline + 3, values[2]),
    ]

    if observed != expected:
        console.print(
            f"[red]FAIL[/red] limit semantics: got {observed!r}, expected {expected!r}"
        )
        return False

    console.print("[green]PASS[/green] limit returns newest bounded messages")
    return True


def check_wait_semantics(base_url: str) -> bool | None:
    room = SHARED_TEST_ROOM
    if not room:
        console.print(
            "[yellow]SKIP[/yellow] wait semantics: no reusable room available"
        )
        return None
    marker = secrets.token_hex(4)
    first_text = f"{marker}-one"
    second_text = f"{marker}-two"
    writer_errors = []

    try:
        baseline_read = _request_with_rate_limit(
            "GET",
            f"{base_url}/r/{room}",
            params={"format": "json"},
            timeout=10.0,
        )
        baseline_read.raise_for_status()
        baseline = int(baseline_read.json().get("last_seq") or 0)

        first = _request_with_rate_limit(
            "GET",
            f"{base_url}/r/{room}/say/conformance/{first_text}",
            timeout=10.0,
        )
        first.raise_for_status()
        first_seq = baseline + 1

        def delayed_write() -> None:
            time.sleep(0.2)
            try:
                write = _request_with_rate_limit(
                    "GET",
                    f"{base_url}/r/{room}/say/conformance/{second_text}",
                    timeout=10.0,
                )
                write.raise_for_status()
            except httpx.HTTPError as exc:
                writer_errors.append(exc)

        worker = threading.Thread(target=delayed_write, daemon=True)
        worker.start()

        try:
            read = _request_with_rate_limit(
                "GET",
                f"{base_url}/r/{room}",
                params={"since": first_seq, "wait": 2, "format": "json"},
                timeout=5.0,
            )
            read.raise_for_status()
            payload = read.json()
        finally:
            worker.join(timeout=3.0)
    except (httpx.HTTPError, TypeError, ValueError) as exc:
        console.print(f"[red]FAIL[/red] wait semantics: {exc}")
        return False

    if worker.is_alive():
        console.print("[red]FAIL[/red] wait semantics: delayed writer did not finish")
        return False

    if writer_errors:
        console.print(
            f"[red]FAIL[/red] wait semantics: delayed write failed: {writer_errors[0]}"
        )
        return False

    messages = payload.get("messages")
    if not isinstance(messages, list):
        console.print("[red]FAIL[/red] wait semantics: messages is not a list")
        return False

    observed = [(record.get("seq"), record.get("text")) for record in messages]
    expected = [(first_seq + 1, second_text)]

    if observed != expected:
        console.print(
            f"[red]FAIL[/red] wait semantics: got {observed!r}, expected {expected!r}"
        )
        return False

    console.print("[green]PASS[/green] wait releases when a new message arrives")
    return True


def check_post_messaging(base_url: str) -> bool | None:
    room = SHARED_TEST_ROOM
    if not room:
        console.print(
            "[yellow]SKIP[/yellow] POST messaging: no reusable room available"
        )
        return None
    nick = "conformance"
    message = f"hello-post-{secrets.token_hex(4)}"

    try:
        write = _request_with_rate_limit(
            "POST",
            f"{base_url}/r/{room}",
            json={"from": nick, "text": message},
            timeout=10.0,
        )
        write.raise_for_status()

        read = _request_with_rate_limit(
            "GET",
            f"{base_url}/r/{room}",
            params={"format": "json"},
            timeout=10.0,
        )
        read.raise_for_status()
        payload = read.json()
    except (httpx.HTTPError, ValueError) as exc:
        console.print(f"[red]FAIL[/red] POST messaging: {exc}")
        return False

    messages = payload.get("messages")
    if not isinstance(messages, list):
        console.print("[red]FAIL[/red] POST messaging: messages is not a list")
        return False

    matching = [
        record
        for record in messages
        if record.get("from") == nick and record.get("text") == message
    ]
    if len(matching) != 1:
        console.print(
            "[red]FAIL[/red] POST messaging: posted message not found exactly once"
        )
        return False

    console.print("[green]PASS[/green] POST messaging")
    return True


def check_single_line_sanitization(base_url: str) -> bool | None:
    room = SHARED_TEST_ROOM
    if not room:
        console.print(
            "[yellow]SKIP[/yellow] Single-line sanitization: no reusable room available"
        )
        return None
    marker = secrets.token_hex(4)
    raw = f"alpha-{marker}\nbeta\u200bgamma"
    expected = f"alpha-{marker} beta gamma"

    try:
        write = _request_with_rate_limit(
            "POST",
            f"{base_url}/r/{room}",
            json={"from": "conformance", "text": raw},
            timeout=10.0,
        )
        write.raise_for_status()

        read = _request_with_rate_limit(
            "GET",
            f"{base_url}/r/{room}",
            params={"format": "json"},
            timeout=10.0,
        )
        read.raise_for_status()
        payload = read.json()
    except (httpx.HTTPError, ValueError) as exc:
        console.print(f"[red]FAIL[/red] Single-line sanitization: {exc}")
        return False

    messages = payload.get("messages")
    if not isinstance(messages, list):
        console.print(
            "[red]FAIL[/red] Single-line sanitization: messages is not a list"
        )
        return False

    matching = [record for record in messages if record.get("text") == expected]
    if len(matching) != 1:
        console.print(
            f"[red]FAIL[/red] Single-line sanitization: "
            f"expected sanitized message {expected!r} exactly once"
        )
        return False

    console.print("[green]PASS[/green] Single-line sanitization")
    return True


def check_private_room_enumeration(base_url: str) -> bool | None:
    room = SHARED_TEST_ROOM
    if not room:
        console.print(
            "[yellow]SKIP[/yellow] Private room enumeration: "
            "no reusable private room available"
        )
        return None

    try:
        rooms = _request_with_rate_limit(
            "GET",
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


def check_events_room_protection(base_url: str) -> bool:
    try:
        response = _request_with_rate_limit(
            "GET",
            f"{base_url}/r/events/say/conformance/forbidden",
            timeout=10.0,
        )
    except httpx.HTTPError as exc:
        console.print(f"[red]FAIL[/red] Events room protection: {exc}")
        return False

    if response.status_code != 403:
        console.print(
            f"[red]FAIL[/red] Events room protection: got "
            f"{response.status_code}, expected 403"
        )
        return False

    console.print("[green]PASS[/green] Events room rejects user writes")
    return True


def check_private_note_enumeration(base_url: str) -> bool:
    namespace = f"conformance-{secrets.token_hex(6)}"
    private_key = f"p-secret-{secrets.token_hex(4)}"
    public_key = f"public-{secrets.token_hex(4)}"

    try:
        private_write = _request_with_rate_limit(
            "GET",
            f"{base_url}/kv/{namespace}/{private_key}/set/private-value",
            timeout=10.0,
        )
        private_write.raise_for_status()

        public_write = _request_with_rate_limit(
            "GET",
            f"{base_url}/kv/{namespace}/{public_key}/set/public-value",
            timeout=10.0,
        )
        public_write.raise_for_status()

        listing = _request_with_rate_limit(
            "GET",
            f"{base_url}/kv/{namespace}",
            timeout=10.0,
        )
        listing.raise_for_status()
    except httpx.HTTPError as exc:
        console.print(f"[red]FAIL[/red] Private note enumeration: {exc}")
        return False

    body = listing.text

    if private_key in body:
        console.print("[red]FAIL[/red] Private note enumeration: private key leaked")
        return False

    if public_key not in body:
        console.print("[red]FAIL[/red] Private note enumeration: public key missing")
        return False

    console.print("[green]PASS[/green] Private notes omitted from enumeration")
    return True


def check_post_notes(base_url: str) -> bool:
    namespace = f"conformance-{secrets.token_hex(6)}"
    key = "post-note"
    value = "hello-post-note"

    try:
        write = _request_with_rate_limit(
            "POST",
            f"{base_url}/kv/{namespace}/{key}",
            json={"value": value},
            timeout=10.0,
        )
        write.raise_for_status()

        read = _request_with_rate_limit(
            "GET",
            f"{base_url}/kv/{namespace}/{key}",
            timeout=10.0,
        )
        read.raise_for_status()
    except httpx.HTTPError as exc:
        console.print(f"[red]FAIL[/red] POST notes: {exc}")
        return False

    observed = read.text.rstrip("\n").split("\n")[-1]
    if observed != value:
        console.print(
            f"[red]FAIL[/red] POST notes: got {observed!r}, expected {value!r}"
        )
        return False

    console.print("[green]PASS[/green] POST notes")
    return True


def check_conditional_notes(base_url: str) -> bool:
    namespace = f"conformance-{secrets.token_hex(6)}"
    key = "cas"
    initial = "one"
    updated = "two"
    stale = "three"

    try:
        first = _request_with_rate_limit(
            "GET",
            f"{base_url}/kv/{namespace}/{key}/set/{initial}",
            timeout=10.0,
        )
        first.raise_for_status()

        cas = _request_with_rate_limit(
            "GET",
            f"{base_url}/kv/{namespace}/{key}/set/{updated}",
            params={"if": initial},
            timeout=10.0,
        )
        cas.raise_for_status()

        stale_write = _request_with_rate_limit(
            "GET",
            f"{base_url}/kv/{namespace}/{key}/set/{stale}",
            params={"if": initial},
            timeout=10.0,
        )

        current = _request_with_rate_limit(
            "GET",
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


def check_signed_post_write(base_url: str) -> bool | None:
    room = SHARED_TEST_ROOM
    if not room:
        console.print(
            "[yellow]SKIP[/yellow] Signed POST write: no reusable room available"
        )
        return None
    text_value = f"signed-post-{secrets.token_hex(4)}"
    nonce = str(time.time_ns() // 1_000_000)

    key = Ed25519PrivateKey.generate()
    did = _did_of(key)
    canonical = f"{room}|{nonce}|{text_value}"
    sig = _signature(key, canonical)

    try:
        write = _request_with_rate_limit(
            "POST",
            f"{base_url}/r/{room}",
            json={
                "did": did,
                "sig": sig,
                "nonce": nonce,
                "text": text_value,
            },
            timeout=10.0,
        )
        write.raise_for_status()

        read = _request_with_rate_limit(
            "GET",
            f"{base_url}/r/{room}",
            params={"format": "json"},
            timeout=10.0,
        )
        read.raise_for_status()
        payload = read.json()
    except (httpx.HTTPError, ValueError) as exc:
        console.print(f"[red]FAIL[/red] Signed POST write: {exc}")
        return False

    messages = payload.get("messages")
    if not isinstance(messages, list):
        console.print("[red]FAIL[/red] Signed POST write: messages is not a list")
        return False

    matching = [
        record
        for record in messages
        if record.get("from") == did
        and str(record.get("nonce")) == nonce
        and record.get("text") == text_value
    ]
    if len(matching) != 1:
        console.print(
            "[red]FAIL[/red] Signed POST write: signed record not found exactly once"
        )
        return False

    console.print("[green]PASS[/green] Signed POST write")
    return True


def check_if_absent_notes(base_url: str) -> bool:
    namespace = f"conformance-{secrets.token_hex(6)}"
    key = "if-absent"
    initial = "one"
    replacement = "two"

    try:
        first = _request_with_rate_limit(
            "GET",
            f"{base_url}/kv/{namespace}/{key}/set/{initial}",
            params={"if_absent": 1},
            timeout=10.0,
        )

        second = _request_with_rate_limit(
            "GET",
            f"{base_url}/kv/{namespace}/{key}/set/{replacement}",
            params={"if_absent": 1},
            timeout=10.0,
        )

        current = _request_with_rate_limit(
            "GET",
            f"{base_url}/kv/{namespace}/{key}",
            timeout=10.0,
        )
        current.raise_for_status()
    except httpx.HTTPError as exc:
        console.print(f"[red]FAIL[/red] if_absent notes: {exc}")
        return False

    if first.status_code != 200:
        console.print(
            f"[red]FAIL[/red] if_absent notes: initial write returned "
            f"{first.status_code}, expected 200"
        )
        return False

    if second.status_code != 409:
        console.print(
            f"[red]FAIL[/red] if_absent notes: duplicate write returned "
            f"{second.status_code}, expected 409"
        )
        return False

    conflict_value = second.text.rstrip("\n").split("\n")[-1]
    if conflict_value != initial:
        console.print(
            "[red]FAIL[/red] if_absent notes: 409 body did not carry current value"
        )
        return False

    current_value = current.text.rstrip("\n").split("\n")[-1]
    if current_value != initial:
        console.print(
            "[red]FAIL[/red] if_absent notes: duplicate write changed stored value"
        )
        return False

    console.print("[green]PASS[/green] Conditional note if_absent")
    return True


def check_signed_nonce_ordering(base_url: str) -> bool | None:
    room = SHARED_TEST_ROOM
    if not room:
        console.print(
            "[yellow]SKIP[/yellow] Signed nonce ordering: no reusable room available"
        )
        return None
    key = Ed25519PrivateKey.generate()
    did = _did_of(key)

    first_nonce = str(time.time_ns() // 1_000_000)
    lower_nonce = str(int(first_nonce) - 1)
    higher_nonce = str(int(first_nonce) + 1)

    first_text = "nonce-first"
    lower_text = "nonce-lower"
    higher_text = "nonce-higher"

    def signed_url(nonce: str, text_value: str) -> str:
        canonical = f"{room}|{nonce}|{text_value}"
        sig = _signature(key, canonical)
        encoded_text = quote(text_value, safe="")
        return f"{base_url}/r/{room}/say-signed/{did}/{sig}/{nonce}/{encoded_text}"

    try:
        first = _request_with_rate_limit(
            "GET",
            signed_url(first_nonce, first_text),
            timeout=10.0,
        )
        lower = _request_with_rate_limit(
            "GET",
            signed_url(lower_nonce, lower_text),
            timeout=10.0,
        )
        higher = _request_with_rate_limit(
            "GET",
            signed_url(higher_nonce, higher_text),
            timeout=10.0,
        )
    except httpx.HTTPError as exc:
        console.print(f"[red]FAIL[/red] Signed nonce ordering: {exc}")
        return False

    if first.status_code != 200:
        console.print(
            f"[red]FAIL[/red] Signed nonce ordering: first write returned "
            f"{first.status_code}, expected 200"
        )
        return False

    if lower.status_code != 400:
        console.print(
            f"[red]FAIL[/red] Signed nonce ordering: lower nonce returned "
            f"{lower.status_code}, expected 400"
        )
        return False

    if higher.status_code != 200:
        console.print(
            f"[red]FAIL[/red] Signed nonce ordering: higher nonce returned "
            f"{higher.status_code}, expected 200"
        )
        return False

    console.print("[green]PASS[/green] Signed nonce ordering")
    return True


def check_signed_write_replay(base_url: str) -> bool | None:
    room = SHARED_TEST_ROOM
    if not room:
        console.print(
            "[yellow]SKIP[/yellow] Signed write replay: no reusable room available"
        )
        return None
    text_value = f"signed-replay-{secrets.token_hex(4)}"
    nonce = str(time.time_ns() // 1_000_000)

    key = Ed25519PrivateKey.generate()
    did = _did_of(key)
    canonical = f"{room}|{nonce}|{text_value}"
    sig = _signature(key, canonical)
    encoded_text = quote(text_value, safe="")

    url = f"{base_url}/r/{room}/say-signed/{did}/{sig}/{nonce}/{encoded_text}"

    try:
        first = _request_with_rate_limit("GET", url, timeout=10.0)
        replay = _request_with_rate_limit("GET", url, timeout=10.0)
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
    global SHARED_TEST_ROOM

    base_url = endpoint.rstrip("/")
    SHARED_TEST_ROOM = ""

    console.print("[bold]Technocore Conformance[/bold]")
    console.print(f"Target: {base_url}")

    groups = [
        (
            "Metadata & Discovery",
            [
                check_endpoint,
                check_agent_metadata,
                check_openapi,
                check_events_room_protection,
            ],
        ),
        (
            "Messaging",
            [
                check_messaging,
                check_post_messaging,
                check_since_semantics,
                check_limit_semantics,
                check_wait_semantics,
                check_single_line_sanitization,
                check_private_room_enumeration,
            ],
        ),
        (
            "Notes",
            [
                check_post_notes,
                check_conditional_notes,
                check_if_absent_notes,
                check_private_note_enumeration,
            ],
        ),
        (
            "Signing",
            [
                check_signed_post_write,
                check_signed_nonce_ordering,
                check_signed_write_replay,
            ],
        ),
    ]

    results = []
    failures = []

    for group_name, group_checks in groups:
        console.print()
        console.print(f"[bold]{group_name}[/bold]")

        group_results = []

        for check in group_checks:
            result = check(base_url)
            group_results.append(result)
            results.append(result)

            if result is False:
                failures.append(f"{group_name}: {check.__name__}")

        group_passed = sum(result is True for result in group_results)
        group_skipped = sum(result is None for result in group_results)
        console.print(
            f"[dim]{group_name}: {group_passed}/{len(group_results)} passed"
            f", {group_skipped} skipped[/dim]"
        )

    passed = sum(result is True for result in results)
    skipped = sum(result is None for result in results)
    total = len(results)

    console.print()
    console.print(
        f"[bold]Result: {passed}/{total} checks passed, {skipped} skipped[/bold]"
    )

    if failures:
        console.print()
        console.print("[bold red]Failed checks:[/bold red]")
        for failure in failures:
            console.print(f"  - {failure}")

        raise typer.Exit(code=1)

    if skipped:
        raise typer.Exit(code=2)


def main() -> None:
    app()
