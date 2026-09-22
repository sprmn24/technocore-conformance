from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_conformance import _did_of, _signature


def test_did_and_signature_shape() -> None:
    key = Ed25519PrivateKey.generate()

    did = _did_of(key)
    sig = _signature(key, "room|1|hello")

    assert did.startswith("did:key:z6Mk")
    assert len(did) == 56
    assert len(sig) == 86
    assert "=" not in sig


def test_check_post_messaging(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, payload=None):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    calls = []
    posted_text = None

    def fake_post(url, *, json, timeout):
        nonlocal posted_text
        posted_text = json["text"]
        calls.append(("POST", url, json))
        return Response()

    def fake_get(url, *, params, timeout):
        calls.append(("GET", url, params))
        room = url.rsplit("/", 1)[-1]
        return Response(
            {
                "room": room,
                "first_seq": 40,
                "last_seq": 42,
                "messages": [
                    {"seq": 40, "from": "other", "text": "older"},
                    {"seq": 41, "from": "conformance", "text": posted_text},
                    {"seq": 42, "from": "other", "text": "newer"},
                ],
            }
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_post_messaging("https://example.test") is True
    assert calls[0][0] == "POST"
    assert calls[0][2]["from"] == "conformance"
    assert calls[0][2]["text"].startswith("hello-post-")
    assert calls[1][0] == "GET"
    assert calls[1][2] == {"format": "json"}


def test_check_since_semantics(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, payload=None):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    writes = []
    read_count = 0

    def fake_get(url, *, timeout, params=None):
        nonlocal read_count

        if "/say/" in url:
            writes.append(url)
            return Response()

        read_count += 1
        if read_count == 1:
            assert params == {"format": "json"}
            return Response({"last_seq": 40})

        assert params == {"since": 40, "format": "json"}
        texts = [url.rsplit("/", 1)[-1] for url in writes]
        return Response(
            {
                "messages": [
                    {"seq": 41, "from": "conformance", "text": texts[0]},
                    {"seq": 42, "from": "conformance", "text": texts[1]},
                    {"seq": 43, "from": "conformance", "text": texts[2]},
                ]
            }
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_since_semantics("https://example.test") is True
    assert len(writes) == 3


def test_check_limit_semantics(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, payload=None):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    writes = []
    read_count = 0

    def fake_get(url, *, timeout, params=None):
        nonlocal read_count

        if "/say/" in url:
            writes.append(url)
            return Response()

        read_count += 1
        if read_count == 1:
            assert params == {"format": "json"}
            return Response({"last_seq": 40})

        assert params == {"limit": 2, "format": "json"}
        texts = [url.rsplit("/", 1)[-1] for url in writes]
        return Response(
            {
                "messages": [
                    {"seq": 42, "from": "conformance", "text": texts[1]},
                    {"seq": 43, "from": "conformance", "text": texts[2]},
                ]
            }
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_limit_semantics("https://example.test") is True
    assert len(writes) == 3


def test_check_if_absent_notes(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, status_code=200, text="", payload=None):
            self.status_code = status_code
            self.text = text
            self._payload = payload

        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    "error",
                    request=httpx.Request("GET", "https://example.test"),
                    response=httpx.Response(self.status_code),
                )

    calls = []

    def fake_get(url, *, timeout, params=None):
        calls.append((url, params))

        if url.endswith("/set/one"):
            return Response(status_code=200)

        if url.endswith("/set/two"):
            return Response(status_code=409, text="409 conflict\n\none")

        return Response(status_code=200, text="UNTRUSTED CONTENT\n\none\n")

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_if_absent_notes("https://example.test") is True
    assert calls[0][1] == {"if_absent": 1}
    assert calls[1][1] == {"if_absent": 1}
    assert calls[2][1] is None


def test_check_since_semantics_rejects_inclusive_since(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, payload=None):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    writes = []
    read_count = 0

    def fake_get(url, *, timeout, params=None):
        nonlocal read_count

        if "/say/" in url:
            writes.append(url)
            return Response()

        read_count += 1
        if read_count == 1:
            return Response({"last_seq": 40})

        texts = [url.rsplit("/", 1)[-1] for url in writes]
        return Response(
            {
                "messages": [
                    {"seq": 40, "from": "conformance", "text": "old"},
                    {"seq": 41, "from": "conformance", "text": texts[0]},
                    {"seq": 42, "from": "conformance", "text": texts[1]},
                    {"seq": 43, "from": "conformance", "text": texts[2]},
                ]
            }
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_since_semantics("https://example.test") is False


def test_check_limit_semantics_rejects_oldest_window(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, payload=None):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    writes = []
    read_count = 0

    def fake_get(url, *, timeout, params=None):
        nonlocal read_count

        if "/say/" in url:
            writes.append(url)
            return Response()

        read_count += 1
        if read_count == 1:
            return Response({"last_seq": 40})

        texts = [url.rsplit("/", 1)[-1] for url in writes]
        return Response(
            {
                "messages": [
                    {"seq": 41, "from": "conformance", "text": texts[0]},
                    {"seq": 42, "from": "conformance", "text": texts[1]},
                ]
            }
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_limit_semantics("https://example.test") is False


def test_check_if_absent_notes_rejects_wrong_conflict_body(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, status_code=200, text=""):
            self.status_code = status_code
            self.text = text

        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    "error",
                    request=httpx.Request("GET", "https://example.test"),
                    response=httpx.Response(self.status_code),
                )

    def fake_get(url, *, timeout, params=None):
        if url.endswith("/set/one"):
            return Response(status_code=200)

        if url.endswith("/set/two"):
            return Response(status_code=409, text="wrong-current-value")

        return Response(status_code=200, text="one")

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_if_absent_notes("https://example.test") is False


def test_check_if_absent_notes_rejects_mutated_value(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, status_code=200, text=""):
            self.status_code = status_code
            self.text = text

        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    "error",
                    request=httpx.Request("GET", "https://example.test"),
                    response=httpx.Response(self.status_code),
                )

    def fake_get(url, *, timeout, params=None):
        if url.endswith("/set/one"):
            return Response(status_code=200)

        if url.endswith("/set/two"):
            return Response(status_code=409, text="one")

        return Response(status_code=200, text="two")

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_if_absent_notes("https://example.test") is False


def test_check_single_line_sanitization(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, payload=None):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    posted = {}

    def fake_post(url, *, json, timeout):
        posted.update(json)
        return Response()

    def fake_get(url, *, params, timeout):
        expected = posted["text"].replace("\n", " ").replace("\u200b", " ")
        return Response(
            {
                "messages": [
                    {"seq": 10, "from": "other", "text": "older"},
                    {"seq": 11, "from": "conformance", "text": expected},
                ]
            }
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_single_line_sanitization("https://example.test") is True
    assert posted["text"].startswith("alpha-")
    assert posted["text"].endswith("\nbeta\u200bgamma")


def test_check_single_line_sanitization_rejects_unswept_text(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, payload=None):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    posted = {}

    def fake_post(url, *, json, timeout):
        posted.update(json)
        return Response()

    def fake_get(url, *, params, timeout):
        return Response(
            {
                "messages": [
                    {"seq": 10, "from": "other", "text": "older"},
                    {"seq": 11, "from": "conformance", "text": posted["text"]},
                ]
            }
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_single_line_sanitization("https://example.test") is False


def test_check_signed_post_write(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, payload=None):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    posted = {}

    def fake_post(url, *, json, timeout):
        posted.update(json)
        return Response()

    def fake_get(url, *, params, timeout):
        return Response(
            {
                "messages": [
                    {"seq": 40, "from": "other", "text": "older"},
                    {
                        "seq": 41,
                        "from": posted["did"],
                        "nonce": posted["nonce"],
                        "text": posted["text"],
                    },
                ]
            }
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_signed_post_write("https://example.test") is True
    assert posted["did"].startswith("did:key:z6Mk")
    assert len(posted["sig"]) == 86
    assert posted["text"].startswith("signed-post-")


def test_check_signed_post_write_rejects_unsigned_identity(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, payload=None):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    posted = {}

    def fake_post(url, *, json, timeout):
        posted.update(json)
        return Response()

    def fake_get(url, *, params, timeout):
        return Response(
            {
                "messages": [
                    {
                        "seq": 1,
                        "from": "conformance",
                        "nonce": posted["nonce"],
                        "text": posted["text"],
                    }
                ]
            }
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_signed_post_write("https://example.test") is False


def test_check_events_room_protection(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        status_code = 403

    def fake_get(url, *, timeout):
        assert url.endswith("/r/events/say/conformance/forbidden")
        return Response()

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_events_room_protection("https://example.test") is True


def test_check_events_room_protection_rejects_writable_events(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        status_code = 200

    def fake_get(url, *, timeout):
        return Response()

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_events_room_protection("https://example.test") is False


def test_check_private_note_enumeration(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, text=""):
            self.text = text

        def raise_for_status(self):
            return None

    public_key = {"value": None}

    def fake_get(url, *, timeout):
        if "/set/" in url:
            key = url.split("/kv/", 1)[1].split("/")[1]
            if key.startswith("public-"):
                public_key["value"] = key
            return Response()

        return Response(text=public_key["value"])

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_private_note_enumeration("https://example.test") is True


def test_check_private_note_enumeration_rejects_private_key_leak(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, text=""):
            self.text = text

        def raise_for_status(self):
            return None

    keys = []

    def fake_get(url, *, timeout):
        if "/set/" in url:
            key = url.split("/kv/", 1)[1].split("/")[1]
            keys.append(key)
            return Response()

        return Response(text="\n".join(keys))

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_private_note_enumeration("https://example.test") is False


def test_check_openapi_requires_core_paths(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "openapi": "3.1.0",
                "paths": {
                    "/r/{room}": {},
                    "/r/{room}/say/{nick}/{text}": {},
                    "/r/{room}/say-signed/{did}/{sig}/{nonce}/{text}": {},
                    "/kv/{ns}/{key}": {},
                    "/kv/{ns}/{key}/set/{value}": {},
                    "/kv/{ns}": {},
                    "/rooms": {},
                },
            }

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: Response())

    assert tc.check_openapi("https://example.test") is True


def test_check_openapi_rejects_missing_core_path(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "openapi": "3.1.0",
                "paths": {
                    "/r/{room}": {},
                    "/r/{room}/say/{nick}/{text}": {},
                    "/kv/{ns}/{key}": {},
                    "/kv/{ns}/{key}/set/{value}": {},
                    "/kv/{ns}": {},
                    "/rooms": {},
                },
            }

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: Response())

    assert tc.check_openapi("https://example.test") is False


def test_check_post_notes(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, text=""):
            self.text = text

        def raise_for_status(self):
            return None

    posted = {}

    def fake_post(url, *, json, timeout):
        posted.update(json)
        return Response()

    def fake_get(url, *, timeout):
        return Response(text=f"UNTRUSTED CONTENT\n\n{posted['value']}\n")

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_post_notes("https://example.test") is True
    assert posted == {"value": "hello-post-note"}


def test_check_post_notes_rejects_wrong_stored_value(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, text=""):
            self.text = text

        def raise_for_status(self):
            return None

    def fake_post(url, *, json, timeout):
        return Response()

    def fake_get(url, *, timeout):
        return Response(text="wrong-value")

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_post_notes("https://example.test") is False


def test_check_wait_semantics(monkeypatch) -> None:
    import threading

    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, payload=None):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    message_arrived = threading.Event()
    writes = []
    read_count = 0

    def fake_get(url, *, timeout, params=None):
        nonlocal read_count

        if "/say/conformance/" in url:
            writes.append(url)
            if len(writes) == 2:
                message_arrived.set()
            return Response()

        read_count += 1
        if read_count == 1:
            assert params == {"format": "json"}
            return Response({"last_seq": 40})

        assert params == {"since": 41, "wait": 2, "format": "json"}
        assert message_arrived.wait(timeout=1.0)

        second_text = writes[1].rsplit("/", 1)[-1]
        return Response(
            {
                "messages": [
                    {
                        "seq": 42,
                        "from": "conformance",
                        "text": second_text,
                    }
                ]
            }
        )

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr(tc.time, "sleep", lambda _: None)

    assert tc.check_wait_semantics("https://example.test") is True


def test_check_wait_semantics_rejects_server_that_returns_early(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    class Response:
        def __init__(self, payload=None):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    def fake_get(url, *, timeout, params=None):
        if "/say/" in url:
            return Response()

        return Response({"messages": []})

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr(tc.time, "sleep", lambda _: None)

    assert tc.check_wait_semantics("https://example.test") is False


def test_check_signed_nonce_ordering(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    statuses = iter([200, 400, 200])

    class Response:
        def __init__(self, status_code):
            self.status_code = status_code

    def fake_get(url, *, timeout):
        return Response(next(statuses))

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_signed_nonce_ordering("https://example.test") is True


def test_check_signed_nonce_ordering_rejects_accepted_lower_nonce(
    monkeypatch,
) -> None:
    import httpx

    import technocore_conformance as tc

    statuses = iter([200, 200, 200])

    class Response:
        def __init__(self, status_code):
            self.status_code = status_code

    def fake_get(url, *, timeout):
        return Response(next(statuses))

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_signed_nonce_ordering("https://example.test") is False


def test_check_signed_nonce_ordering_rejects_higher_nonce_failure(
    monkeypatch,
) -> None:
    import httpx

    import technocore_conformance as tc

    statuses = iter([200, 400, 400])

    class Response:
        def __init__(self, status_code):
            self.status_code = status_code

    def fake_get(url, *, timeout):
        return Response(next(statuses))

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_signed_nonce_ordering("https://example.test") is False


def test_request_with_rate_limit_retries_429(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    responses = iter(
        [
            httpx.Response(
                429,
                headers={"Retry-After": "2"},
                request=httpx.Request("GET", "https://example.test"),
            ),
            httpx.Response(
                200,
                request=httpx.Request("GET", "https://example.test"),
            ),
        ]
    )
    sleeps = []

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: next(responses))
    monkeypatch.setattr(tc.time, "sleep", sleeps.append)

    response = tc._request_with_rate_limit(
        "GET",
        "https://example.test",
    )

    assert response.status_code == 200
    assert sleeps == [2]


def test_request_with_rate_limit_stops_after_retry_limit(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    def always_limited(*args, **kwargs):
        return httpx.Response(
            429,
            headers={"Retry-After": "1"},
            request=httpx.Request("GET", "https://example.test"),
        )

    sleeps = []

    monkeypatch.setattr(httpx, "get", always_limited)
    monkeypatch.setattr(tc.time, "sleep", sleeps.append)

    response = tc._request_with_rate_limit(
        "GET",
        "https://example.test",
        max_retries=2,
    )

    assert response.status_code == 429
    assert sleeps == [1, 1]


def test_request_with_rate_limit_does_not_wait_for_room_creation_budget(
    monkeypatch,
) -> None:
    import httpx

    import technocore_conformance as tc

    response = httpx.Response(
        429,
        text="429 room-creation budget spent: test",
        headers={"Retry-After": "3600"},
        request=httpx.Request("GET", "https://example.test"),
    )
    sleeps = []

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: response)
    monkeypatch.setattr(tc.time, "sleep", sleeps.append)

    observed = tc._request_with_rate_limit(
        "GET",
        "https://example.test",
    )

    assert observed.status_code == 429
    assert sleeps == []


def test_scan_exits_inconclusive_when_checks_are_skipped(monkeypatch) -> None:
    from typer.testing import CliRunner

    import technocore_conformance as tc

    check_names = [
        "check_endpoint",
        "check_agent_metadata",
        "check_openapi",
        "check_events_room_protection",
        "check_messaging",
        "check_post_messaging",
        "check_since_semantics",
        "check_limit_semantics",
        "check_wait_semantics",
        "check_single_line_sanitization",
        "check_private_room_enumeration",
        "check_post_notes",
        "check_conditional_notes",
        "check_if_absent_notes",
        "check_private_note_enumeration",
        "check_signed_post_write",
        "check_signed_nonce_ordering",
        "check_signed_write_replay",
        "check_room_ownership_claim",
        "check_owned_room_write_authorization",
        "check_room_allow_list",
    ]

    for name in check_names:
        monkeypatch.setattr(tc, name, lambda base_url: True)

    monkeypatch.setattr(tc, "check_messaging", lambda base_url: None)

    result = CliRunner().invoke(tc.app, ["https://example.test"])

    assert result.exit_code == 2
    assert "20/21 checks passed, 1 skipped" in result.stdout


def test_scan_failure_takes_precedence_over_skip(monkeypatch) -> None:
    from typer.testing import CliRunner

    import technocore_conformance as tc

    check_names = [
        "check_endpoint",
        "check_agent_metadata",
        "check_openapi",
        "check_events_room_protection",
        "check_messaging",
        "check_post_messaging",
        "check_since_semantics",
        "check_limit_semantics",
        "check_wait_semantics",
        "check_single_line_sanitization",
        "check_private_room_enumeration",
        "check_post_notes",
        "check_conditional_notes",
        "check_if_absent_notes",
        "check_private_note_enumeration",
        "check_signed_post_write",
        "check_signed_nonce_ordering",
        "check_signed_write_replay",
        "check_room_ownership_claim",
        "check_owned_room_write_authorization",
        "check_room_allow_list",
    ]

    for name in check_names:
        monkeypatch.setattr(tc, name, lambda base_url: True)

    monkeypatch.setattr(tc, "check_messaging", lambda base_url: None)

    def failing_endpoint(base_url):
        return False

    failing_endpoint.__name__ = "check_endpoint"
    monkeypatch.setattr(tc, "check_endpoint", failing_endpoint)

    result = CliRunner().invoke(tc.app, ["https://example.test"])

    assert result.exit_code == 1
    assert "Failed checks:" in result.stdout
    assert "Metadata & Discovery: check_endpoint" in result.stdout


def test_check_private_room_enumeration_reuses_shared_room(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    original_room = tc.SHARED_TEST_ROOM
    tc.SHARED_TEST_ROOM = "e-p-conformance-existing"

    calls = []

    class Response:
        status_code = 200
        text = ""

        def raise_for_status(self):
            return None

        def json(self):
            return {
                "rooms": [
                    {"name": "public-room"},
                    {"name": "another-room"},
                ]
            }

    def fake_get(url, *, params, timeout):
        calls.append((url, params))
        return Response()

    monkeypatch.setattr(httpx, "get", fake_get)

    try:
        assert tc.check_private_room_enumeration("https://example.test") is True
        assert calls == [
            (
                "https://example.test/rooms",
                {"format": "json"},
            )
        ]
    finally:
        tc.SHARED_TEST_ROOM = original_room


def test_check_private_room_enumeration_skips_without_shared_room() -> None:
    import technocore_conformance as tc

    original_room = tc.SHARED_TEST_ROOM
    tc.SHARED_TEST_ROOM = ""

    try:
        assert tc.check_private_room_enumeration("https://example.test") is None
    finally:
        tc.SHARED_TEST_ROOM = original_room


def test_request_with_rate_limit_does_not_wait_for_large_retry_after(
    monkeypatch,
) -> None:
    import httpx

    import technocore_conformance as tc

    response = httpx.Response(
        429,
        text="429 rate limited",
        headers={"Retry-After": "3600"},
        request=httpx.Request("GET", "https://example.test"),
    )
    sleeps = []

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: response)
    monkeypatch.setattr(tc.time, "sleep", sleeps.append)

    observed = tc._request_with_rate_limit(
        "GET",
        "https://example.test",
    )

    assert observed.status_code == 429
    assert sleeps == []


def test_check_room_ownership_claim(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    captured = {}
    call_index = 0

    class Response:
        def __init__(self, status_code=200, text=""):
            self.status_code = status_code
            self.text = text

    def fake_get(url, *, timeout):
        nonlocal call_index
        call_index += 1
        if call_index == 1:
            did = url.split("/set-signed/")[1].split("/")[0]
            captured["owner_did"] = did
            return Response(status_code=200)
        if call_index == 2:
            return Response(status_code=403)
        if call_index == 3:
            return Response(
                status_code=200,
                text=captured["owner_did"] + "\n# budget: 7 of 120 reads left this minute\n",
            )
        raise AssertionError(f"unexpected extra call: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_room_ownership_claim("https://example.test") is True


def test_check_room_ownership_claim_rejects_second_claimant_accepted(
    monkeypatch,
) -> None:
    import httpx

    import technocore_conformance as tc

    call_index = 0

    class Response:
        def __init__(self, status_code=200, text=""):
            self.status_code = status_code
            self.text = text

    def fake_get(url, *, timeout):
        nonlocal call_index
        call_index += 1
        if call_index == 1:
            return Response(status_code=200)
        if call_index == 2:
            # a buggy server silently accepts a second claimant instead
            # of rejecting it at the ownership gate
            return Response(status_code=200)
        return Response(status_code=200, text="whoever")

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_room_ownership_claim("https://example.test") is False


def test_check_room_ownership_claim_rejects_sequential_second_claimant_conflict_status(
    monkeypatch,
) -> None:
    # Regression test: _note_write_gate() for the room-owners namespace runs
    # before the CAS/if_absent write and short-circuits a sequential second
    # claimant (different signer, owner already set) with a plain 403 --
    # the if_absent CAS point is never reached. A 409 here can only mean the
    # server let the request past the ownership gate, so it must FAIL, not
    # be accepted as an alternate "conflict" status.
    import httpx

    import technocore_conformance as tc

    call_index = 0

    class Response:
        def __init__(self, status_code=200, text=""):
            self.status_code = status_code
            self.text = text

    def fake_get(url, *, timeout):
        nonlocal call_index
        call_index += 1
        if call_index == 1:
            return Response(status_code=200)
        if call_index == 2:
            return Response(status_code=409)
        return Response(status_code=200, text="whoever")

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_room_ownership_claim("https://example.test") is False


def test_check_room_ownership_claim_rejects_wrong_stored_owner(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    call_index = 0

    class Response:
        def __init__(self, status_code=200, text=""):
            self.status_code = status_code
            self.text = text

    def fake_get(url, *, timeout):
        nonlocal call_index
        call_index += 1
        if call_index == 1:
            return Response(status_code=200)
        if call_index == 2:
            return Response(status_code=403)
        # stored owner does not match the first claimant's DID
        return Response(status_code=200, text="did:key:zSOMEONE-ELSE")

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_room_ownership_claim("https://example.test") is False


def test_check_owned_room_write_authorization(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    call_index = 0

    class Response:
        def __init__(self, status_code=200, payload=None, text=""):
            self.status_code = status_code
            self._payload = payload
            self.text = text

        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    "error",
                    request=httpx.Request("GET", "https://example.test"),
                    response=httpx.Response(self.status_code),
                )

        def json(self):
            return self._payload

    def fake_get(url, *, timeout, params=None):
        nonlocal call_index
        call_index += 1
        if call_index == 1:
            return Response(status_code=200)
        if call_index == 2:
            return Response(status_code=403)
        if call_index == 3:
            return Response(status_code=200)
        if call_index == 4:
            return Response(status_code=403)
        return Response(
            status_code=200, payload={"messages": [{"text": "owner-message"}]}
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_owned_room_write_authorization("https://example.test") is True



def test_check_owned_room_write_authorization_rejects_leaked_rejected_write(
    monkeypatch,
) -> None:
    import httpx

    import technocore_conformance as tc

    call_index = 0

    class Response:
        def __init__(self, status_code=200, payload=None, text=""):
            self.status_code = status_code
            self._payload = payload
            self.text = text

        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    "error",
                    request=httpx.Request("GET", "https://example.test"),
                    response=httpx.Response(self.status_code),
                )

        def json(self):
            return self._payload

    def fake_get(url, *, timeout, params=None):
        nonlocal call_index
        call_index += 1
        if call_index == 1:
            return Response(status_code=200)
        if call_index == 2:
            return Response(status_code=403)
        if call_index == 3:
            return Response(status_code=200)
        if call_index == 4:
            return Response(status_code=403)
        return Response(
            status_code=200,
            payload={
                "messages": [
                    {"text": "owner-message"},
                    {"text": "intruder-message"},
                ]
            },
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_owned_room_write_authorization("https://example.test") is False


def test_check_owned_room_write_authorization_rejects_malformed_room_state(
    monkeypatch,
) -> None:
    import httpx

    import technocore_conformance as tc

    call_index = 0

    class Response:
        def __init__(self, status_code=200, payload=None, text=""):
            self.status_code = status_code
            self._payload = payload
            self.text = text

        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    "error",
                    request=httpx.Request("GET", "https://example.test"),
                    response=httpx.Response(self.status_code),
                )

        def json(self):
            return self._payload

    def fake_get(url, *, timeout, params=None):
        nonlocal call_index
        call_index += 1
        if call_index == 1:
            return Response(status_code=200)
        if call_index == 2:
            return Response(status_code=403)
        if call_index == 3:
            return Response(status_code=200)
        if call_index == 4:
            return Response(status_code=403)
        return Response(status_code=200, payload=["not", "an", "object"])

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_owned_room_write_authorization("https://example.test") is False


def test_check_owned_room_write_authorization_rejects_non_list_messages(
    monkeypatch,
) -> None:
    import httpx

    import technocore_conformance as tc

    call_index = 0

    class Response:
        def __init__(self, status_code=200, payload=None, text=""):
            self.status_code = status_code
            self._payload = payload
            self.text = text

        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(
                    "error",
                    request=httpx.Request("GET", "https://example.test"),
                    response=httpx.Response(self.status_code),
                )

        def json(self):
            return self._payload

    def fake_get(url, *, timeout, params=None):
        nonlocal call_index
        call_index += 1
        if call_index == 1:
            return Response(status_code=200)
        if call_index == 2:
            return Response(status_code=403)
        if call_index == 3:
            return Response(status_code=200)
        if call_index == 4:
            return Response(status_code=403)
        return Response(
            status_code=200,
            payload={"messages": {"text": "owner-message"}},
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_owned_room_write_authorization("https://example.test") is False


def test_check_owned_room_write_authorization_skips_on_room_creation_budget(
    monkeypatch,
) -> None:
    import httpx

    import technocore_conformance as tc

    call_index = 0

    class Response:
        def __init__(self, status_code=200, text=""):
            self.status_code = status_code
            self.text = text

    def fake_get(url, *, timeout, params=None):
        nonlocal call_index
        call_index += 1
        if call_index == 1:
            return Response(status_code=200)
        if call_index == 2:
            return Response(status_code=403)
        if call_index == 3:
            return Response(
                status_code=429,
                text="429 room-creation budget spent: 0 remaining",
            )
        raise AssertionError(f"unexpected extra call: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_owned_room_write_authorization("https://example.test") is None
    assert call_index == 3

def test_check_room_allow_list(monkeypatch) -> None:
    from urllib.parse import unquote

    import httpx

    import technocore_conformance as tc

    captured = {}
    call_index = 0

    class Response:
        def __init__(self, status_code=200, text=""):
            self.status_code = status_code
            self.text = text

    def fake_get(url, *, timeout):
        nonlocal call_index
        call_index += 1
        if call_index == 1:
            return Response(status_code=200)
        if call_index == 2:
            captured["guest_did"] = unquote(url.rsplit("/", 1)[-1])
            return Response(status_code=200)
        if call_index == 3:
            return Response(status_code=200)
        if call_index == 4:
            return Response(status_code=403)
        return Response(
                status_code=200,
                text=captured["guest_did"] + "\n# budget: 7 of 120 reads left this minute\n",
            )

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_room_allow_list("https://example.test") is True


def test_check_room_allow_list_rejects_non_owner_write_reported_as_conflict(
    monkeypatch,
) -> None:
    # Regression test: a non-owner allow-list write must be rejected with
    # exactly 403. These nonces are deterministically increasing and never
    # produce a genuine CAS conflict here, so a 409 can only mean the
    # server mishandled authorization.
    import httpx

    import technocore_conformance as tc

    call_index = 0

    class Response:
        def __init__(self, status_code=200, text=""):
            self.status_code = status_code
            self.text = text

    def fake_get(url, *, timeout):
        nonlocal call_index
        call_index += 1
        if call_index == 1:
            return Response(status_code=200)
        if call_index == 2:
            return Response(status_code=200)
        if call_index == 3:
            return Response(status_code=200)
        if call_index == 4:
            return Response(status_code=409)
        return Response(status_code=200, text="whatever-was-stored")

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_room_allow_list("https://example.test") is False


def test_check_room_allow_list_rejects_stale_stored_value(monkeypatch) -> None:
    import httpx

    import technocore_conformance as tc

    call_index = 0

    class Response:
        def __init__(self, status_code=200, text=""):
            self.status_code = status_code
            self.text = text

    def fake_get(url, *, timeout):
        nonlocal call_index
        call_index += 1
        if call_index == 1:
            return Response(status_code=200)
        if call_index == 2:
            return Response(status_code=200)
        if call_index == 3:
            return Response(status_code=200)
        if call_index == 4:
            return Response(status_code=403)
        # buggy server: the allow-list no longer matches the owner's
        # original grant
        return Response(status_code=200, text="did:key:zSOMEONE-ELSE")

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_room_allow_list("https://example.test") is False


def test_check_room_allow_list_skips_on_room_creation_budget(monkeypatch) -> None:
    # The budget check only applies to the first real room *message* write
    # (guest_write here), never to the room-owners/room-allow KV notes --
    # neither note write reaches _room_create_gate() upstream.
    import httpx

    import technocore_conformance as tc

    call_index = 0

    class Response:
        def __init__(self, status_code, text=""):
            self.status_code = status_code
            self.text = text

    def fake_get(url, *, timeout):
        nonlocal call_index
        call_index += 1
        if call_index == 1:
            return Response(status_code=200)
        if call_index == 2:
            return Response(status_code=200)
        return Response(
            status_code=429, text="429 room-creation budget spent: 0 remaining"
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    assert tc.check_room_allow_list("https://example.test") is None
